//! The accounts offered, kept in the module's own directory as `accounts.json`: public material
//! and the serial of the Shell each came from, nothing else.

use std::collections::BTreeMap;
use std::path::PathBuf;

use logos_signer_interface::Account;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Offered {
    pub account: Account,
    /// The USB serial of the Shell it came from: available while that Shell is connected.
    pub serial: String,
    /// The account key, compressed, hex: what an EVM answer names as the key that signed.
    #[serde(default)]
    pub key: String,
    /// SHA-256 of the full uncompressed master public key; never the short fingerprint.
    #[serde(default)]
    pub master_key_id: String,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct File {
    accounts: Vec<Offered>,
    #[serde(default)]
    wallet_names: BTreeMap<String, String>,
    #[serde(default)]
    aliases: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    connections: BTreeMap<String, Vec<String>>,
}

#[derive(Clone, Default)]
pub struct Store {
    path: Option<PathBuf>,
    offered: Vec<Offered>,
    wallet_names: BTreeMap<String, String>,
    aliases: BTreeMap<String, Vec<String>>,
    connections: BTreeMap<String, Vec<String>>,
}

impl Store {
    /// In memory only, until [`Store::open`].
    pub fn new() -> Self {
        Store::default()
    }

    /// Read `dir/accounts.json`, kept there from now on. A missing file is an empty list.
    pub fn open(dir: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path = dir.into().join("accounts.json");
        let mut file = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<File>(&bytes)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => File::default(),
            Err(e) => return Err(e),
        };
        for o in &file.accounts {
            file.wallet_names.entry(wallet_id(o)).or_default();
        }
        Ok(Store {
            path: Some(path),
            offered: file.accounts,
            wallet_names: file.wallet_names,
            aliases: file.aliases,
            connections: file.connections,
        })
    }

    pub fn list(&self) -> &[Offered] {
        &self.offered
    }

    pub fn find(&self, id: &str) -> Option<&Offered> {
        self.offered.iter().find(|o| same(&o.account, id))
    }

    /// Commit a verified root and account migration together. Keep old names as aliases.
    pub fn put_identified(
        &mut self,
        add: Vec<Offered>,
        root: &str,
        serial: &str,
    ) -> std::io::Result<()> {
        self.check_keys(&add)?;
        let previous = self.clone();
        let id = format!("seed:{root}");
        self.wallet_names.entry(id.clone()).or_default();
        let connections = self.connections.entry(id).or_default();
        if !connections.iter().any(|s| s == serial) {
            connections.push(serial.into());
        }
        self.merge(add);
        if let Err(e) = self.save() {
            *self = previous;
            return Err(e);
        }
        Ok(())
    }

    pub fn put(&mut self, add: Vec<Offered>) -> std::io::Result<()> {
        self.check_keys(&add)?;
        let previous = self.clone();
        self.merge(add);
        if let Err(e) = self.save() {
            *self = previous;
            return Err(e);
        }
        Ok(())
    }

    fn check_keys(&self, add: &[Offered]) -> std::io::Result<()> {
        for o in add {
            if let Some(old) = self.find(&o.account.id) {
                if old.key != o.key
                    || (!old.master_key_id.is_empty() && old.master_key_id != o.master_key_id)
                {
                    return Err(std::io::Error::other(
                        "Account identifier belongs to another key; existing account was kept",
                    ));
                }
            }
        }
        Ok(())
    }

    fn merge(&mut self, add: Vec<Offered>) {
        let mut old_ids = Vec::new();
        for mut o in add {
            let id = wallet_id(&o);
            self.wallet_names.entry(id.clone()).or_default();
            if !o.master_key_id.is_empty() {
                let connections = self.connections.entry(id.clone()).or_default();
                if !connections.contains(&o.serial) {
                    connections.push(o.serial.clone());
                }
            }
            if let Some(index) = self
                .offered
                .iter()
                .position(|have| same(&have.account, &o.account.id))
            {
                let old = &self.offered[index];
                let old_id = wallet_id(old);
                o.account.label = old.account.label.clone();
                if old_id != id {
                    let name = self.wallet_name(&old_id);
                    if !name.is_empty() {
                        if self.wallet_name(&id).is_empty() {
                            self.wallet_names.insert(id.clone(), name.clone());
                        }
                        let aliases = self.aliases.entry(id.clone()).or_default();
                        if !aliases.contains(&name) {
                            aliases.push(name);
                        }
                    }
                    old_ids.push(old_id);
                }
                self.offered[index] = o;
            } else {
                self.offered.push(o);
            }
        }
        for id in old_ids {
            if !self.offered.iter().any(|o| wallet_id(o) == id) {
                self.wallet_names.remove(&id);
                self.connections.remove(&id);
            }
        }
    }

    pub fn connections(&self, id: &str) -> Vec<String> {
        self.connections.get(id).cloned().unwrap_or_default()
    }
    pub fn aliases(&self, id: &str) -> Vec<String> {
        self.aliases.get(id).cloned().unwrap_or_default()
    }
    pub fn available_serial(&self, o: &Offered, connected: &[String]) -> Option<String> {
        if connected.contains(&o.serial) {
            return Some(o.serial.clone());
        }
        self.connections(&wallet_id(o))
            .into_iter()
            .find(|s| connected.contains(s))
    }

    /// Local display metadata only. A failed write must not change the offered account.
    pub fn rename_account(&mut self, id: &str, name: &str) -> std::io::Result<()> {
        let name = name.trim();
        if name.chars().count() > 80 || name.chars().any(char::is_control) {
            return Err(std::io::Error::other(
                "Account names must be at most 80 characters, without control characters",
            ));
        }
        let index = self
            .offered
            .iter()
            .position(|o| same(&o.account, id))
            .ok_or_else(|| std::io::Error::other("Unknown account"))?;
        let previous = self.offered[index].account.label.clone();
        self.offered[index].account.label = (!name.is_empty()).then(|| name.to_owned());
        if let Err(e) = self.save() {
            self.offered[index].account.label = previous;
            return Err(e);
        }
        Ok(())
    }

    /// Whether an account went, saved.
    pub fn remove(&mut self, id: &str) -> std::io::Result<bool> {
        let before = self.offered.len();
        self.offered.retain(|o| !same(&o.account, id));
        self.save()?;
        Ok(self.offered.len() != before)
    }

    pub fn wallet_names(&self) -> &BTreeMap<String, String> {
        &self.wallet_names
    }

    pub fn wallet_name(&self, id: &str) -> String {
        self.wallet_names.get(id).cloned().unwrap_or_default()
    }

    pub fn rename_wallet(&mut self, id: &str, name: &str) -> std::io::Result<()> {
        let name = name.trim();
        if !self.wallet_names.contains_key(id)
            || name.chars().count() > 80
            || name.chars().any(char::is_control)
        {
            return Err(std::io::Error::other("Unknown wallet or invalid name"));
        }
        let previous = self.wallet_names.clone();
        self.wallet_names.insert(id.into(), name.into());
        if let Err(e) = self.save() {
            self.wallet_names = previous;
            return Err(e);
        }
        Ok(())
    }

    pub fn forget_wallet(&mut self, id: &str) -> std::io::Result<()> {
        if !self.wallet_names.contains_key(id) {
            return Err(std::io::Error::other("Unknown wallet"));
        }
        let previous = self.clone();
        self.offered.retain(|o| wallet_id(o) != id);
        self.wallet_names.remove(id);
        self.aliases.remove(id);
        self.connections.remove(id);
        if let Err(e) = self.save() {
            *self = previous;
            return Err(e);
        }
        Ok(())
    }

    fn save(&self) -> std::io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let body = serde_json::to_vec_pretty(&File {
            accounts: self.offered.clone(),
            wallet_names: self.wallet_names.clone(),
            aliases: self.aliases.clone(),
            connections: self.connections.clone(),
        })?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, body)?;
        std::fs::rename(tmp, path)
    }
}

/// EVM addresses compare without case; other ids exactly.
fn same(a: &Account, id: &str) -> bool {
    if a.family == logos_signer_interface::Family::Evm {
        a.id.eq_ignore_ascii_case(id.trim())
    } else {
        a.id == id.trim()
    }
}

/// The fingerprint is an organization hint supplied by the Shell, not a physical card ID.
pub fn wallet_id(o: &Offered) -> String {
    if !o.master_key_id.is_empty() {
        return format!("seed:{}", o.master_key_id);
    }
    format!(
        "shell:{}:{}",
        o.serial,
        o.account.fingerprint.as_deref().unwrap_or("unknown")
    )
}
