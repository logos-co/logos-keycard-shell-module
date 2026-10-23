//! The accounts offered, kept in the module's own directory as `accounts.sealed.json`: one
//! document per seed (its accounts, its name, the Shells that hold it), sealed under the module's
//! key for that seed from the signer manager and read only while it is unlocked. Public material
//! and the serial of the Shell each came from, nothing else. An account of no verified seed is
//! kept in memory only.

use std::collections::BTreeMap;
use std::path::PathBuf;

use logos_signer_interface::sealed::SealedDocs;
use logos_signer_interface::wallets::DataKey;
use logos_signer_interface::{Account, SignerError};
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

/// One seed's document.
#[derive(Default, Serialize, Deserialize)]
struct Wallet {
    accounts: Vec<Offered>,
    #[serde(default)]
    name: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    connections: Vec<String>,
}

/// What the sealed documents are called in their boxes.
const WALLETS: &str = "keycard_shell_module wallets";

fn io(e: SignerError) -> std::io::Error {
    std::io::Error::other(e.message)
}

pub struct Store {
    /// Each seed's document, by master key id; the readable ones are in the fields below.
    docs: SealedDocs,
    offered: Vec<Offered>,
    wallet_names: BTreeMap<String, String>,
    aliases: BTreeMap<String, Vec<String>>,
    connections: BTreeMap<String, Vec<String>>,
    /// Added while their seed was locked, with the Shell they came through: merged in, and saved,
    /// once it unlocks.
    waiting: BTreeMap<String, (Vec<Offered>, Vec<String>)>,
}

impl Default for Store {
    fn default() -> Self {
        Store {
            docs: SealedDocs::in_memory(WALLETS),
            offered: Vec::new(),
            wallet_names: BTreeMap::new(),
            aliases: BTreeMap::new(),
            connections: BTreeMap::new(),
            waiting: BTreeMap::new(),
        }
    }
}

/// The state that rolls back when a write fails.
struct Snapshot {
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

    /// Read `dir/accounts.sealed.json`, kept there from now on. A missing file is an empty list.
    /// Each seed's document stays sealed until its key arrives ([`Store::unlock`]).
    pub fn open(dir: impl Into<PathBuf>) -> std::io::Result<Self> {
        let docs =
            SealedDocs::load(dir.into().join("accounts.sealed.json"), WALLETS).map_err(io)?;
        Ok(Store {
            docs,
            ..Store::default()
        })
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot {
            offered: self.offered.clone(),
            wallet_names: self.wallet_names.clone(),
            aliases: self.aliases.clone(),
            connections: self.connections.clone(),
        }
    }

    fn restore(&mut self, s: Snapshot) {
        self.offered = s.offered;
        self.wallet_names = s.wallet_names;
        self.aliases = s.aliases;
        self.connections = s.connections;
    }

    /// A seed this store keeps a wallet of, locked or not.
    pub fn knows(&self, seed: &str) -> bool {
        self.docs.seeds().iter().any(|s| s == seed)
            || self.waiting.contains_key(seed)
            || self.offered.iter().any(|o| o.master_key_id == seed)
    }

    /// Sealed, and its key not given yet.
    fn is_locked(&self, seed: &str) -> bool {
        self.docs.wanted(seed).is_some()
    }

    /// The seeds whose documents wait for their key, each with the generation it is sealed
    /// under, if it is sealed yet.
    pub fn closed(&self) -> Vec<(String, Option<u32>)> {
        let mut out: Vec<(String, Option<u32>)> = self
            .docs
            .seeds()
            .into_iter()
            .filter(|s| !self.docs.is_open(s))
            .map(|s| {
                let g = self.docs.wanted(&s);
                (s, g)
            })
            .collect();
        for seed in self.waiting.keys() {
            if !out.iter().any(|(s, _)| s == seed) {
                out.push((seed.clone(), None));
            }
        }
        out
    }

    /// A seed's key arrived: its wallet is shown again, with what was added meanwhile.
    pub fn unlock(
        &mut self,
        seed: &str,
        box_key: &DataKey,
        current: &DataKey,
    ) -> std::io::Result<()> {
        self.docs.unlock(seed, box_key, current).map_err(io)?;
        let doc: Wallet = self
            .docs
            .get(seed)
            .filter(|b| !b.is_empty())
            .map(serde_json::from_slice)
            .transpose()?
            .unwrap_or_default();
        let id = format!("seed:{seed}");
        self.offered.retain(|o| o.master_key_id != seed);
        self.offered.extend(doc.accounts);
        self.wallet_names.insert(id.clone(), doc.name);
        self.aliases.remove(&id);
        if !doc.aliases.is_empty() {
            self.aliases.insert(id.clone(), doc.aliases);
        }
        self.connections.insert(id.clone(), doc.connections);
        if let Some((add, serials)) = self.waiting.remove(seed) {
            let connections = self.connections.entry(id).or_default();
            for serial in serials {
                if !connections.contains(&serial) {
                    connections.push(serial);
                }
            }
            self.merge(add);
        }
        self.save()
    }

    /// Wallets were locked: nothing of a locked seed is shown. What waits for its key stays.
    pub fn lock(&mut self) {
        self.docs.lock();
        let readable: Vec<String> = self.docs.readable().into_iter().map(|(s, _)| s).collect();
        let shown = |id: &String| {
            id.strip_prefix("seed:")
                .is_none_or(|seed| readable.iter().any(|r| r == seed))
        };
        self.offered
            .retain(|o| o.master_key_id.is_empty() || readable.contains(&o.master_key_id));
        self.wallet_names.retain(|id, _| shown(id));
        self.aliases.retain(|id, _| shown(id));
        self.connections.retain(|id, _| shown(id));
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
        if self.is_locked(root) {
            let (accounts, serials) = self.waiting.entry(root.into()).or_default();
            for o in add {
                accounts.retain(|have| !same(&have.account, &o.account.id));
                accounts.push(o);
            }
            if !serials.iter().any(|s| s == serial) {
                serials.push(serial.into());
            }
            return Ok(());
        }
        let previous = self.snapshot();
        let id = format!("seed:{root}");
        self.wallet_names.entry(id.clone()).or_default();
        let connections = self.connections.entry(id).or_default();
        if !connections.iter().any(|s| s == serial) {
            connections.push(serial.into());
        }
        self.merge(add);
        if let Err(e) = self.save() {
            self.restore(previous);
            return Err(e);
        }
        Ok(())
    }

    pub fn put(&mut self, add: Vec<Offered>) -> std::io::Result<()> {
        self.check_keys(&add)?;
        if let Some(locked) = add.iter().find(|o| self.is_locked(&o.master_key_id)) {
            return self.put_identified(
                add.clone(),
                &locked.master_key_id.clone(),
                &locked.serial.clone(),
            );
        }
        let previous = self.snapshot();
        self.merge(add);
        if let Err(e) = self.save() {
            self.restore(previous);
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
        let previous = self.snapshot();
        self.offered.retain(|o| wallet_id(o) != id);
        self.wallet_names.remove(id);
        self.aliases.remove(id);
        self.connections.remove(id);
        if let Err(e) = self.save() {
            self.restore(previous);
            return Err(e);
        }
        if let Some(seed) = id.strip_prefix("seed:") {
            self.waiting.remove(seed);
        }
        Ok(())
    }

    /// Each shown seed's document, sealed under its key, or kept in memory until it comes.
    fn save(&mut self) -> std::io::Result<()> {
        let mut docs: BTreeMap<String, Wallet> = BTreeMap::new();
        for id in self.wallet_names.keys() {
            if let Some(seed) = id.strip_prefix("seed:") {
                docs.insert(
                    seed.into(),
                    Wallet {
                        accounts: Vec::new(),
                        name: self.wallet_name(id),
                        aliases: self.aliases(id),
                        connections: self.connections(id),
                    },
                );
            }
        }
        for o in self.offered.iter().filter(|o| !o.master_key_id.is_empty()) {
            docs.entry(o.master_key_id.clone())
                .or_default()
                .accounts
                .push(o.clone());
        }
        let gone: Vec<String> = self
            .docs
            .readable()
            .into_iter()
            .map(|(seed, _)| seed)
            .filter(|seed| !docs.contains_key(seed))
            .collect();
        for seed in gone {
            self.docs.remove(&seed).map_err(io)?;
        }
        for (seed, doc) in docs {
            self.docs
                .put(&seed, serde_json::to_vec(&doc)?)
                .map_err(io)?;
        }
        Ok(())
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
