//! The accounts offered, kept in the module's own directory as `accounts.json`: public material
//! and the serial of the Shell each came from, nothing else.

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
}

#[derive(Default, Serialize, Deserialize)]
struct File {
    accounts: Vec<Offered>,
}

#[derive(Default)]
pub struct Store {
    path: Option<PathBuf>,
    offered: Vec<Offered>,
}

impl Store {
    /// In memory only, until [`Store::open`].
    pub fn new() -> Self {
        Store::default()
    }

    /// Read `dir/accounts.json`, kept there from now on. A missing file is an empty list.
    pub fn open(dir: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path = dir.into().join("accounts.json");
        let offered = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice::<File>(&bytes)?.accounts,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e),
        };
        Ok(Store {
            path: Some(path),
            offered,
        })
    }

    pub fn list(&self) -> &[Offered] {
        &self.offered
    }

    pub fn find(&self, id: &str) -> Option<&Offered> {
        self.offered.iter().find(|o| same(&o.account, id))
    }

    /// Add or replace accounts by id, and save.
    pub fn put(&mut self, add: Vec<Offered>) -> std::io::Result<()> {
        for o in add {
            match self
                .offered
                .iter_mut()
                .find(|have| same(&have.account, &o.account.id))
            {
                Some(have) => *have = o,
                None => self.offered.push(o),
            }
        }
        self.save()
    }

    /// Whether an account went, saved.
    pub fn remove(&mut self, id: &str) -> std::io::Result<bool> {
        let before = self.offered.len();
        self.offered.retain(|o| !same(&o.account, id));
        self.save()?;
        Ok(self.offered.len() != before)
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
