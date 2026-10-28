//! The accounts a Shell offers, built from the keys it exported: public material only. A Bitcoin
//! account's xpub carries its parent's fingerprint, so its parent key is exported too.

use bitcoin::bip32::{ChainCode, ChildNumber, Fingerprint, Xpub};
use bitcoin::hashes::{hash160, Hash};
use bitcoin::NetworkKind;
use logos_signer_interface::{Account, Chain, Family};
use sha3::{Digest, Keccak256};

use crate::commands::Exported;

pub const HARDENED: u32 = 0x8000_0000;

/// m/44'/60'/0'/0/0, the first EVM address.
pub const EVM_PATH: [u32; 5] = [HARDENED | 44, HARDENED | 60, HARDENED, 0, 0];

/// m/84' or m/86', then 0' for Bitcoin or 1' for the test networks, then the account.
pub fn bitcoin_path(family: Family, chain: Chain, account: u32) -> Option<[u32; 3]> {
    let purpose = match family {
        Family::Bitcoin => 84,
        Family::BitcoinTaproot => 86,
        Family::Evm => return None,
    };
    let coin = if chain == Chain::Main { 0 } else { 1 };
    (account < HARDENED).then_some([HARDENED | purpose, HARDENED | coin, HARDENED | account])
}

pub fn path_string(path: &[u32]) -> String {
    let mut s = String::from("m");
    for i in path {
        if i & HARDENED != 0 {
            s += &format!("/{}'", i & !HARDENED);
        } else {
            s += &format!("/{i}");
        }
    }
    s
}

/// The indexes of a path such as `m/84'/1'/0'/0/3` (`h` marks a hardened index too).
pub fn parse_path(s: &str) -> Option<Vec<u32>> {
    let rest = s.trim().strip_prefix('m')?;
    rest.split('/')
        .skip(1)
        .map(|step| {
            let (n, hard) = match step.strip_suffix(['\'', 'h']) {
                Some(n) => (n, HARDENED),
                None => (step, 0),
            };
            n.parse::<u32>()
                .ok()
                .filter(|n| *n < HARDENED)
                .map(|n| n | hard)
        })
        .collect()
}

pub fn evm_address(e: &Exported) -> String {
    let hash = Keccak256::digest(&e.key.serialize_uncompressed()[1..]);
    format!("0x{}", hex::encode(&hash[12..]))
}

pub fn evm_account(e: &Exported, label: Option<String>) -> Account {
    let address = evm_address(e);
    Account {
        id: address.clone(),
        family: Family::Evm,
        chain: None,
        path: Some(path_string(&EVM_PATH)),
        fingerprint: Some(hex::encode(e.fingerprint)),
        address: Some(address),
        xpub: None,
        key: None,
        seed: None,
        label,
        available: true,
    }
}

/// A Bitcoin account from its key and its parent's, both exported with their chain codes.
pub fn bitcoin_account(
    parent: &Exported,
    key: &Exported,
    family: Family,
    chain: Chain,
    account: u32,
    label: Option<String>,
) -> Result<Account, String> {
    let path = bitcoin_path(family, chain, account).ok_or("not a Bitcoin family")?;
    let chain_code = key
        .chain_code
        .ok_or("the account key came without its chain code")?;
    if parent.fingerprint != key.fingerprint {
        return Err("the two keys came from different wallets".into());
    }
    let parent_fp = hash160::Hash::hash(&parent.key.serialize());
    let xpub = Xpub {
        network: if chain == Chain::Main {
            NetworkKind::Main
        } else {
            NetworkKind::Test
        },
        depth: 3,
        parent_fingerprint: Fingerprint::from(
            <[u8; 4]>::try_from(&parent_fp[..4]).expect("4 bytes"),
        ),
        child_number: ChildNumber::from_hardened_idx(account).map_err(|e| e.to_string())?,
        public_key: key.key,
        chain_code: ChainCode::from(chain_code),
    };
    let fp = hex::encode(key.fingerprint);
    Ok(Account {
        id: format!(
            "shell-{fp}-{}-{}-{account}",
            path[0] & !HARDENED,
            path[1] & !HARDENED
        ),
        family,
        chain: Some(chain),
        path: Some(path_string(&path)),
        fingerprint: Some(fp),
        address: None,
        xpub: Some(xpub.to_string()),
        key: None,
        seed: None,
        label,
        available: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::bip32::{DerivationPath, Xpriv};
    use bitcoin::secp256k1::Secp256k1;
    use std::str::FromStr;

    /// What a Shell holding `xprv`'s wallet would export at `path`.
    fn export(master: &Xpriv, path: &str) -> Exported {
        let secp = Secp256k1::new();
        let x = master
            .derive_priv(&secp, &DerivationPath::from_str(path).unwrap())
            .unwrap();
        Exported {
            fingerprint: master.fingerprint(&secp).to_bytes(),
            key: x.private_key.public_key(&secp),
            chain_code: Some(x.chain_code.to_bytes()),
        }
    }

    #[test]
    fn the_xpub_is_the_one_bip84_publishes() {
        // From bitcoin/bips at 927b6de9915c (2026-10-02): BIP86's rootpriv for the "abandon … about"
        // mnemonic, and BIP84's account 0 zpub for the same mnemonic, compared past the version.
        let root = Xpriv::from_str(
            "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu",
        )
        .unwrap();
        let account = bitcoin_account(
            &export(&root, "m/84'/0'"),
            &export(&root, "m/84'/0'/0'"),
            Family::Bitcoin,
            Chain::Main,
            0,
            None,
        )
        .unwrap();
        let ours = bitcoin::base58::decode_check(account.xpub.as_deref().unwrap()).unwrap();
        let published = bitcoin::base58::decode_check(
            "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
        )
        .unwrap();
        assert_eq!(
            &ours[4..],
            &published[4..],
            "all but the version: depth, parent, index, chain code, key"
        );
        assert_eq!(account.id, "shell-73c5da0a-84-0-0");
        assert_eq!(account.path.as_deref(), Some("m/84'/0'/0'"));
    }

    #[test]
    fn paths_read_and_write_alike() {
        assert_eq!(path_string(&EVM_PATH), "m/44'/60'/0'/0/0");
        assert_eq!(
            parse_path("m/84h/1'/0'/1/3"),
            Some(vec![HARDENED | 84, HARDENED | 1, HARDENED, 1, 3])
        );
        assert_eq!(parse_path("84'/1'"), None);
        assert_eq!(
            bitcoin_path(Family::BitcoinTaproot, Chain::Test, 2),
            Some([HARDENED | 86, HARDENED | 1, HARDENED | 2])
        );
    }
}
