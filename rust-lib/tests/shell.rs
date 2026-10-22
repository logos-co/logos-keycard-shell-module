//! The module against a Shell in software: its accounts, the conformance suite, and each way a
//! request ends. Every signature is checked with the manager's own check, over a digest worked
//! out here.

use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use keycard_shell_module::apdu::{self, ShellError, Transport};
use keycard_shell_module::commands;
use keycard_shell_module::emulator::{Confirm, Emulator, PHRASE};
use keycard_shell_module::link::{Devices, Emulated};
use keycard_shell_module::signer::{AddRequest, Quiet, ShellSigner};
use keycard_shell_module::store::Store;
use logos_signer_interface::conformance::{self, Fixture};
use logos_signer_interface::verify::check;
use logos_signer_interface::*;
use sha3::{Digest, Keccak256};

/// The emulator, unplugged at will.
struct Plug {
    inner: Emulated,
    on: Arc<AtomicBool>,
    forbid_public: Arc<AtomicBool>,
}

struct SigningTransport {
    inner: Box<dyn Transport>,
    forbid_public: Arc<AtomicBool>,
}
impl Transport for SigningTransport {
    fn exchange(&mut self, command: &[u8]) -> apdu::Result<Vec<u8>> {
        if self.forbid_public.load(Ordering::SeqCst) && command.get(1) == Some(&apdu::GET_PUBLIC) {
            return Err(ShellError::Link(
                "unexpected public-key confirmation while signing".into(),
            ));
        }
        self.inner.exchange(command)
    }
}

impl Devices for Plug {
    fn connected(&self) -> Vec<String> {
        if self.on.load(Ordering::SeqCst) {
            self.inner.connected()
        } else {
            Vec::new()
        }
    }
    fn open(&self, serial: &str) -> apdu::Result<Box<dyn Transport>> {
        Ok(Box::new(SigningTransport {
            inner: self.inner.open(serial)?,
            forbid_public: self.forbid_public.clone(),
        }))
    }
}

struct Rig {
    emu: Emulator,
    addr: String,
    shell: ShellSigner,
    on: Arc<AtomicBool>,
    forbid_public: Arc<AtomicBool>,
}

fn key(byte: u8) -> logos_signer_interface::wallets::DataKey {
    logos_signer_interface::wallets::DataKey {
        key: Secret::new(hex::encode([byte; 32])),
        generation: 0,
    }
}

/// The store kept in `dir`, every seed in it unlocked.
fn unlocked(dir: &std::path::Path) -> Store {
    let mut store = Store::open(dir).unwrap();
    for (seed, _) in store.closed() {
        store.unlock(&seed, &key(1), &key(1)).unwrap();
    }
    store
}

/// `rig`'s seeds unlocked, as the signer manager's key would.
fn unlock_all(rig: &Rig) {
    for (seed, _) in rig.shell.closed_seeds() {
        rig.shell.open_seed(&seed, &key(1), &key(1)).unwrap();
    }
}

fn rig_with(store: Store) -> Rig {
    let emu = Emulator::new(PHRASE, Confirm::Manual);
    let addr = emu.listen().unwrap();
    let on = Arc::new(AtomicBool::new(true));
    let forbid_public = Arc::new(AtomicBool::new(false));
    let devices = Plug {
        inner: Emulated::new(addr.clone()),
        on: on.clone(),
        forbid_public: forbid_public.clone(),
    };
    let shell = ShellSigner::new(Box::new(devices), store, Box::new(Quiet));
    Rig {
        emu,
        addr,
        shell,
        on,
        forbid_public,
    }
}

/// Press yes for every question the Shell asks until `done` says to stop.
fn answer_until(emu: &Emulator, yes: bool, mut done: impl FnMut() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "the Shell kept waiting"
        );
        if emu.asking().is_some() {
            emu.press(yes);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn add(rig: &Rig, families: Vec<Family>, chain: Chain) -> Vec<Account> {
    let job = rig
        .shell
        .add_accounts(AddRequest {
            families,
            chain,
            account: 0,
            label: None,
            serial: None,
            fingerprint: None,
            master_key_id: None,
            identify: false,
            verify_only: false,
        })
        .unwrap();
    let mut out = None;
    answer_until(&rig.emu, true, || match rig.shell.add_status(&job) {
        Some(a) if a.state == "done" => {
            out = Some(a.accounts);
            true
        }
        Some(a) if a.state == "failed" => panic!("{:?}", a.error),
        _ => false,
    });
    out.unwrap()
}

fn settle(rig: &mut Rig, job: &str, yes: bool) -> JobStatus {
    let mut last = None;
    let shell = &mut rig.shell;
    answer_until(&rig.emu, yes, || {
        let st = shell.status(job).unwrap();
        let done = st.state.is_final();
        last = Some(st);
        done
    });
    last.unwrap()
}

fn sign(rig: &mut Rig, account: &Account, payload: Payload) -> Result<Vec<Signature>> {
    rig.forbid_public.store(true, Ordering::SeqCst);
    let job = rig.shell.sign(SignRequest {
        account: account.id.clone(),
        payload,
        secret: None,
        xpub: None,
    })?;
    settle(rig, &job, true);
    rig.shell.result(&job)
}

fn evm_item(data: &[u8]) -> HashItem {
    HashItem {
        path: None,
        scheme: Scheme::Evm,
        digest: hex::encode(Keccak256::digest(data)),
    }
}

#[test]
fn its_accounts_are_the_published_ones_for_the_test_phrase() {
    let rig = rig_with(Store::new());
    let accounts = add(
        &rig,
        vec![Family::Evm, Family::Bitcoin, Family::BitcoinTaproot],
        Chain::Main,
    );
    assert_eq!(accounts[0].id, "0x9858effd232b4033e47d90003d41ec34ecaeda94");
    // From bitcoin/bips at 927b6de9915c (2026-10-02): BIP84's account 0 zpub and BIP86's xpub,
    // both for the "abandon … about" mnemonic. The zpub is compared past its version.
    let ours = bitcoin::base58::decode_check(accounts[1].xpub.as_deref().unwrap()).unwrap();
    let bip84 = bitcoin::base58::decode_check(
        "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
    )
    .unwrap();
    assert_eq!(&ours[4..], &bip84[4..]);
    assert_eq!(
        accounts[2].xpub.as_deref(),
        Some("xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ")
    );
    assert_eq!(accounts[1].fingerprint.as_deref(), Some("73c5da0a"));
}

#[test]
fn it_passes_the_conformance_suite() {
    let mut rig = rig_with(Store::new());
    add(
        &rig,
        vec![Family::Evm, Family::Bitcoin, Family::BitcoinTaproot],
        Chain::Test,
    );
    let emu = rig.emu.clone();
    conformance::run(
        &mut rig.shell,
        &Fixture {
            secret: None,
            wrong_secret: None,
        },
        &mut |s, job| {
            answer_until(&emu, true, || emu.asking().is_some() || ended(s, job));
            emu.press(true);
        },
    );
}

/// A signing job or an unlock-key job has settled, whichever `job` is.
fn ended(s: &mut ShellSigner, job: &str) -> bool {
    match s.status(job) {
        Ok(st) => st.state.is_final(),
        Err(_) => s
            .unlock_key_status(job)
            .map_or(true, |st| st.state.is_final()),
    }
}

#[test]
fn a_legacy_transaction_and_typed_data_are_signed_on_its_screen() {
    let mut rig = rig_with(Store::new());
    let evm = add(&rig, vec![Family::Evm], Chain::Test).remove(0);
    // EIP-155's own example of a signing payload, on chain 1, and the same on Sepolia, whose
    // v no longer fits a byte.
    let mainnet = hex::decode("ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080").unwrap();
    let sepolia = hex::decode(
        "ef098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008083aa36a78080",
    )
    .unwrap();
    for (chain_id, tx) in [(1, mainnet), (11_155_111, sepolia)] {
        let sigs = sign(
            &mut rig,
            &evm,
            Payload::EvmTransaction {
                chain_id,
                tx: hex::encode(&tx),
            },
        )
        .unwrap();
        check(&evm, &evm_item(&tx), &sigs[0]).unwrap_or_else(|e| panic!("chain {chain_id}: {e}"));
    }
    let typed = serde_json::json!({
        "types": {
            "EIP712Domain": [{ "name": "name", "type": "string" }, { "name": "chainId", "type": "uint256" }],
            "Note": [{ "name": "text", "type": "string" }]
        },
        "primaryType": "Note",
        "domain": { "name": "Logos", "chainId": 1 },
        "message": { "text": "shown on the Shell" }
    });
    let hash = serde_json::from_value::<alloy::dyn_abi::TypedData>(typed.clone())
        .unwrap()
        .eip712_signing_hash()
        .unwrap();
    let sigs = sign(&mut rig, &evm, Payload::EvmTypedData { typed_data: typed }).unwrap();
    let item = HashItem {
        path: None,
        scheme: Scheme::Evm,
        digest: hex::encode(hash),
    };
    check(&evm, &item, &sigs[0]).unwrap();
}

#[test]
fn a_refusal_on_the_shell_is_a_refused_job() {
    let mut rig = rig_with(Store::new());
    let accounts = add(&rig, vec![Family::Evm, Family::Bitcoin], Chain::Test);
    let job = rig
        .shell
        .sign(SignRequest {
            account: accounts[0].id.clone(),
            payload: Payload::EvmMessage {
                message: hex::encode("no thanks"),
            },
            secret: None,
            xpub: None,
        })
        .unwrap();
    let st = settle(&mut rig, &job, false);
    assert_eq!(st.state, JobState::Refused, "{st:?}");
    let base = accounts[1].path.clone().unwrap();
    let (psbt, _) = conformance::psbt_for(
        &accounts[1],
        &[(format!("{base}/0/0"), format!("{base}/0/0"))],
    );
    let job = rig
        .shell
        .sign(SignRequest {
            account: accounts[1].id.clone(),
            payload: Payload::BtcPsbt {
                network: "testnet".into(),
                psbt,
            },
            secret: None,
            xpub: None,
        })
        .unwrap();
    let st = settle(&mut rig, &job, false);
    assert_eq!(st.state, JobState::Refused);
    assert!(
        st.error.unwrap().message.contains("as its screen says"),
        "a PSBT's refusal can't say which"
    );
}

#[test]
fn one_request_at_a_time_and_a_cancelled_one_signs_nothing() {
    let mut rig = rig_with(Store::new());
    let evm = add(&rig, vec![Family::Evm], Chain::Test).remove(0);
    let ask = |text: &str| SignRequest {
        account: evm.id.clone(),
        payload: Payload::EvmMessage {
            message: hex::encode(text),
        },
        secret: None,
        xpub: None,
    };
    let first = rig.shell.sign(ask("first")).unwrap();
    assert_eq!(
        rig.shell.sign(ask("second")).unwrap_err().code,
        ErrorCode::Busy
    );
    // Cancel an in-flight device request. With a cached root, cancellation can
    // otherwise win before the worker starts, in which case no prompt is correct.
    answer_until(&rig.emu, true, || rig.emu.asking().is_some());
    rig.shell.cancel(&first).unwrap();
    // The Shell still shows it; whatever the person does, nothing comes back.
    rig.emu.press(true);
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(rig.shell.status(&first).unwrap().state, JobState::Cancelled);
    assert!(rig.shell.result(&first).is_err());
    let next = rig.shell.sign(ask("second")).unwrap();
    assert_eq!(
        settle(&mut rig, &next, true).state,
        JobState::Done,
        "free again once the Shell answered"
    );
}

#[test]
fn an_unplugged_shell_keeps_its_accounts_listed_and_signs_nothing() {
    let mut rig = rig_with(Store::new());
    let evm = add(&rig, vec![Family::Evm], Chain::Test).remove(0);
    rig.on.store(false, Ordering::SeqCst);
    rig.shell.refresh();
    let listed = rig.shell.accounts().unwrap();
    assert_eq!(listed.len(), 1);
    assert!(!listed[0].available);
    let e = rig
        .shell
        .sign(SignRequest {
            account: evm.id,
            payload: Payload::EvmMessage {
                message: "00".into(),
            },
            secret: None,
            xpub: None,
        })
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Unavailable);
}

#[test]
fn its_accounts_are_kept_and_can_be_removed() {
    let dir = std::env::temp_dir().join(format!("kshell-store-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let rig = rig_with(Store::open(&dir).unwrap());
    let added = add(&rig, vec![Family::Evm, Family::BitcoinTaproot], Chain::Test);
    unlock_all(&rig);
    drop(rig);
    let mut locked = rig_with(Store::open(&dir).unwrap());
    assert!(
        locked.shell.accounts().unwrap().is_empty(),
        "none offered while locked"
    );
    let more = add(&locked, vec![Family::Bitcoin], Chain::Test);
    assert!(
        locked.shell.accounts().unwrap().is_empty(),
        "one added while locked waits for the key"
    );
    unlock_all(&locked);
    assert_eq!(locked.shell.accounts().unwrap().len(), 3);
    assert!(locked.shell.remove_account(&more[0].id).unwrap());
    drop(locked);
    let mut again = rig_with(unlocked(&dir));
    let listed = again.shell.accounts().unwrap();
    assert_eq!(
        listed.iter().map(|a| a.id.clone()).collect::<Vec<_>>(),
        added.iter().map(|a| a.id.clone()).collect::<Vec<_>>()
    );
    assert!(again.shell.remove_account(&added[1].id).unwrap());
    assert_eq!(again.shell.accounts().unwrap().len(), 1);
    let kept = std::fs::read_to_string(dir.join("accounts.sealed.json")).unwrap();
    for public in [&added[0].id, &added[1].id] {
        assert!(!kept.contains(public.as_str()), "{kept}");
    }
    assert!(
        !kept.contains("pub") && !kept.contains("prv") && !kept.contains(&again.emu.serial()),
        "{kept}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_emulator_answers_the_shells_device_info() {
    let rig = rig_with(Store::new());
    let devices = rig.shell.devices();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].serial, rig.emu.serial());
    assert_eq!(devices[0].firmware.as_deref(), Some("1.4.0"));
}

/// The suite's taproot PSBT at the account's first address, its internal key replaced by `internal`.
fn taproot_psbt(
    account: &Account,
    internal: Option<bitcoin::XOnlyPublicKey>,
) -> (String, Vec<HashItem>) {
    let base = account.path.clone().unwrap();
    let path = format!("{base}/0/0");
    let (psbt, items) = conformance::psbt_for(account, &[(path.clone(), path)]);
    let mut p = bitcoin::Psbt::from_str(&psbt).unwrap();
    p.inputs[0].tap_internal_key = internal;
    (p.to_string(), items)
}

#[test]
fn a_taproot_psbt_without_its_internal_key_has_it_named_and_signs() {
    let mut rig = rig_with(Store::new());
    let taproot = add(&rig, vec![Family::BitcoinTaproot], Chain::Test).remove(0);
    let (psbt, items) = taproot_psbt(&taproot, None);
    let payload = Payload::BtcPsbt {
        network: "testnet".into(),
        psbt,
    };
    let sigs = sign(&mut rig, &taproot, payload).unwrap();
    check(&taproot, &items[0], &sigs[0]).unwrap();
}

#[test]
fn a_taproot_psbt_naming_another_internal_key_is_refused_before_the_shell() {
    let mut rig = rig_with(Store::new());
    let taproot = add(&rig, vec![Family::BitcoinTaproot], Chain::Test).remove(0);
    // The generator's x coordinate: a key, but not this account's.
    let other = bitcoin::XOnlyPublicKey::from_str(
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    )
    .unwrap();
    let (psbt, _) = taproot_psbt(&taproot, Some(other));
    let e = rig
        .shell
        .sign(SignRequest {
            account: taproot.id.clone(),
            payload: Payload::BtcPsbt {
                network: "testnet".into(),
                psbt,
            },
            secret: None,
            xpub: None,
        })
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::Invalid, "{}", e.message);
}

#[test]
fn the_emulator_refuses_a_taproot_input_without_its_internal_key_as_the_firmware_does() {
    let rig = rig_with(Store::new());
    let taproot = add(&rig, vec![Family::BitcoinTaproot], Chain::Test).remove(0);
    let (psbt, _) = taproot_psbt(&taproot, None);
    let bytes = bitcoin::Psbt::from_str(&psbt).unwrap().serialize();
    let mut t = Emulated::new(rig.addr.clone())
        .open(&rig.emu.serial())
        .unwrap();
    let answer = commands::sign_psbt(&mut *t, &bytes);
    assert!(matches!(answer, Err(ShellError::InvalidData)), "{answer:?}");
}

#[test]
fn additional_evm_accounts_keep_their_path_and_wallet_group() {
    let mut rig = rig_with(Store::new());
    let first = add(&rig, vec![Family::Evm], Chain::Main).remove(0);
    let job = rig
        .shell
        .add_accounts(AddRequest {
            families: vec![Family::Evm],
            chain: Chain::Main,
            account: 1,
            label: Some("Second".into()),
            serial: None,
            fingerprint: first.fingerprint.clone(),
            master_key_id: None,
            identify: false,
            verify_only: false,
        })
        .unwrap();
    answer_until(&rig.emu, true, || {
        rig.shell
            .add_status(&job)
            .is_some_and(|s| s.state != "confirm_on_device")
    });
    let result = rig.shell.add_status(&job).unwrap();
    assert_eq!(result.state, "done");
    assert_ne!(first.id, result.accounts[0].id);
    assert_eq!(result.accounts[0].path.as_deref(), Some("m/44'/60'/0'/0/1"));
    let tx = hex::decode("ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080").unwrap();
    let sigs = sign(
        &mut rig,
        &result.accounts[0],
        Payload::EvmTransaction {
            chain_id: 1,
            tx: hex::encode(&tx),
        },
    )
    .unwrap();
    check(&result.accounts[0], &evm_item(&tx), &sigs[0]).unwrap();
    let groups = rig.shell.wallet_groups();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0]["accounts"].as_array().unwrap().len(), 2);
    let id = groups[0]["id"].as_str().unwrap();
    rig.shell.rename_wallet(id, "Travel").unwrap();
    assert_eq!(rig.shell.wallet_groups()[0]["name"], "Travel");
    let wrong = rig
        .shell
        .add_accounts(AddRequest {
            families: vec![Family::Evm],
            chain: Chain::Main,
            account: 2,
            label: None,
            serial: None,
            fingerprint: Some("00000000".into()),
            master_key_id: None,
            identify: false,
            verify_only: false,
        })
        .unwrap();
    answer_until(&rig.emu, true, || {
        rig.shell
            .add_status(&wrong)
            .is_some_and(|s| s.state != "confirm_on_device")
    });
    assert_eq!(rig.shell.add_status(&wrong).unwrap().state, "failed");
    assert_eq!(
        rig.shell.wallet_groups()[0]["accounts"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    rig.shell.forget_wallet(id).unwrap();
    assert!(rig.shell.wallet_groups().is_empty());
}

#[test]
fn wallet_names_and_empty_wallets_survive_reload() {
    let dir = std::env::temp_dir().join(format!(
        "shell-wallets-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let rig = rig_with(Store::open(&dir).unwrap());
    let account = add(&rig, vec![Family::Evm], Chain::Main).remove(0);
    let id = rig.shell.wallet_groups()[0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    rig.shell.rename_wallet(&id, "Travel").unwrap();
    rig.shell.remove_account(&account.id).unwrap();
    unlock_all(&rig);
    let restored = rig_with(unlocked(&dir));
    let groups = restored.shell.wallet_groups();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0]["name"], "Travel");
    assert!(groups[0]["accounts"].as_array().unwrap().is_empty());
    restored.shell.forget_wallet(&id).unwrap();
    assert!(Store::open(&dir).unwrap().closed().is_empty());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn account_renaming_persists_without_changing_keys_and_rolls_back_on_write_failure() {
    let dir = std::env::temp_dir().join(format!("shell-account-name-{}", std::process::id()));
    let rig = rig_with(Store::open(&dir).unwrap());
    let account = add(&rig, vec![Family::Evm], Chain::Main).remove(0);
    unlock_all(&rig);
    let original = unlocked(&dir).find(&account.id).unwrap().clone();
    rig.shell
        .rename_account(&account.id.to_uppercase(), "  Travel ETH  ")
        .unwrap();
    let mut expected = original.clone();
    expected.account.label = Some("Travel ETH".into());
    assert_eq!(unlocked(&dir).find(&account.id), Some(&expected));
    assert_eq!(
        rig.shell.wallet_groups()[0]["accounts"][0]["label"],
        "Travel ETH"
    );
    assert!(rig.shell.rename_account("unknown", "Other").is_err());
    assert!(rig
        .shell
        .rename_account(&account.id, &"x".repeat(81))
        .is_err());
    assert!(rig.shell.rename_account(&account.id, "bad\nname").is_err());
    rig.shell.rename_account(&account.id, " ").unwrap();
    expected.account.label = None;
    assert_eq!(unlocked(&dir).find(&account.id), Some(&expected));
    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::write(&dir, "not a directory").unwrap();
    assert!(rig.shell.rename_account(&account.id, "Unsaved").is_err());
    assert!(rig.shell.wallet_groups()[0]["accounts"][0]["label"].is_null());
    std::fs::remove_file(dir).unwrap();
}

#[test]
fn legacy_wallet_migration_preserves_names_and_verifies_each_full_account_key() {
    let dir = std::env::temp_dir().join(format!("shell-seed-migrate-{}", std::process::id()));
    let rig = rig_with(Store::open(&dir).unwrap());
    let account = add(&rig, vec![Family::Evm], Chain::Main).remove(0);
    unlock_all(&rig);
    let mut old = unlocked(&dir).find(&account.id).unwrap().clone();
    let root = old.master_key_id.clone();
    let mut guarded = unlocked(&dir);
    let original = old.clone();
    let mut wrong_key = old.clone();
    wrong_key.key = "other full public key".into();
    assert!(guarded.put(vec![wrong_key]).is_err());
    assert_eq!(guarded.find(&account.id), Some(&original));
    old.master_key_id.clear();
    old.account.label = Some("Existing savings".into());
    let mut legacy = Store::new();
    legacy.put(vec![old.clone()]).unwrap();
    let old_id = keycard_shell_module::store::wallet_id(&old);
    legacy
        .rename_wallet(&old_id, "Existing travel wallet")
        .unwrap();
    // A colliding short fingerprint does not prove this second saved key is the same seed.
    let mut collision = old.clone();
    collision.account.id = "different-account".into();
    collision.key = "wrong-full-key".into();
    legacy.put(vec![collision]).unwrap();
    let migrated = rig_with(legacy);
    let job = migrated
        .shell
        .add_accounts(AddRequest {
            families: vec![],
            chain: Chain::Main,
            account: 0,
            label: None,
            serial: None,
            fingerprint: None,
            master_key_id: None,
            identify: true,
            verify_only: false,
        })
        .unwrap();
    answer_until(&migrated.emu, true, || {
        migrated
            .shell
            .add_status(&job)
            .is_some_and(|s| s.state != "confirm_on_device")
    });
    assert_eq!(migrated.shell.add_status(&job).unwrap().state, "done");
    let groups = migrated.shell.wallet_groups();
    assert_eq!(
        groups.len(),
        2,
        "the colliding legacy account stays separate"
    );
    let g = groups
        .iter()
        .find(|g| g["id"] == format!("seed:{root}"))
        .unwrap();
    assert_eq!(g["name"], "Existing travel wallet");
    assert_eq!(g["accounts"][0]["label"], "Existing savings");
    let legacy = groups.iter().find(|g| g["id"] == old_id).unwrap();
    assert_eq!(legacy["accounts"][0]["id"], "different-account");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn one_seed_on_two_shells_is_one_wallet_and_signs_through_the_remaining_shell() {
    struct TwoShells {
        inner: Emulated,
        first: Arc<AtomicBool>,
    }
    impl Devices for TwoShells {
        fn connected(&self) -> Vec<String> {
            let mut ids = vec!["shell-b".into()];
            if self.first.load(Ordering::SeqCst) {
                ids.push("shell-a".into());
            }
            ids
        }
        fn open(&self, _: &str) -> apdu::Result<Box<dyn Transport>> {
            self.inner.open(&self.inner.connected()[0])
        }
    }
    let emu = Emulator::new(PHRASE, Confirm::Manual);
    let addr = emu.listen().unwrap();
    let first = Arc::new(AtomicBool::new(true));
    let mut shell = ShellSigner::new(
        Box::new(TwoShells {
            inner: Emulated::new(addr),
            first: first.clone(),
        }),
        Store::new(),
        Box::new(Quiet),
    );
    for serial in ["shell-b", "shell-a"] {
        let job = shell
            .add_accounts(AddRequest {
                families: vec![Family::Evm],
                chain: Chain::Main,
                account: 0,
                label: Some("Savings".into()),
                serial: Some(serial.into()),
                fingerprint: None,
                master_key_id: None,
                identify: false,
                verify_only: false,
            })
            .unwrap();
        answer_until(&emu, true, || {
            shell
                .add_status(&job)
                .is_some_and(|s| s.state != "confirm_on_device")
        });
        assert_eq!(shell.add_status(&job).unwrap().state, "done");
    }
    let groups = shell.wallet_groups();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0]["connections"].as_array().unwrap().len(), 2);
    assert_eq!(groups[0]["accounts"].as_array().unwrap().len(), 1);
    let wrong = shell
        .add_accounts(AddRequest {
            families: vec![Family::Evm],
            chain: Chain::Main,
            account: 1,
            label: None,
            serial: Some("shell-a".into()),
            fingerprint: None,
            master_key_id: Some("different-root".into()),
            identify: false,
            verify_only: false,
        })
        .unwrap();
    answer_until(&emu, true, || {
        shell
            .add_status(&wrong)
            .is_some_and(|s| s.state != "confirm_on_device")
    });
    assert_eq!(shell.add_status(&wrong).unwrap().state, "failed");
    first.store(false, Ordering::SeqCst);
    shell.refresh();
    let account = shell.accounts().unwrap().remove(0);
    assert!(account.available);
    let job = shell
        .sign(SignRequest {
            account: account.id.clone(),
            payload: Payload::EvmMessage {
                message: hex::encode("remaining Shell"),
            },
            secret: None,
            xpub: None,
        })
        .unwrap();
    answer_until(&emu, true, || shell.status(&job).unwrap().state.is_final());
    assert_eq!(shell.status(&job).unwrap().state, JobState::Done);
    assert_eq!(shell.result(&job).unwrap().len(), 1);
}

#[test]
fn a_public_offer_uses_an_unregistered_shell_without_importing_or_reexporting_the_root() {
    let source = rig_with(Store::new());
    let account = add(&source, vec![Family::Evm], Chain::Test).remove(0);
    let v = source.shell.routing_accounts()[&account.id].clone();
    let mut target = rig_with(Store::new());
    let offer = keycard_shell_module::store::Offered {
        account: account.clone(),
        serial: "old-shell".into(),
        master_key_id: v["masterKeyId"].as_str().unwrap().into(),
        key: v["key"].as_str().unwrap().into(),
    };
    let request = || SignRequest {
        account: account.id.clone(),
        payload: Payload::EvmMessage {
            message: hex::encode(b"routing test"),
        },
        secret: None,
        xpub: None,
    };
    let job = target.shell.sign_offered(request(), offer.clone()).unwrap();
    assert_eq!(settle(&mut target, &job, true).state, JobState::Done);
    assert!(!target.shell.result(&job).unwrap().is_empty());
    assert!(target.shell.accounts().unwrap().is_empty());
    target.forbid_public.store(true, Ordering::SeqCst);
    let job = target.shell.sign_offered(request(), offer.clone()).unwrap();
    assert_eq!(settle(&mut target, &job, true).state, JobState::Done);
    let mut wrong = offer.clone();
    wrong.master_key_id = "00".repeat(32);
    let job = target.shell.sign_offered(request(), wrong).unwrap();
    assert_eq!(settle(&mut target, &job, true).state, JobState::Failed);
    assert!(target.shell.result(&job).is_err());
    let job = target.shell.sign_offered(request(), offer).unwrap();
    assert_eq!(settle(&mut target, &job, false).state, JobState::Refused);
    assert!(target.shell.accounts().unwrap().is_empty());
}

#[test]
fn a_different_seed_is_skipped_but_a_refusal_ends_verification() {
    struct Pair {
        old: Emulated,
        matching: Emulated,
        opened_matching: Arc<AtomicBool>,
    }
    impl Devices for Pair {
        fn connected(&self) -> Vec<String> {
            vec!["original".into(), "new-reader".into()]
        }
        fn open(&self, serial: &str) -> apdu::Result<Box<dyn Transport>> {
            let device = if serial == "original" {
                &self.old
            } else {
                self.opened_matching.store(true, Ordering::SeqCst);
                &self.matching
            };
            device.open(&device.connected()[0])
        }
    }
    let source = rig_with(Store::new());
    let account = add(&source, vec![Family::Evm], Chain::Test).remove(0);
    let v = source.shell.routing_accounts()[&account.id].clone();
    for decision in [Confirm::Auto, Confirm::Refuse] {
        let wrong = Emulator::new("different public test seed", decision);
        let matching = Emulator::new(PHRASE, Confirm::Auto);
        let opened = Arc::new(AtomicBool::new(false));
        let mut target = ShellSigner::new(
            Box::new(Pair {
                old: Emulated::new(wrong.listen().unwrap()),
                matching: Emulated::new(matching.listen().unwrap()),
                opened_matching: opened.clone(),
            }),
            Store::new(),
            Box::new(Quiet),
        );
        let offer = keycard_shell_module::store::Offered {
            account: account.clone(),
            serial: "original".into(),
            master_key_id: v["masterKeyId"].as_str().unwrap().into(),
            key: v["key"].as_str().unwrap().into(),
        };
        let job = target
            .sign_offered(
                SignRequest {
                    account: account.id.clone(),
                    payload: Payload::EvmMessage {
                        message: hex::encode("two connections"),
                    },
                    secret: None,
                    xpub: None,
                },
                offer,
            )
            .unwrap();
        answer_until(&matching, true, || {
            target.status(&job).unwrap().state.is_final()
        });
        assert_eq!(
            target.status(&job).unwrap().state,
            if decision == Confirm::Auto {
                JobState::Done
            } else {
                JobState::Refused
            }
        );
        assert_eq!(opened.load(Ordering::SeqCst), decision == Confirm::Auto);
        if decision == Confirm::Auto {
            let sigs = target.result(&job).unwrap();
            let item = evm_item(b"\x19Ethereum Signed Message:\n15two connections");
            check(&account, &item, &sigs[0]).unwrap();
        } else {
            assert!(target.result(&job).is_err());
        }
        assert!(target.accounts().unwrap().is_empty());
    }
}

// Model USB attachment generations separately from the persistent Shell serial. Changing
// the emulator behind an unchanged generation models an in-place seed reset.
struct SessionDevices {
    address: Arc<std::sync::Mutex<String>>,
    generation: Arc<std::sync::atomic::AtomicU64>,
    root_requests: Arc<std::sync::atomic::AtomicUsize>,
}
struct CountRoots {
    inner: Box<dyn Transport>,
    count: Arc<std::sync::atomic::AtomicUsize>,
}
impl Transport for CountRoots {
    fn exchange(&mut self, command: &[u8]) -> apdu::Result<Vec<u8>> {
        if command.get(1) == Some(&apdu::GET_PUBLIC) && command.get(5) == Some(&0) {
            self.count.fetch_add(1, Ordering::SeqCst);
        }
        self.inner.exchange(command)
    }
}
impl Devices for SessionDevices {
    fn connected(&self) -> Vec<String> {
        if self.generation.load(Ordering::SeqCst) == 0 {
            vec![]
        } else {
            vec!["same-shell".into()]
        }
    }
    fn connections(&self) -> Vec<(String, String)> {
        self.connected()
            .into_iter()
            .map(|s| (s, self.generation.load(Ordering::SeqCst).to_string()))
            .collect()
    }
    fn open(&self, serial: &str) -> apdu::Result<Box<dyn Transport>> {
        Ok(Box::new(CountRoots {
            inner: Emulated::new(self.address.lock().unwrap().clone()).open(serial)?,
            count: self.root_requests.clone(),
        }))
    }
}

#[test]
fn root_verification_is_per_attachment_and_never_persisted() {
    use std::sync::atomic::{AtomicU64, AtomicUsize};
    let source = rig_with(Store::new());
    let account = add(&source, vec![Family::Evm], Chain::Test).remove(0);
    let v = source.shell.routing_accounts()[&account.id].clone();
    let offer = keycard_shell_module::store::Offered {
        account: account.clone(),
        serial: "same-shell".into(),
        master_key_id: v["masterKeyId"].as_str().unwrap().into(),
        key: v["key"].as_str().unwrap().into(),
    };
    let emu = Emulator::new(PHRASE, Confirm::Auto);
    let address = Arc::new(std::sync::Mutex::new(emu.listen().unwrap()));
    let generation = Arc::new(AtomicU64::new(1));
    let count = Arc::new(AtomicUsize::new(0));
    let make_signer = || {
        ShellSigner::new(
            Box::new(SessionDevices {
                address: address.clone(),
                generation: generation.clone(),
                root_requests: count.clone(),
            }),
            Store::new(),
            Box::new(Quiet),
        )
    };
    let request = || SignRequest {
        account: account.id.clone(),
        payload: Payload::EvmMessage {
            message: hex::encode("session test"),
        },
        secret: None,
        xpub: None,
    };
    let attempt = |target: &mut ShellSigner| {
        let job = target.sign_offered(request(), offer.clone()).unwrap();
        answer_until(&emu, true, || target.status(&job).unwrap().state.is_final());
        target.result(&job)
    };
    let mut target = make_signer();
    let item = evm_item(b"\x19Ethereum Signed Message:\n12session test");
    for _ in 0..2 {
        check(&account, &item, &attempt(&mut target).unwrap()[0]).unwrap();
    }
    assert_eq!(
        count.load(Ordering::SeqCst),
        1,
        "one root prompt per connection"
    );
    assert!(target.devices()[0].verified_master_key_id.is_some());

    // A quick disconnect/reconnect with the same serial between polls still invalidates.
    generation.store(2, Ordering::SeqCst);
    target.refresh();
    assert!(target.devices()[0].verified_master_key_id.is_none());
    attempt(&mut target).unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 2);
    // Observed removal invalidates even if a backend reuses its attachment path.
    generation.store(0, Ordering::SeqCst);
    target.refresh();
    generation.store(2, Ordering::SeqCst);
    target.refresh();
    attempt(&mut target).unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 3);

    drop(target);
    let mut target = make_signer();
    assert!(target.devices()[0].verified_master_key_id.is_none());
    attempt(&mut target).unwrap();
    assert_eq!(
        count.load(Ordering::SeqCst),
        4,
        "restart must not reuse verification"
    );

    // A failed link invalidates verification even if enumeration still reports the device.
    let working = address.lock().unwrap().clone();
    *address.lock().unwrap() = "127.0.0.1:0".into();
    assert!(attempt(&mut target).is_err());
    assert!(target.devices()[0].verified_master_key_id.is_none());
    *address.lock().unwrap() = working;
    attempt(&mut target).unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 5);

    // An in-place reset deliberately keeps the attachment identity. The returned
    // signature must still fail the same account verification used by the manager.
    let other = Emulator::new("different public test seed", Confirm::Auto);
    *address.lock().unwrap() = other.listen().unwrap();
    let sigs = attempt(&mut target).unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 5);
    assert!(check(&account, &item, &sigs[0]).is_err());

    // After reconnection the different seed is rejected before a signature is returned.
    generation.store(3, Ordering::SeqCst);
    assert!(attempt(&mut target).is_err());
    assert_eq!(count.load(Ordering::SeqCst), 6);
}

#[test]
fn refused_verification_is_not_cached() {
    use std::sync::atomic::{AtomicU64, AtomicUsize};
    let source = rig_with(Store::new());
    let account = add(&source, vec![Family::Evm], Chain::Test).remove(0);
    let v = source.shell.routing_accounts()[&account.id].clone();
    let offer = keycard_shell_module::store::Offered {
        account: account.clone(),
        serial: "same-shell".into(),
        master_key_id: v["masterKeyId"].as_str().unwrap().into(),
        key: v["key"].as_str().unwrap().into(),
    };
    let refused = Emulator::new(PHRASE, Confirm::Refuse);
    let count = Arc::new(AtomicUsize::new(0));
    let mut target = ShellSigner::new(
        Box::new(SessionDevices {
            address: Arc::new(std::sync::Mutex::new(refused.listen().unwrap())),
            generation: Arc::new(AtomicU64::new(1)),
            root_requests: count.clone(),
        }),
        Store::new(),
        Box::new(Quiet),
    );
    for expected in 1..=2 {
        let job = target
            .sign_offered(
                SignRequest {
                    account: account.id.clone(),
                    payload: Payload::EvmMessage {
                        message: hex::encode("no"),
                    },
                    secret: None,
                    xpub: None,
                },
                offer.clone(),
            )
            .unwrap();
        answer_until(&refused, false, || {
            target.status(&job).unwrap().state.is_final()
        });
        assert_eq!(target.status(&job).unwrap().state, JobState::Refused);
        assert_eq!(count.load(Ordering::SeqCst), expected);
        assert!(target.devices()[0].verified_master_key_id.is_none());
    }
}

#[test]
fn manual_verification_replaces_the_cache_without_changing_saved_wallets() {
    use std::sync::atomic::{AtomicU64, AtomicUsize};
    let source = rig_with(Store::new());
    let account = add(&source, vec![Family::Evm], Chain::Test).remove(0);
    let v = source.shell.routing_accounts()[&account.id].clone();
    let root = v["masterKeyId"].as_str().unwrap().to_string();
    let offer = keycard_shell_module::store::Offered {
        account: account.clone(),
        serial: "same-shell".into(),
        master_key_id: root.clone(),
        key: v["key"].as_str().unwrap().into(),
    };
    let emu = Emulator::new(PHRASE, Confirm::Auto);
    let address = Arc::new(std::sync::Mutex::new(emu.listen().unwrap()));
    let count = Arc::new(AtomicUsize::new(0));
    let mut store = Store::new();
    store
        .put_identified(vec![offer], &root, "same-shell")
        .unwrap();
    store
        .rename_wallet(&format!("seed:{root}"), "Saved wallet name")
        .unwrap();
    let target = ShellSigner::new(
        Box::new(SessionDevices {
            address: address.clone(),
            generation: Arc::new(AtomicU64::new(1)),
            root_requests: count.clone(),
        }),
        store,
        Box::new(Quiet),
    );
    let before = target.wallet_groups();
    let verify = || {
        let job = target
            .add_accounts(AddRequest {
                families: vec![],
                chain: Chain::Test,
                account: 0,
                label: None,
                serial: Some("same-shell".into()),
                fingerprint: None,
                master_key_id: Some(root.clone()),
                identify: false,
                verify_only: true,
            })
            .unwrap();
        answer_until(&emu, true, || {
            target
                .add_status(&job)
                .is_some_and(|s| s.state != "confirm_on_device")
        });
        target.add_status(&job).unwrap()
    };
    for expected in 1..=2 {
        let result = verify();
        assert_eq!(result.state, "done");
        assert!(result.accounts.is_empty());
        assert_eq!(
            count.load(Ordering::SeqCst),
            expected,
            "manual action must bypass a valid cache"
        );
        assert_eq!(
            target.devices()[0].verified_master_key_id.as_ref(),
            Some(&root)
        );
        assert_eq!(target.wallet_groups(), before);
    }
    let refusal = Emulator::new(PHRASE, Confirm::Refuse);
    *address.lock().unwrap() = refusal.listen().unwrap();
    assert_eq!(verify().state, "failed");
    assert_eq!(count.load(Ordering::SeqCst), 3);
    assert!(
        target.devices()[0].verified_master_key_id.is_none(),
        "refusal must not restore the previous verification"
    );
    assert_eq!(target.wallet_groups(), before);
    let other = Emulator::new("different public test seed", Confirm::Auto);
    *address.lock().unwrap() = other.listen().unwrap();
    let result = verify();
    assert_eq!(result.state, "failed");
    assert!(result.error.unwrap().contains("different wallet"));
    assert_ne!(
        target.devices()[0].verified_master_key_id.as_ref(),
        Some(&root)
    );
    assert_eq!(
        target.wallet_groups(),
        before,
        "verification must not import or regroup a different wallet"
    );
}

/// The phrase's own key at `m/1280263247'/n'`, as any other holder of it gives.
fn phrase_unlock_key(phrase: &str, n: u32) -> String {
    use bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let seed = bip39_seed(phrase);
    let master = Xpriv::new_master(bitcoin::NetworkKind::Test, &seed).unwrap();
    let path = DerivationPath::from_str(&format!("m/1280263247'/{n}'")).unwrap();
    hex::encode(
        Xpub::from_priv(&secp, &master.derive_priv(&secp, &path).unwrap())
            .public_key
            .serialize(),
    )
}

fn bip39_seed(phrase: &str) -> [u8; 64] {
    let mut seed = [0u8; 64];
    pbkdf2::pbkdf2_hmac::<sha2::Sha512>(phrase.as_bytes(), b"mnemonic", 2048, &mut seed);
    seed
}

#[test]
fn the_shell_gives_its_phrases_unlock_key_once_its_person_confirms() {
    let mut rig = rig_with(Store::new());
    let added = add(&rig, vec![Family::Evm], Chain::Test);
    let seed = added[0]
        .seed
        .clone()
        .expect("an added account names its seed");
    assert_eq!(
        rig.shell.accounts().unwrap()[0].seed.as_deref(),
        Some(seed.as_str())
    );

    let job = rig
        .shell
        .unlock_key(UnlockKeyRequest {
            seed: seed.clone(),
            index: 1,
            secret: None,
        })
        .unwrap();
    assert_eq!(
        rig.shell.unlock_key_status(&job).unwrap().state,
        JobState::ConfirmOnDevice
    );
    answer_until(&rig.emu, true, || {
        rig.shell.unlock_key_status(&job).unwrap().state.is_final()
    });
    assert_eq!(
        rig.shell.unlock_key_result(&job).unwrap().key.expose(),
        phrase_unlock_key(PHRASE, 1)
    );

    // Declined on the Shell: refused, and no key.
    let job = rig
        .shell
        .unlock_key(UnlockKeyRequest {
            seed,
            index: 0,
            secret: None,
        })
        .unwrap();
    answer_until(&rig.emu, false, || {
        rig.shell.unlock_key_status(&job).unwrap().state.is_final()
    });
    assert_eq!(
        rig.shell.unlock_key_status(&job).unwrap().state,
        JobState::Refused
    );
    let foreign = rig.shell.unlock_key(UnlockKeyRequest {
        seed: "00".repeat(32),
        index: 0,
        secret: None,
    });
    assert_eq!(foreign.unwrap_err().code, ErrorCode::WrongSeed);
}

#[test]
fn a_shell_verified_to_hold_another_seed_leaves_this_ones_accounts_unavailable() {
    let rig = rig_with(Store::new());
    let added = add(&rig, vec![Family::Evm], Chain::Test);
    let mut shell = rig.shell;
    assert!(
        shell.accounts().unwrap()[0].available,
        "its own verified Shell is connected"
    );

    // The same store, with the accounts' seed changed to one the connected Shell doesn't hold.
    let mut other = Store::new();
    let theirs: Vec<_> = shell
        .routing_accounts()
        .as_object()
        .unwrap()
        .values()
        .map(|v| keycard_shell_module::store::Offered {
            account: serde_json::from_value(v["account"].clone()).unwrap(),
            serial: rig.emu.serial(),
            master_key_id: "11".repeat(32),
            key: v["key"].as_str().unwrap().into(),
        })
        .collect();
    other
        .put_identified(theirs, &"11".repeat(32), &rig.emu.serial())
        .unwrap();
    shell.set_store(other);
    let listed = shell.accounts().unwrap();
    assert_eq!(listed[0].seed.as_deref(), Some("11".repeat(32).as_str()));
    assert!(
        !listed[0].available,
        "the connected Shell is verified to hold {:?}",
        added[0].seed
    );
}
