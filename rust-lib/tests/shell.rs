//! The module against a Shell in software: its accounts, the conformance suite, and each way a
//! request ends. Every signature is checked with the manager's own check, over a digest worked
//! out here.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use keycard_shell_module::apdu::{self, Transport};
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
        self.inner.open(serial)
    }
}

struct Rig {
    emu: Emulator,
    shell: ShellSigner,
    on: Arc<AtomicBool>,
}

fn rig_with(store: Store) -> Rig {
    let emu = Emulator::new(PHRASE, Confirm::Manual);
    let addr = emu.listen().unwrap();
    let on = Arc::new(AtomicBool::new(true));
    let devices = Plug {
        inner: Emulated::new(addr),
        on: on.clone(),
    };
    let shell = ShellSigner::new(Box::new(devices), store, Box::new(Quiet));
    Rig { emu, shell, on }
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
    let job = rig.shell.sign(SignRequest {
        account: account.id.clone(),
        payload,
        secret: None,
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
            answer_until(&emu, true, || {
                emu.asking().is_some() || s.status(job).unwrap().state.is_final()
            });
            emu.press(true);
        },
    );
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
    };
    let first = rig.shell.sign(ask("first")).unwrap();
    assert_eq!(
        rig.shell.sign(ask("second")).unwrap_err().code,
        ErrorCode::Busy
    );
    rig.shell.cancel(&first).unwrap();
    // The Shell still shows it; whatever the person does, nothing comes back.
    answer_until(&rig.emu, true, || rig.emu.asking().is_some());
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
    drop(rig);
    let mut again = rig_with(Store::open(&dir).unwrap());
    let listed = again.shell.accounts().unwrap();
    assert_eq!(
        listed.iter().map(|a| a.id.clone()).collect::<Vec<_>>(),
        added.iter().map(|a| a.id.clone()).collect::<Vec<_>>()
    );
    assert!(again.shell.remove_account(&added[1].id).unwrap());
    assert_eq!(again.shell.accounts().unwrap().len(), 1);
    let kept = std::fs::read_to_string(dir.join("accounts.json")).unwrap();
    assert!(
        !kept.contains("xprv") && !kept.contains("tprv"),
        "public material only"
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
