//! The Shell behind `logos.signer/1`: the accounts it offered, kept as public material, and each
//! request signed on its screen in a job of its own, one at a time. Adding accounts asks it too.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use bitcoin::secp256k1::PublicKey;
use bitcoin::Psbt;
use logos_signer_interface::jobs::JobTable;
use logos_signer_interface::{
    Account, Chain, Collects, ErrorCode, Family, JobState, JobStatus, Payload, RequestKind,
    SignRequest, Signature, Signer, SignerError, SignerInfo, INTERFACE,
};
use serde::{Deserialize, Serialize};

use crate::accounts::{self, parse_path, HARDENED};
use crate::answers::{self, VBase};
use crate::apdu::ShellError;
use crate::commands;
use crate::link::Devices;
use crate::store::{Offered, Store};

/// What the module announces; its glue turns these into events.
pub trait Events: Send + Sync {
    fn sign_progress(&self, job: &str, state: JobState);
    fn accounts_changed(&self, count: usize);
    fn device_changed(&self, connected: bool);
}

/// Announces nothing, for tests.
pub struct Quiet;

impl Events for Quiet {
    fn sign_progress(&self, _: &str, _: JobState) {}
    fn accounts_changed(&self, _: usize) {}
    fn device_changed(&self, _: bool) {}
}

/// What the Shell's app asks for: accounts to export from the connected Shell.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AddRequest {
    pub families: Vec<Family>,
    #[serde(default = "test_chain")]
    pub chain: Chain,
    #[serde(default)]
    pub account: u32,
    #[serde(default)]
    pub label: Option<String>,
    /// Which Shell, when more than one is connected.
    #[serde(default)]
    pub serial: Option<String>,
}

fn test_chain() -> Chain {
    Chain::Test
}

/// Where an export stands: `confirm_on_device`, then `done` with the accounts or `failed`.
#[derive(Clone, Debug, Serialize)]
pub struct Added {
    pub state: &'static str,
    pub accounts: Vec<Account>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// A connected Shell, as GET DEVICE INFO describes it.
#[derive(Clone, Debug, Serialize)]
pub struct Device {
    pub serial: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firmware: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<u32>,
    pub busy: bool,
}

struct Shared {
    devices: Box<dyn Devices>,
    store: Mutex<Store>,
    jobs: Mutex<JobTable>,
    adds: Mutex<HashMap<String, Added>>,
    connected: Mutex<Vec<String>>,
    busy: AtomicBool,
    seq: AtomicU64,
    events: Box<dyn Events>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// What one request asks of the Shell, checked before it is touched.
enum Work {
    EvmTx {
        path: Vec<u32>,
        tx: Vec<u8>,
        base: VBase,
        key: PublicKey,
    },
    EvmMessage {
        path: Vec<u32>,
        message: Vec<u8>,
        key: PublicKey,
    },
    EvmTyped {
        path: Vec<u32>,
        json: Vec<u8>,
        key: PublicKey,
    },
    Psbt {
        psbt: Vec<u8>,
        fingerprint: [u8; 4],
    },
}

fn err(code: ErrorCode, msg: impl Into<String>) -> SignerError {
    SignerError::new(code, msg)
}

/// What the Shell's refusal means to the manager. For a PSBT the Shell answers 0x6a80 both when
/// the person declines and when it can't sign, and its own screen says which.
fn shell_error(e: ShellError, psbt: bool) -> SignerError {
    match e {
        ShellError::Denied => err(ErrorCode::Refused, e.to_string()),
        ShellError::InvalidData if psbt => err(
            ErrorCode::Refused,
            "the Keycard Shell didn't sign the PSBT: declined, or it couldn't sign it, as its screen says",
        ),
        ShellError::InvalidData => err(ErrorCode::Invalid, e.to_string()),
        ShellError::Unsupported => err(ErrorCode::Unsupported, e.to_string()),
        ShellError::Conditions | ShellError::Link(_) => err(ErrorCode::Unavailable, e.to_string()),
        ShellError::Cancelled => err(ErrorCode::Refused, e.to_string()),
        ShellError::Status(_) => err(ErrorCode::Internal, e.to_string()),
    }
}

impl Work {
    fn of(offered: &Offered, payload: &Payload) -> Result<Work, SignerError> {
        let account = &offered.account;
        let unsupported = || {
            err(
                ErrorCode::Unsupported,
                format!("{:?} for a {:?} account", payload.kind(), account.family),
            )
        };
        let invalid = |m: String| err(ErrorCode::Invalid, m);
        let unhex = |s: &str| {
            hex::decode(s.trim().trim_start_matches("0x")).map_err(|_| invalid("not hex".into()))
        };
        let evm_path = || {
            parse_path(account.path.as_deref().unwrap_or_default())
                .ok_or_else(|| invalid("account path".into()))
        };
        let key = || {
            hex::decode(&offered.key)
                .ok()
                .and_then(|k| PublicKey::from_slice(&k).ok())
                .ok_or_else(|| {
                    err(
                        ErrorCode::Internal,
                        "the account's key is missing: add it again",
                    )
                })
        };
        match (account.family, payload) {
            (Family::Evm, Payload::EvmTransaction { chain_id, tx }) => {
                let tx = unhex(tx)?;
                Ok(Work::EvmTx {
                    path: evm_path()?,
                    base: VBase::of_tx(&tx, *chain_id),
                    tx,
                    key: key()?,
                })
            }
            (Family::Evm, Payload::EvmMessage { message }) => Ok(Work::EvmMessage {
                path: evm_path()?,
                message: unhex(message)?,
                key: key()?,
            }),
            (Family::Evm, Payload::EvmTypedData { typed_data }) => Ok(Work::EvmTyped {
                path: evm_path()?,
                json: serde_json::to_vec(typed_data).map_err(|e| invalid(e.to_string()))?,
                key: key()?,
            }),
            (Family::Bitcoin | Family::BitcoinTaproot, Payload::BtcPsbt { psbt, .. }) => {
                let fingerprint = hex::decode(account.fingerprint.as_deref().unwrap_or_default())
                    .ok()
                    .and_then(|f| <[u8; 4]>::try_from(f).ok())
                    .ok_or_else(|| invalid("account fingerprint".into()))?;
                let base = parse_path(account.path.as_deref().unwrap_or_default())
                    .ok_or_else(|| invalid("account path".into()))?;
                let parsed =
                    Psbt::from_str(psbt.trim()).map_err(|e| invalid(format!("psbt: {e}")))?;
                check_inputs(&parsed, account.family, fingerprint, &base)?;
                Ok(Work::Psbt {
                    psbt: parsed.serialize(),
                    fingerprint,
                })
            }
            _ => Err(unsupported()),
        }
    }
}

/// Every input must be this wallet's, at a path below the account with two unhardened steps,
/// or the Shell would be asked to sign with a key outside it.
fn check_inputs(
    psbt: &Psbt,
    family: Family,
    fingerprint: [u8; 4],
    base: &[u32],
) -> Result<(), SignerError> {
    for (i, input) in psbt.inputs.iter().enumerate() {
        let ours = |(fp, path): &bitcoin::bip32::KeySource| {
            (fp.to_bytes() == fingerprint).then_some(path.clone())
        };
        let origins: Vec<_> = if family == Family::Bitcoin {
            input.bip32_derivation.values().filter_map(ours).collect()
        } else {
            input
                .tap_key_origins
                .values()
                .filter_map(|(_, source)| ours(source))
                .collect()
        };
        if origins.is_empty() {
            return Err(err(
                ErrorCode::Invalid,
                format!("input {i}: no key of this wallet"),
            ));
        }
        for path in origins {
            let steps: Vec<u32> = path.into_iter().map(|c| u32::from(*c)).collect();
            let below = steps.len() == base.len() + 2
                && steps.starts_with(base)
                && steps[base.len()..].iter().all(|s| s & HARDENED == 0);
            if !below {
                return Err(err(
                    ErrorCode::Invalid,
                    format!("input {i}: a key outside the account"),
                ));
            }
        }
    }
    Ok(())
}

impl Shared {
    fn refresh_connected(&self) {
        let now = self.devices.connected();
        let changed = {
            let mut have = lock(&self.connected);
            let changed = *have != now;
            *have = now.clone();
            changed
        };
        if changed {
            self.events.device_changed(!now.is_empty());
            self.events.accounts_changed(lock(&self.store).list().len());
        }
    }

    fn run(&self, offered: &Offered, work: Work) -> Result<Vec<Signature>, SignerError> {
        let psbt = matches!(work, Work::Psbt { .. });
        let shell = |e| shell_error(e, psbt);
        let mut t = self.devices.open(&offered.serial).map_err(shell)?;
        let t = &mut *t;
        let evm = |a: commands::Vrs, base, key: &PublicKey| {
            answers::evm_signature(&a, base, key)
                .map(|s| vec![s])
                .map_err(|e| err(ErrorCode::Internal, e))
        };
        match work {
            Work::EvmTx {
                path,
                tx,
                base,
                key,
            } => evm(
                commands::sign_eth_tx(t, &path, &tx).map_err(shell)?,
                base,
                &key,
            ),
            Work::EvmMessage { path, message, key } => evm(
                commands::sign_eth_message(t, &path, &message).map_err(shell)?,
                VBase::Message,
                &key,
            ),
            Work::EvmTyped { path, json, key } => evm(
                commands::sign_eip712(t, &path, &json).map_err(shell)?,
                VBase::Message,
                &key,
            ),
            Work::Psbt { psbt, fingerprint } => {
                let out = commands::sign_psbt(t, &psbt).map_err(shell)?;
                let signed = Psbt::deserialize(&out)
                    .map_err(|e| err(ErrorCode::Internal, format!("the PSBT it returned: {e}")))?;
                Ok(answers::psbt_signatures(&signed, fingerprint))
            }
        }
    }

    fn export(&self, serial: &str, req: &AddRequest) -> Result<Vec<Offered>, SignerError> {
        let shell = |e| shell_error(e, false);
        let mut t = self.devices.open(serial).map_err(shell)?;
        let t = &mut *t;
        let mut out = Vec::new();
        for family in &req.families {
            let label = req
                .label
                .clone()
                .or_else(|| Some(default_label(*family, req.chain)));
            let offered = match family {
                Family::Evm => {
                    let e = commands::get_public(t, &accounts::EVM_PATH, false).map_err(shell)?;
                    Offered {
                        account: accounts::evm_account(&e, label),
                        serial: serial.into(),
                        key: hex::encode(e.key.serialize()),
                    }
                }
                Family::Bitcoin | Family::BitcoinTaproot => {
                    let path = accounts::bitcoin_path(*family, req.chain, req.account)
                        .ok_or_else(|| err(ErrorCode::Invalid, "account index"))?;
                    let parent = commands::get_public(t, &path[..2], true).map_err(shell)?;
                    let key = commands::get_public(t, &path, true).map_err(shell)?;
                    let account = accounts::bitcoin_account(
                        &parent,
                        &key,
                        *family,
                        req.chain,
                        req.account,
                        label,
                    )
                    .map_err(|e| err(ErrorCode::Internal, e))?;
                    Offered {
                        account,
                        serial: serial.into(),
                        key: hex::encode(key.key.serialize()),
                    }
                }
            };
            out.push(offered);
        }
        Ok(out)
    }

    fn next_id(&self, prefix: &str) -> String {
        format!("{prefix}_{}", self.seq.fetch_add(1, Ordering::SeqCst) + 1)
    }
}

fn default_label(family: Family, chain: Chain) -> String {
    let what = match family {
        Family::Evm => "EVM",
        Family::Bitcoin => "native segwit",
        Family::BitcoinTaproot => "taproot",
    };
    let test = if family != Family::Evm && chain == Chain::Test {
        " (test)"
    } else {
        ""
    };
    format!("Keycard Shell {what}{test}")
}

/// The module's state, shared with the jobs it runs.
#[derive(Clone)]
pub struct ShellSigner {
    s: Arc<Shared>,
}

impl ShellSigner {
    pub fn new(devices: Box<dyn Devices>, store: Store, events: Box<dyn Events>) -> Self {
        let s = Arc::new(Shared {
            devices,
            store: Mutex::new(store),
            jobs: Mutex::new(JobTable::new()),
            adds: Mutex::new(HashMap::new()),
            connected: Mutex::new(Vec::new()),
            busy: AtomicBool::new(false),
            seq: AtomicU64::new(0),
            events,
        });
        s.refresh_connected();
        ShellSigner { s }
    }

    /// Look for Shells plugged in or out every `every`, while this signer lives.
    pub fn watch(&self, every: Duration) {
        let weak = Arc::downgrade(&self.s);
        std::thread::spawn(move || loop {
            std::thread::sleep(every);
            let Some(s) = weak.upgrade() else { return };
            // A Shell busy with a request answers nothing else until it is done.
            if !s.busy.load(Ordering::SeqCst) {
                s.refresh_connected();
            }
        });
    }

    /// Look for Shells now, as the watcher does every so often.
    pub fn refresh(&self) {
        if !self.s.busy.load(Ordering::SeqCst) {
            self.s.refresh_connected();
        }
    }

    /// Use the accounts kept in `store` from now on, as when the module learns its directory.
    pub fn set_store(&self, store: Store) {
        *lock(&self.s.store) = store;
        self.s
            .events
            .accounts_changed(lock(&self.s.store).list().len());
    }

    pub fn devices(&self) -> Vec<Device> {
        let connected = lock(&self.s.connected).clone();
        connected
            .into_iter()
            .map(|serial| {
                if self.s.busy.load(Ordering::SeqCst) {
                    return Device {
                        serial,
                        firmware: None,
                        database: None,
                        busy: true,
                    };
                }
                let info = self
                    .s
                    .devices
                    .open(&serial)
                    .and_then(|mut t| commands::device_info(&mut *t))
                    .ok();
                Device {
                    firmware: info.as_ref().map(commands::DeviceInfo::firmware_version),
                    database: info.map(|i| i.database),
                    serial,
                    busy: false,
                }
            })
            .collect()
    }

    /// Export the requested accounts from a connected Shell, each confirmed on it: a job id.
    pub fn add_accounts(&self, req: AddRequest) -> Result<String, SignerError> {
        if req.families.is_empty() {
            return Err(err(ErrorCode::Invalid, "name at least one family"));
        }
        if req.account >= HARDENED {
            return Err(err(ErrorCode::Invalid, "account index out of range"));
        }
        let connected = lock(&self.s.connected).clone();
        let serial = match &req.serial {
            Some(want) => connected
                .iter()
                .find(|s| s.eq_ignore_ascii_case(want))
                .cloned(),
            None => connected.first().cloned(),
        }
        .ok_or_else(|| err(ErrorCode::Unavailable, "no Keycard Shell is connected"))?;
        if self.s.busy.swap(true, Ordering::SeqCst) {
            return Err(err(
                ErrorCode::Busy,
                "the Keycard Shell is busy with another request",
            ));
        }
        let id = self.s.next_id("add");
        lock(&self.s.adds).insert(
            id.clone(),
            Added {
                state: "confirm_on_device",
                accounts: Vec::new(),
                error: None,
            },
        );
        let s = Arc::clone(&self.s);
        let job = id.clone();
        std::thread::spawn(move || {
            let outcome = s.export(&serial, &req);
            s.busy.store(false, Ordering::SeqCst);
            let added = match outcome.and_then(|offered| {
                let accounts = offered.iter().map(|o| o.account.clone()).collect();
                lock(&s.store)
                    .put(offered)
                    .map_err(|e| err(ErrorCode::Internal, e.to_string()))?;
                Ok(accounts)
            }) {
                Ok(accounts) => Added {
                    state: "done",
                    accounts,
                    error: None,
                },
                Err(e) => Added {
                    state: "failed",
                    accounts: Vec::new(),
                    error: Some(e.message),
                },
            };
            let done = added.state == "done";
            lock(&s.adds).insert(job, added);
            if done {
                s.events.accounts_changed(lock(&s.store).list().len());
            }
        });
        Ok(id)
    }

    pub fn add_status(&self, job: &str) -> Option<Added> {
        lock(&self.s.adds).get(job).cloned()
    }

    /// Stop offering an account. Nothing on the Shell changes.
    pub fn remove_account(&self, id: &str) -> Result<bool, SignerError> {
        let gone = lock(&self.s.store)
            .remove(id)
            .map_err(|e| err(ErrorCode::Internal, e.to_string()))?;
        if gone {
            self.s
                .events
                .accounts_changed(lock(&self.s.store).list().len());
        }
        Ok(gone)
    }
}

impl Signer for ShellSigner {
    fn info(&self) -> SignerInfo {
        SignerInfo {
            interface: INTERFACE.into(),
            kind: "keycard_shell".into(),
            model: "Keycard Shell".into(),
            families: vec![Family::Evm, Family::Bitcoin, Family::BitcoinTaproot],
            request_kinds: vec![
                RequestKind::EvmTransaction,
                RequestKind::EvmMessage,
                RequestKind::EvmTypedData,
                RequestKind::BtcPsbt,
            ],
            shows_request: true,
            collects: Collects::Nothing,
        }
    }

    fn accounts(&mut self) -> logos_signer_interface::Result<Vec<Account>> {
        let connected = lock(&self.s.connected).clone();
        Ok(lock(&self.s.store)
            .list()
            .iter()
            .map(|o| Account {
                available: connected.contains(&o.serial),
                ..o.account.clone()
            })
            .collect())
    }

    fn sign(&mut self, request: SignRequest) -> logos_signer_interface::Result<String> {
        let offered = lock(&self.s.store)
            .find(&request.account)
            .cloned()
            .ok_or_else(|| {
                err(
                    ErrorCode::UnknownAccount,
                    format!("no account {}", request.account),
                )
            })?;
        let work = Work::of(&offered, &request.payload)?;
        if !lock(&self.s.connected).contains(&offered.serial) {
            return Err(err(
                ErrorCode::Unavailable,
                "the Keycard Shell that holds this account isn't connected",
            ));
        }
        if self.s.busy.swap(true, Ordering::SeqCst) {
            return Err(err(
                ErrorCode::Busy,
                "the Keycard Shell is busy with another request",
            ));
        }
        let job = lock(&self.s.jobs).start(JobState::ConfirmOnDevice);
        let s = Arc::clone(&self.s);
        let id = job.clone();
        std::thread::spawn(move || {
            let outcome = s.run(&offered, work);
            s.busy.store(false, Ordering::SeqCst);
            let state = {
                let mut jobs = lock(&s.jobs);
                let _ = jobs.finish(&id, outcome);
                jobs.status(&id)
                    .map(|st| st.state)
                    .unwrap_or(JobState::Failed)
            };
            s.events.sign_progress(&id, state);
        });
        Ok(job)
    }

    fn status(&mut self, job: &str) -> logos_signer_interface::Result<JobStatus> {
        lock(&self.s.jobs).status(job)
    }

    fn result(&mut self, job: &str) -> logos_signer_interface::Result<Vec<Signature>> {
        lock(&self.s.jobs).result(job)
    }

    /// The Shell keeps showing the request until the person answers it; the answer is dropped.
    fn cancel(&mut self, job: &str) -> logos_signer_interface::Result<()> {
        lock(&self.s.jobs).cancel(job)
    }
}
