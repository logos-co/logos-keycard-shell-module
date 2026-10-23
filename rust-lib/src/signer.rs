//! The Shell behind `logos.signer/1`: the accounts it offered, kept as public material, and each
//! request signed on its screen in a job of its own, one at a time. Adding accounts asks it too.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::PublicKey;
use bitcoin::Psbt;
use logos_signer_interface::jobs::{JobTable, KeyJobs};
use logos_signer_interface::unlock::{evm_path_ok, is_reserved, roster_key, PURPOSE};
use logos_signer_interface::wallets::DataKey;
use logos_signer_interface::{
    Account, Chain, Collects, ErrorCode, Family, JobState, JobStatus, Payload, RequestKind, Secret,
    SignRequest, Signature, Signer, SignerError, SignerInfo, UnlockKey, UnlockKeyRequest,
    INTERFACE,
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
    /// Accounts of a seed were added, with its unlock key at index 0 when the Shell gave it: the
    /// glue registers the seed with the signer manager.
    fn seed_added(&self, _seed: &str, _unlock_key: Option<[u8; 33]>, _name: &str) {}
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
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub master_key_id: Option<String>,
    #[serde(default)]
    pub identify: bool,
    /// Explicitly re-check the connection without importing or regrouping accounts.
    #[serde(default)]
    pub verify_only: bool,
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
    #[serde(
        rename = "verifiedMasterKeyId",
        skip_serializing_if = "Option::is_none"
    )]
    pub verified_master_key_id: Option<String>,
}

// Never persisted: a new signer process starts with no trusted USB connections.
struct ConnectionSession {
    token: String,
    epoch: u64,
    root: Option<commands::Exported>,
}

struct Shared {
    devices: Box<dyn Devices>,
    store: Mutex<Store>,
    jobs: Mutex<JobTable>,
    /// Unlock-key jobs: read once, by the manager only, and announced nowhere.
    keys: Mutex<KeyJobs>,
    adds: Mutex<HashMap<String, Added>>,
    connected: Mutex<Vec<String>>,
    sessions: Mutex<HashMap<String, ConnectionSession>>,
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
        // An edited store could name a path no account has: nothing signs there.
        if let Some(path) = account.path.as_deref() {
            if is_reserved(path) || (account.family == Family::Evm && !evm_path_ok(path)) {
                return Err(invalid(format!("{path} is not an account's path")));
            }
        }
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
                let mut parsed =
                    Psbt::from_str(psbt.trim()).map_err(|e| invalid(format!("psbt: {e}")))?;
                check_inputs(&parsed, account.family, fingerprint, &base)?;
                if account.family == Family::BitcoinTaproot {
                    name_internal_keys(&mut parsed, fingerprint)?;
                }
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

/// The Shell's firmware signs a taproot input only once the PSBT names its internal key, which
/// for this wallet's key-path spend is the key at the input's own path: name it where a wallet left
/// it out. An input naming another key, or a script tree, is no key-path spend of this account.
fn name_internal_keys(psbt: &mut Psbt, fingerprint: [u8; 4]) -> Result<(), SignerError> {
    for (i, input) in psbt.inputs.iter_mut().enumerate() {
        let Some(key) = input
            .tap_key_origins
            .iter()
            .find(|(_, (_, (fp, _)))| fp.to_bytes() == fingerprint)
            .map(|(k, _)| *k)
        else {
            continue;
        };
        if input.tap_merkle_root.is_some() || input.tap_internal_key.is_some_and(|k| k != key) {
            return Err(err(
                ErrorCode::Invalid,
                format!("input {i}: not a key-path spend of this account"),
            ));
        }
        input.tap_internal_key = Some(key);
    }
    Ok(())
}

/// What an add exported: the accounts, the seed's master key id, and its unlock key at index 0.
type Exported = (Vec<Offered>, String, Option<[u8; 33]>);

impl Shared {
    fn refresh_connected(&self) {
        // Serialize enumeration and cache updates so an older poll cannot restore a session.
        let mut sessions = lock(&self.sessions);
        let attachments = self.devices.connections();
        let mut now: Vec<_> = attachments
            .iter()
            .map(|(serial, _)| serial.clone())
            .collect();
        now.sort();
        now.dedup();
        let before = sessions.len();
        sessions.retain(|serial, session| {
            attachments
                .iter()
                .any(|(s, token)| s == serial && token == &session.token)
        });
        let mut changed = sessions.len() != before;
        for (serial, token) in attachments {
            sessions.entry(serial).or_insert_with(|| {
                changed = true;
                ConnectionSession {
                    token,
                    epoch: self.seq.fetch_add(1, Ordering::SeqCst),
                    root: None,
                }
            });
        }
        *lock(&self.connected) = now.clone();
        drop(sessions);
        if changed {
            self.events.device_changed(!now.is_empty());
            self.events.accounts_changed(lock(&self.store).list().len());
        }
    }

    fn open_session(
        &self,
        serial: &str,
    ) -> Result<(Box<dyn crate::apdu::Transport>, u64), SignerError> {
        let (token, epoch) = lock(&self.sessions)
            .get(serial)
            .map(|s| (s.token.clone(), s.epoch))
            .ok_or_else(|| {
                err(
                    ErrorCode::Unavailable,
                    "The Shell disconnected. Reconnect it and retry.",
                )
            })?;
        let t = self
            .devices
            .open_connection(serial, &token)
            .map_err(|e| self.connection_error(serial, epoch, e, false))?;
        Ok((t, epoch))
    }

    fn connection_error(
        &self,
        serial: &str,
        epoch: u64,
        error: ShellError,
        psbt: bool,
    ) -> SignerError {
        if matches!(&error, ShellError::Link(_) | ShellError::Conditions) {
            if let Some(session) = lock(&self.sessions)
                .get_mut(serial)
                .filter(|s| s.epoch == epoch)
            {
                session.root = None;
            }
        }
        shell_error(error, psbt)
    }

    fn verified_root(
        &self,
        serial: &str,
        epoch: u64,
        t: &mut dyn crate::apdu::Transport,
    ) -> Result<commands::Exported, SignerError> {
        if let Some(root) = lock(&self.sessions)
            .get(serial)
            .filter(|s| s.epoch == epoch)
            .and_then(|s| s.root.clone())
        {
            return Ok(root);
        }
        let root = commands::get_public(t, &[], false)
            .map_err(|e| self.connection_error(serial, epoch, e, false))?;
        let mut sessions = lock(&self.sessions);
        let session = sessions
            .get_mut(serial)
            .filter(|s| s.epoch == epoch)
            .ok_or_else(|| {
                err(
                    ErrorCode::Unavailable,
                    "The USB connection changed during verification. Retry.",
                )
            })?;
        session.root = Some(root.clone());
        drop(sessions);
        self.events.accounts_changed(lock(&self.store).list().len());
        Ok(root)
    }

    fn run(&self, offered: &Offered, work: Work, job: &str) -> Result<Vec<Signature>, SignerError> {
        let psbt = matches!(work, Work::Psbt { .. });
        let mut candidates = lock(&self.connected).clone();
        candidates.sort_by_key(|serial| serial != &offered.serial);
        let mut available = None;
        for serial in candidates {
            if lock(&self.jobs)
                .status(job)
                .is_ok_and(|s| s.state == JobState::Cancelled)
            {
                return Err(err(ErrorCode::Refused, "Request cancelled"));
            }
            if offered.master_key_id.is_empty() && serial != offered.serial {
                continue;
            }
            let (mut t, epoch) = match self.open_session(&serial) {
                Ok(t) => t,
                Err(_) => continue,
            };
            let root = self.verified_root(&serial, epoch, &mut *t)?;
            if offered.master_key_id.is_empty() {
                return Err(err(
                    ErrorCode::Invalid,
                    "Identify this wallet before signing.",
                ));
            }
            if master_id(&root.key) != offered.master_key_id {
                continue;
            }
            available = Some((t, serial, epoch));
            break;
        }
        let (mut transport, serial, epoch) = available.ok_or_else(|| {
            err(
                ErrorCode::Unavailable,
                "No connected Shell has this wallet's seed. Insert its Keycard and retry.",
            )
        })?;
        let shell = |e| self.connection_error(&serial, epoch, e, psbt);
        let t = &mut *transport;
        if lock(&self.jobs)
            .status(job)
            .is_ok_and(|s| s.state == JobState::Cancelled)
        {
            return Err(err(ErrorCode::Refused, "Request cancelled"));
        }
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

    /// A connected Shell whose verified root is the seed `master_key_id`.
    fn holding(
        &self,
        master_key_id: &str,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(Box<dyn crate::apdu::Transport>, String, u64), SignerError> {
        let candidates = lock(&self.connected).clone();
        for serial in candidates {
            if cancelled() {
                return Err(err(ErrorCode::Refused, "Request cancelled"));
            }
            let Ok((mut t, epoch)) = self.open_session(&serial) else {
                continue;
            };
            let root = self.verified_root(&serial, epoch, &mut *t)?;
            if master_id(&root.key) == master_key_id {
                return Ok((t, serial, epoch));
            }
        }
        Err(err(
            ErrorCode::Unavailable,
            "No connected Shell has this wallet's seed. Insert its Keycard and retry.",
        ))
    }

    /// The seed's unlock key at `index`, confirmed on a Shell holding it.
    fn unlock_key_now(&self, seed: &str, index: u32, job: &str) -> Result<UnlockKey, SignerError> {
        let cancelled = || {
            lock(&self.keys)
                .status(job)
                .is_ok_and(|s| s.state == JobState::Cancelled)
        };
        let (mut transport, serial, epoch) = self.holding(seed, &cancelled)?;
        let key = commands::get_public(
            &mut *transport,
            &[HARDENED | PURPOSE, HARDENED | index],
            false,
        )
        .map_err(|e| self.connection_error(&serial, epoch, e, false))?;
        Ok(UnlockKey {
            key: Secret::new(hex::encode(key.key.serialize())),
        })
    }

    fn export(&self, serial: &str, req: &AddRequest) -> Result<Exported, SignerError> {
        let (mut t, epoch) = self.open_session(serial)?;
        let shell = |e| self.connection_error(serial, epoch, e, false);
        let t = &mut *t;
        let root = self.verified_root(serial, epoch, t)?;
        let root_id = master_id(&root.key);
        if req.master_key_id.as_ref().is_some_and(|id| id != &root_id) {
            return Err(err(
                ErrorCode::Invalid,
                "The Shell contains a different wallet. Open the selected wallet and retry.",
            ));
        }
        if req.verify_only {
            return Ok((Vec::new(), root_id, None));
        }
        let mut out = Vec::new();
        // A short fingerprint cannot prove that legacy accounts share this root. Re-export
        // each saved key and compare its full public key before associating it with the root.
        let legacy: Vec<_> = lock(&self.store)
            .list()
            .iter()
            .filter(|o| {
                o.serial == serial
                    && o.master_key_id.is_empty()
                    && o.account.fingerprint.as_deref()
                        == Some(hex::encode(root.fingerprint).as_str())
            })
            .cloned()
            .collect();
        for mut o in legacy {
            let Some(path) = o.account.path.as_deref() else {
                continue;
            };
            let path = parse_path(path)
                .ok_or_else(|| err(ErrorCode::Invalid, "Invalid saved account path"))?;
            let key = commands::get_public(t, &path, false).map_err(shell)?;
            if hex::encode(key.key.serialize()) == o.key {
                o.master_key_id = root_id.clone();
                out.push(o);
            }
        }
        for family in &req.families {
            // Its own name only: an unnamed account shows as its kind and address, not a stored default.
            let label = req.label.clone().filter(|l| !l.trim().is_empty());
            let offered = match family {
                Family::Evm => {
                    let mut path = accounts::EVM_PATH;
                    path[4] = req.account;
                    let e = commands::get_public(t, &path, false).map_err(shell)?;
                    let mut account = accounts::evm_account(&e, label);
                    account.path = Some(accounts::path_string(&path));
                    Offered {
                        account,
                        serial: serial.into(),
                        master_key_id: root_id.clone(),
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
                        master_key_id: root_id.clone(),
                        key: hex::encode(key.key.serialize()),
                    }
                }
            };
            if req
                .fingerprint
                .as_ref()
                .is_some_and(|fp| offered.account.fingerprint.as_ref() != Some(fp))
            {
                return Err(err(ErrorCode::Invalid, "The Shell contains a different wallet. Open the selected wallet on the Shell and try again."));
            }
            out.retain(|o| o.account.id != offered.account.id);
            out.push(offered);
        }
        // One more confirmation: the seed's unlock key, so adding never asks twice. A Shell that
        // won't export it still adds; its wallet then unlocks by a password.
        let unlock_key = commands::get_public(t, &[HARDENED | PURPOSE, HARDENED], false)
            .ok()
            .map(|k| k.key.serialize());
        Ok((out, root_id, unlock_key))
    }

    fn next_id(&self, prefix: &str) -> String {
        format!("{prefix}_{}", self.seq.fetch_add(1, Ordering::SeqCst) + 1)
    }
}

/// Same encoding as the Keycard applet's key UID (EC getW, SEC1 uncompressed).
fn master_id(key: &PublicKey) -> String {
    sha256::Hash::hash(&key.serialize_uncompressed()).to_string()
}

/// The module's state, shared with the jobs it runs.
#[derive(Clone)]
pub struct ShellSigner {
    s: Arc<Shared>,
}

impl ShellSigner {
    pub fn sign_offered(
        &mut self,
        request: SignRequest,
        mut offered: Offered,
    ) -> logos_signer_interface::Result<String> {
        if !(if offered.account.family == Family::Evm {
            request.account.eq_ignore_ascii_case(&offered.account.id)
        } else {
            request.account == offered.account.id
        }) {
            return Err(err(
                ErrorCode::Invalid,
                "Routed account does not match the request",
            ));
        }
        if let (Some(brought), Some(listed)) =
            (request.xpub.as_deref(), offered.account.xpub.as_deref())
        {
            let (family, chain) = (offered.account.family, offered.account.chain);
            if roster_key(family, chain, brought).ok() != roster_key(family, chain, listed).ok() {
                return Err(err(
                    ErrorCode::Invalid,
                    "the request's xpub is not this account's",
                ));
            }
        }
        let work = Work::of(&offered, &request.payload)?;
        self.s.refresh_connected();
        let connected = lock(&self.s.connected).clone();
        offered.serial = lock(&self.s.store)
            .available_serial(&offered, &connected)
            .or_else(|| {
                (!offered.master_key_id.is_empty())
                    .then(|| connected.first().cloned())
                    .flatten()
            })
            .ok_or_else(|| err(ErrorCode::Unavailable, "No USB Shell is connected"))?;
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
            let outcome = s.run(&offered, work, &id);
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

    pub fn routing_accounts(&self) -> serde_json::Value {
        lock(&self.s.store)
            .list()
            .iter()
            .filter(|o| !o.master_key_id.is_empty())
            .map(|o| {
                (
                    o.account.id.clone(),
                    serde_json::json!({
                        "account": o.account, "masterKeyId": o.master_key_id, "key": o.key
                    }),
                )
            })
            .collect::<serde_json::Map<String, serde_json::Value>>()
            .into()
    }
    pub fn routing_connections(&self) -> serde_json::Value {
        self.s.refresh_connected();
        serde_json::json!({"transport": "shell", "connected": !lock(&self.s.connected).is_empty()})
    }

    pub fn new(devices: Box<dyn Devices>, store: Store, events: Box<dyn Events>) -> Self {
        let s = Arc::new(Shared {
            devices,
            store: Mutex::new(store),
            jobs: Mutex::new(JobTable::new()),
            keys: Mutex::new(KeyJobs::new()),
            adds: Mutex::new(HashMap::new()),
            connected: Mutex::new(Vec::new()),
            sessions: Mutex::new(HashMap::new()),
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

    /// The seeds whose wallets wait for their key from the signer manager, each with the
    /// generation its document is sealed under.
    pub fn closed_seeds(&self) -> Vec<(String, Option<u32>)> {
        lock(&self.s.store).closed()
    }

    /// A seed's key arrived: its wallet and accounts are shown.
    pub fn open_seed(
        &self,
        seed: &str,
        box_key: &DataKey,
        current: &DataKey,
    ) -> std::io::Result<()> {
        let count = {
            let mut store = lock(&self.s.store);
            store.unlock(seed, box_key, current)?;
            store.list().len()
        };
        self.s.events.accounts_changed(count);
        Ok(())
    }

    /// Wallets were locked: nothing of theirs is shown or offered.
    pub fn lock_seeds(&self) {
        let count = {
            let mut store = lock(&self.s.store);
            store.lock();
            store.list().len()
        };
        self.s.events.accounts_changed(count);
    }

    pub fn devices(&self) -> Vec<Device> {
        let connected = lock(&self.s.connected).clone();
        connected
            .into_iter()
            .map(|serial| {
                let verified_master_key_id = lock(&self.s.sessions)
                    .get(&serial)
                    .and_then(|s| s.root.as_ref())
                    .map(|r| master_id(&r.key));
                if self.s.busy.load(Ordering::SeqCst) {
                    return Device {
                        serial,
                        firmware: None,
                        database: None,
                        busy: true,
                        verified_master_key_id,
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
                    verified_master_key_id,
                }
            })
            .collect()
    }

    /// Export the requested accounts from a connected Shell, each confirmed on it: a job id.
    pub fn add_accounts(&self, req: AddRequest) -> Result<String, SignerError> {
        if req.verify_only && (!req.families.is_empty() || req.identify) {
            return Err(err(
                ErrorCode::Invalid,
                "Verification cannot also add or identify accounts",
            ));
        }
        if req.families.is_empty() && !req.identify && !req.verify_only {
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
        if req.verify_only {
            if let Some(session) = lock(&self.s.sessions).get_mut(&serial) {
                session.root = None;
            }
            self.s
                .events
                .accounts_changed(lock(&self.s.store).list().len());
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
            let added = match outcome.and_then(|(offered, root, unlock_key)| {
                let accounts = offered
                    .iter()
                    .map(|o| Account {
                        seed: Some(root.clone()),
                        ..o.account.clone()
                    })
                    .collect();
                if !req.verify_only {
                    lock(&s.store)
                        .put_identified(offered, &root, &serial)
                        .map_err(|e| err(ErrorCode::Internal, e.to_string()))?;
                    let name = req
                        .label
                        .clone()
                        .filter(|n| !n.trim().is_empty())
                        .unwrap_or_else(|| "Keycard Shell".into());
                    s.events.seed_added(&root, unlock_key, &name);
                }
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
            s.busy.store(false, Ordering::SeqCst);
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

    /// Root identity is independent of transport. Unverified legacy groups remain separate.
    pub fn wallet_groups(&self) -> Vec<serde_json::Value> {
        let connected = lock(&self.s.connected).clone();
        let store = lock(&self.s.store);
        let mut groups = std::collections::BTreeMap::new();
        for (id, name) in store.wallet_names() {
            let mut serials = store.connections(id);
            if id.starts_with("shell:") {
                if let Some(serial) = id.split(':').nth(1) {
                    serials.push(serial.into());
                }
            }
            let connections: Vec<_> = serials.iter().map(|serial| serde_json::json!({
                "id": id, "serial": serial, "transport": "shell", "connected": connected.contains(serial)
            })).collect();
            groups.insert(
                id.clone(),
                serde_json::json!({
                    "id": id, "name": name, "aliases": store.aliases(id), "transport": "shell",
                    "serial": serials.iter().find(|s| connected.contains(s)).or(serials.first()),
                    "connections": connections, "identified": id.starts_with("seed:"),
                    "connected": serials.iter().any(|s| connected.contains(s)), "accounts": [],
                    "locked": false
                }),
            );
        }
        // A wallet sealed until the person unlocks it in the Signer app: its name and accounts
        // are in its sealed document, so only that it is there shows.
        for (seed, sealed) in store.closed() {
            if sealed.is_some() {
                let id = format!("seed:{seed}");
                groups.entry(id.clone()).or_insert_with(|| {
                    serde_json::json!({
                        "id": id, "name": "", "aliases": [], "transport": "shell", "serial": null,
                        "connections": [], "identified": true, "connected": false, "accounts": [],
                        "locked": true
                    })
                });
            }
        }
        for o in store.list() {
            let id = crate::store::wallet_id(o);
            if let Some(g) = groups.get_mut(&id) {
                let mut account = o.account.clone();
                account.available = store.available_serial(o, &connected).is_some();
                g["accounts"]
                    .as_array_mut()
                    .unwrap()
                    .push(serde_json::to_value(account).unwrap());
            }
        }
        groups.into_values().collect()
    }

    pub fn rename_account(&self, id: &str, name: &str) -> Result<(), SignerError> {
        lock(&self.s.store)
            .rename_account(id, name)
            .map_err(|e| err(ErrorCode::Invalid, e.to_string()))?;
        self.s
            .events
            .accounts_changed(lock(&self.s.store).list().len());
        Ok(())
    }

    pub fn rename_wallet(&self, id: &str, name: &str) -> Result<(), SignerError> {
        lock(&self.s.store)
            .rename_wallet(id, name)
            .map_err(|e| err(ErrorCode::Invalid, e.to_string()))?;
        self.s
            .events
            .accounts_changed(lock(&self.s.store).list().len());
        Ok(())
    }

    pub fn forget_wallet(&self, id: &str) -> Result<(), SignerError> {
        if self.s.busy.swap(true, Ordering::SeqCst) {
            return Err(err(
                ErrorCode::Busy,
                "The Shell is busy with another request",
            ));
        }
        let result = lock(&self.s.store)
            .forget_wallet(id)
            .map_err(|e| err(ErrorCode::Invalid, e.to_string()));
        self.s.busy.store(false, Ordering::SeqCst);
        self.s
            .events
            .accounts_changed(lock(&self.s.store).list().len());
        result
    }

    pub fn origins(&self) -> serde_json::Value {
        let store = lock(&self.s.store);
        let entries: serde_json::Map<String, serde_json::Value> = store
            .list()
            .iter()
            .map(|o| {
                let id = crate::store::wallet_id(o);
                (
                    o.account.id.clone(),
                    serde_json::json!({
                        "devices": [{"kind": "keycard_shell", "id": o.serial, "name": ""}],
                        "phrase": {"id": id, "name": store.wallet_name(&id)}, "kind": "derived"
                    }),
                )
            })
            .collect();
        entries.into()
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
            unlock_key: true,
        }
    }

    fn accounts(&mut self) -> logos_signer_interface::Result<Vec<Account>> {
        let connected = lock(&self.s.connected).clone();
        // What each connected Shell is known to hold: its verified root, or nothing known yet.
        let roots: Vec<(String, Option<String>)> = {
            let sessions = lock(&self.s.sessions);
            connected
                .iter()
                .map(|serial| {
                    (
                        serial.clone(),
                        sessions
                            .get(serial)
                            .and_then(|s| s.root.as_ref())
                            .map(|r| master_id(&r.key)),
                    )
                })
                .collect()
        };
        let store = lock(&self.s.store);
        Ok(store
            .list()
            .iter()
            .map(|o| {
                // A Shell verified to hold another seed doesn't make this one's accounts available.
                let unverified: Vec<String> = roots
                    .iter()
                    .filter(|(_, r)| r.is_none())
                    .map(|(s, _)| s.clone())
                    .collect();
                let verified = !o.master_key_id.is_empty()
                    && roots
                        .iter()
                        .any(|(_, r)| r.as_deref() == Some(o.master_key_id.as_str()));
                Account {
                    available: verified || store.available_serial(o, &unverified).is_some(),
                    seed: (!o.master_key_id.is_empty()).then(|| o.master_key_id.clone()),
                    ..o.account.clone()
                }
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
        self.sign_offered(request, offered)
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

    /// A seed's unlock key, from a connected Shell holding that seed once its person confirms
    /// the export. The job waits in `confirm_on_device`.
    fn unlock_key(&mut self, request: UnlockKeyRequest) -> logos_signer_interface::Result<String> {
        logos_signer_interface::unlock::unlock_key_path(request.index)?;
        let seed = request.seed.trim().to_string();
        if !lock(&self.s.store)
            .list()
            .iter()
            .any(|o| o.master_key_id == seed)
        {
            return Err(err(
                ErrorCode::WrongSeed,
                "no Shell account comes from this seed",
            ));
        }
        self.s.refresh_connected();
        if lock(&self.s.connected).is_empty() {
            return Err(err(ErrorCode::Unavailable, "No USB Shell is connected"));
        }
        if self.s.busy.swap(true, Ordering::SeqCst) {
            return Err(err(
                ErrorCode::Busy,
                "the Keycard Shell is busy with another request",
            ));
        }
        let job = lock(&self.s.keys).start(JobState::ConfirmOnDevice);
        let s = Arc::clone(&self.s);
        let id = job.clone();
        std::thread::spawn(move || {
            let outcome = s.unlock_key_now(&seed, request.index, &id);
            s.busy.store(false, Ordering::SeqCst);
            let _ = lock(&s.keys).finish(&id, outcome);
        });
        Ok(job)
    }

    fn unlock_key_status(&mut self, job: &str) -> logos_signer_interface::Result<JobStatus> {
        lock(&self.s.keys).status(job)
    }

    fn unlock_key_result(&mut self, job: &str) -> logos_signer_interface::Result<UnlockKey> {
        lock(&self.s.keys).take(job)
    }

    fn cancel_unlock_key(&mut self, job: &str) -> logos_signer_interface::Result<()> {
        lock(&self.s.keys).cancel(job)
    }
}
