//! Logos module glue for `keycard_shell_module`. The builder derives the `.lidl` from the
//! `KeycardShellModule` trait and injects the generated scaffold at the `include!` point.
//!
//! Every reply is a JSON string: `{ "ok": true, ... }` or `{ "ok": false, "error": "...", "code"? }`.

use std::time::Duration;

use logos_signer_interface::json as signer_json;
use logos_signer_interface::JobState;
use serde_json::json;

use crate::link;
use crate::signer::{AddRequest, Events, ShellSigner};
use crate::store::Store;
use logos_signer_interface::wallets::{read_data_key, DataKey, DataKeyRequest};

pub trait KeycardShellModule: Send + Sync + 'static {
    // ── logos.signer/1 ──────────────────────────────────────────────────
    fn signer_info(&self) -> String;
    fn signer_accounts(&self) -> String;
    fn sign(&self, request_json: String) -> String;
    fn sign_status(&self, job: String) -> String;
    fn sign_result(&self, job: String) -> String;
    fn cancel_sign(&self, job: String) -> String;
    /// A seed's unlock key, for the signer manager alone: `{ seed, index }` → `{ ok, job }`; the
    /// job waits in `confirm_on_device` until the person confirms on a Shell holding the seed.
    fn unlock_key(&self, request_json: String) -> String;
    fn unlock_key_status(&self, job: String) -> String;
    /// `{ ok, job, key }`, once: the job forgets it.
    fn unlock_key_result(&self, job: String) -> String;
    fn cancel_unlock_key(&self, job: String) -> String;

    // ── the Shell's app ─────────────────────────────────────────────────
    /// The Shells connected now: `{ ok, devices: [{ serial, firmware?, database?, busy }] }`.
    fn devices(&self) -> String;
    fn wallet_groups(&self) -> String;
    fn rename_wallet(&self, id: String, name: String) -> String;
    fn forget_wallet(&self, id: String) -> String;
    /// Export accounts from a connected Shell, each confirmed on it:
    /// `{ families | entries, chain?, account?, label?, serial?, preview?, fromPreview? }` → `{ ok, job }`.
    fn add_accounts(&self, params_json: String) -> String;
    /// An export's progress: `{ ok, job, state, accounts?, error? }`.
    fn add_status(&self, job: String) -> String;
    /// Stop offering an account: `{ ok, removed }`. Nothing on the Shell changes.
    fn remove_account(&self, id: String) -> String;
    /// Rename a locally offered account; an empty name restores the default.
    fn rename_account(&self, id: String, name: String) -> String;

    fn on_context_ready(&self, _ctx: &RustModuleContext) {}
}

pub trait KeycardShellModuleEvents {
    fn signer_accounts_changed(&self, count: i64);
    fn signer_changed(&self, state: String);
    fn sign_progress(&self, job: String, state: String);
}

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/generated/provider_gen.rs"
));

/// The module behind `logos.wallets/1`: the signer manager, bound at runtime, since it depends on
/// this module and this module can't depend on it.
const WALLETS: &str = "signer_manager_module";

fn from_manager() -> bool {
    matches!(logos_rust_sdk::current_caller(), logos_rust_sdk::LogosCaller::Module { name, .. } if name == WALLETS)
}

struct Emit;

impl Events for Emit {
    /// The seed goes to the signer manager while its unlock key is at hand, so the person never
    /// unlocks it a second time. Asked without waiting: without a manager the add stands.
    fn seed_added(&self, seed: &str, unlock_key: Option<[u8; 33]>, name: &str) {
        let body = json!({ "seed": seed, "kind": "keycard_shell", "unlockKey": unlock_key.map(hex::encode), "name": name })
            .to_string();
        wallets::WalletsClient::bind(WALLETS).enroll_seed_async(&body, |_| {});
    }
    fn sign_progress(&self, job: &str, state: JobState) {
        emit_sign_progress(job, state.as_str());
    }
    fn accounts_changed(&self, count: usize) {
        emit_signer_accounts_changed(count as i64);
    }
    fn device_changed(&self, connected: bool) {
        emit_signer_changed(if connected {
            "connected"
        } else {
            "disconnected"
        });
    }
}

/// A seed's wallet opens with this module's key for it, which the signer manager gives once the
/// person unlocks it in the Signer app, and closes when it locks. Asked from threads of their own,
/// never while answering the manager, which would wait on itself.
fn watch_wallets(shell: ShellSigner) {
    let mut client = wallets::WalletsClient::bind(WALLETS);
    let changed = client.on_wallets_changed();
    let locked = client.on_wallets_locked();
    let s = shell.clone();
    std::thread::spawn(move || {
        open_wallets(&s);
        if let Ok(sub) = changed {
            for _ in sub {
                open_wallets(&s);
            }
        }
    });
    if let Ok(sub) = locked {
        std::thread::spawn(move || {
            for _ in sub {
                shell.lock_seeds();
                // Only some may have locked.
                open_wallets(&shell);
            }
        });
    }
}

/// Every closed seed's key; a locked one answers `locked` and stays closed.
fn open_wallets(shell: &ShellSigner) {
    for (seed, sealed_under) in shell.closed_seeds() {
        let Some(current) = data_key(&seed, None) else {
            continue;
        };
        let box_key = match sealed_under {
            Some(g) if g != current.generation => match data_key(&seed, Some(g)) {
                Some(k) => k,
                None => continue,
            },
            _ => current.clone(),
        };
        if let Err(e) = shell.open_seed(&seed, &box_key, &current) {
            eprintln!("keycard_shell_module: a wallet didn't open: {e}");
        }
    }
}

/// The key for a seed's document, named by its master key id, as the manager knows it.
fn data_key(seed: &str, generation: Option<u32>) -> Option<DataKey> {
    let body = serde_json::to_string(&DataKeyRequest {
        seed: seed.to_string(),
        scope: "accounts".into(),
        generation,
    })
    .ok()?;
    let (tx, rx) = std::sync::mpsc::channel();
    wallets::WalletsClient::bind(WALLETS).data_key_async_with_timeout(
        &body,
        Duration::from_secs(10),
        move |r| {
            let _ = tx.send(r);
        },
    );
    read_data_key(&rx.recv().ok()?.ok()?).ok()
}

struct KeycardShellModuleImpl {
    shell: ShellSigner,
}

impl Default for KeycardShellModuleImpl {
    fn default() -> Self {
        let shell = ShellSigner::new(link::from_env(), Store::new(), Box::new(Emit));
        shell.watch(Duration::from_millis(1500));
        KeycardShellModuleImpl { shell }
    }
}

fn err(e: impl std::fmt::Display) -> String {
    json!({ "ok": false, "error": e.to_string() }).to_string()
}

fn signer_err(e: logos_signer_interface::SignerError) -> String {
    json!({ "ok": false, "code": e.code, "error": e.message }).to_string()
}

impl KeycardShellModule for KeycardShellModuleImpl {
    fn signer_info(&self) -> String {
        signer_json::signer_info(&self.shell)
    }

    fn signer_accounts(&self) -> String {
        let mut reply: serde_json::Value =
            serde_json::from_str(&signer_json::signer_accounts(&mut self.shell.clone()))
                .unwrap_or_default();
        let origins = self.shell.origins();
        if let Some(rows) = reply["accounts"].as_array_mut() {
            for row in rows {
                if let Some(origin) = row["id"].as_str().and_then(|id| origins.get(id)) {
                    row["origin"] = origin.clone();
                }
            }
        }
        let public = self.shell.routing_accounts();
        if let Some(rows) = reply["accounts"].as_array_mut() {
            for row in rows {
                if let Some(offer) = row["id"].as_str().and_then(|id| public.get(id)) {
                    row["keycardAccount"] = offer.clone();
                }
            }
        }
        reply["keycardRouting"] = self.shell.routing_connections();
        reply.to_string()
    }

    fn sign(&self, request_json: String) -> String {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Routed {
            account: String,
            #[serde(flatten)]
            payload: logos_signer_interface::Payload,
            secret: Option<logos_signer_interface::Secret>,
            #[serde(default)]
            xpub: Option<String>,
            keycard_account: Option<serde_json::Value>,
        }
        let request: Routed = match serde_json::from_str(&request_json) {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        drop(request_json);
        let req = logos_signer_interface::SignRequest {
            account: request.account,
            payload: request.payload,
            secret: request.secret,
            xpub: request.xpub,
        };
        use logos_signer_interface::Signer;
        let result = if let Some(v) = request.keycard_account {
            if !matches!(logos_rust_sdk::current_caller(), logos_rust_sdk::LogosCaller::Module { name, .. } if name == "signer_manager_module")
            {
                return err("Only the signer manager can route public Keycard accounts");
            }
            let account: logos_signer_interface::Account =
                match serde_json::from_value(v["account"].clone()) {
                    Ok(a) => a,
                    Err(e) => return err(e),
                };
            let root = v["masterKeyId"].as_str().unwrap_or_default();
            let key = v["key"].as_str().unwrap_or_default();
            if root.len() != 64
                || hex::decode(root).is_err()
                || hex::decode(key)
                    .ok()
                    .and_then(|k| bitcoin::secp256k1::PublicKey::from_slice(&k).ok())
                    .is_none()
            {
                return err("Invalid public Keycard routing metadata");
            }
            self.shell.clone().sign_offered(
                req,
                crate::store::Offered {
                    account,
                    master_key_id: root.into(),
                    key: key.into(),
                    serial: String::new(),
                },
            )
        } else {
            self.shell.clone().sign(req)
        };
        match result {
            Ok(job) => json!({"ok": true, "job": job}).to_string(),
            Err(e) => signer_err(e),
        }
    }

    fn sign_status(&self, job: String) -> String {
        signer_json::sign_status(&mut self.shell.clone(), &job)
    }

    fn sign_result(&self, job: String) -> String {
        signer_json::sign_result(&mut self.shell.clone(), &job)
    }

    fn cancel_sign(&self, job: String) -> String {
        signer_json::cancel_sign(&mut self.shell.clone(), &job)
    }

    fn unlock_key(&self, request_json: String) -> String {
        if !from_manager() {
            return err("not authorized");
        }
        signer_json::unlock_key(&mut self.shell.clone(), &request_json)
    }

    fn unlock_key_status(&self, job: String) -> String {
        if !from_manager() {
            return err("not authorized");
        }
        signer_json::unlock_key_status(&mut self.shell.clone(), &job)
    }

    fn unlock_key_result(&self, job: String) -> String {
        if !from_manager() {
            return err("not authorized");
        }
        signer_json::unlock_key_result(&mut self.shell.clone(), &job)
    }

    fn cancel_unlock_key(&self, job: String) -> String {
        if !from_manager() {
            return err("not authorized");
        }
        signer_json::cancel_unlock_key(&mut self.shell.clone(), &job)
    }

    fn devices(&self) -> String {
        json!({ "ok": true, "devices": self.shell.devices() }).to_string()
    }

    fn wallet_groups(&self) -> String {
        json!({"ok": true, "groups": self.shell.wallet_groups()}).to_string()
    }
    fn rename_account(&self, id: String, name: String) -> String {
        match self.shell.rename_account(&id, &name) {
            Ok(()) => json!({"ok":true}).to_string(),
            Err(e) => signer_err(e),
        }
    }

    fn rename_wallet(&self, id: String, name: String) -> String {
        match self.shell.rename_wallet(&id, &name) {
            Ok(()) => json!({"ok":true}).to_string(),
            Err(e) => signer_err(e),
        }
    }
    fn forget_wallet(&self, id: String) -> String {
        match self.shell.forget_wallet(&id) {
            Ok(()) => json!({"ok":true}).to_string(),
            Err(e) => signer_err(e),
        }
    }

    fn add_accounts(&self, params_json: String) -> String {
        let req: AddRequest = match serde_json::from_str(&params_json) {
            Ok(r) => r,
            Err(e) => return err(format!("params: {e}")),
        };
        match self.shell.add_accounts(req) {
            Ok(job) => json!({ "ok": true, "job": job }).to_string(),
            Err(e) => signer_err(e),
        }
    }

    fn add_status(&self, job: String) -> String {
        match self.shell.add_status(&job) {
            Some(added) => {
                let mut v = json!({ "ok": true, "job": job });
                if let (Some(out), Ok(serde_json::Value::Object(fields))) =
                    (v.as_object_mut(), serde_json::to_value(added))
                {
                    out.extend(fields);
                }
                v.to_string()
            }
            None => err(format!("no export {job}")),
        }
    }

    fn remove_account(&self, id: String) -> String {
        match self.shell.remove_account(&id) {
            Ok(removed) => json!({ "ok": true, "removed": removed }).to_string(),
            Err(e) => signer_err(e),
        }
    }

    fn on_context_ready(&self, ctx: &RustModuleContext) {
        // The accounts offered live in the module's own directory.
        match Store::open(&ctx.instance_persistence_path) {
            Ok(store) => {
                self.shell.set_store(store);
                watch_wallets(self.shell.clone());
            }
            Err(e) => eprintln!(
                "keycard_shell_module: {}: {e}",
                ctx.instance_persistence_path
            ),
        }
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<KeycardShellModuleImpl>();
}
