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

pub trait KeycardShellModule: Send + Sync + 'static {
    // ── logos.signer/1 ──────────────────────────────────────────────────
    fn signer_info(&self) -> String;
    fn signer_accounts(&self) -> String;
    fn sign(&self, request_json: String) -> String;
    fn sign_status(&self, job: String) -> String;
    fn sign_result(&self, job: String) -> String;
    fn cancel_sign(&self, job: String) -> String;

    // ── the Shell's app ─────────────────────────────────────────────────
    /// The Shells connected now: `{ ok, devices: [{ serial, firmware?, database?, busy }] }`.
    fn devices(&self) -> String;
    fn wallet_groups(&self) -> String;
    fn rename_wallet(&self, id: String, name: String) -> String;
    fn forget_wallet(&self, id: String) -> String;
    /// Export accounts from a connected Shell, each confirmed on it:
    /// `{ families, chain?, account?, label?, serial? }` → `{ ok, job }`.
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

struct Emit;

impl Events for Emit {
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
        let mut reply: serde_json::Value = serde_json::from_str(&signer_json::signer_accounts(&mut self.shell.clone())).unwrap_or_default();
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
            keycard_account: Option<serde_json::Value>,
        }
        let request: Routed = match serde_json::from_str(&request_json) {
            Ok(r) => r, Err(e) => return err(e),
        };
        drop(request_json);
        let req = logos_signer_interface::SignRequest { account: request.account, payload: request.payload, secret: request.secret };
        use logos_signer_interface::Signer;
        let result = if let Some(v) = request.keycard_account {
            if !matches!(logos_rust_sdk::current_caller(), logos_rust_sdk::LogosCaller::Module { name, .. } if name == "signer_manager_module") {
                return err("Only the signer manager can route public Keycard accounts");
            }
            let account: logos_signer_interface::Account = match serde_json::from_value(v["account"].clone()) {
                Ok(a) => a, Err(e) => return err(e),
            };
            let root = v["masterKeyId"].as_str().unwrap_or_default();
            let key = v["key"].as_str().unwrap_or_default();
            if root.len() != 64 || hex::decode(root).is_err() || hex::decode(key).ok()
                .and_then(|k| bitcoin::secp256k1::PublicKey::from_slice(&k).ok()).is_none() {
                return err("Invalid public Keycard routing metadata");
            }
            self.shell.clone().sign_offered(req, crate::store::Offered {
                account, master_key_id: root.into(), key: key.into(), serial: String::new()
            })
        } else { self.shell.clone().sign(req) };
        match result { Ok(job) => json!({"ok": true, "job": job}).to_string(), Err(e) => signer_err(e) }
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

    fn devices(&self) -> String {
        json!({ "ok": true, "devices": self.shell.devices() }).to_string()
    }

    fn wallet_groups(&self) -> String {
        json!({"ok": true, "groups": self.shell.wallet_groups()}).to_string()
    }
    fn rename_account(&self, id: String, name: String) -> String {
        match self.shell.rename_account(&id, &name) { Ok(()) => json!({"ok":true}).to_string(), Err(e) => signer_err(e) }
    }

    fn rename_wallet(&self, id: String, name: String) -> String {
        match self.shell.rename_wallet(&id, &name) { Ok(()) => json!({"ok":true}).to_string(), Err(e) => signer_err(e) }
    }
    fn forget_wallet(&self, id: String) -> String {
        match self.shell.forget_wallet(&id) { Ok(()) => json!({"ok":true}).to_string(), Err(e) => signer_err(e) }
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
            Ok(store) => self.shell.set_store(store),
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
