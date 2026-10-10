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
    /// Export accounts from a connected Shell, each confirmed on it:
    /// `{ families, chain?, account?, label?, serial? }` → `{ ok, job }`.
    fn add_accounts(&self, params_json: String) -> String;
    /// An export's progress: `{ ok, job, state, accounts?, error? }`.
    fn add_status(&self, job: String) -> String;
    /// Stop offering an account: `{ ok, removed }`. Nothing on the Shell changes.
    fn remove_account(&self, id: String) -> String;

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
        signer_json::signer_accounts(&mut self.shell.clone())
    }

    fn sign(&self, request_json: String) -> String {
        signer_json::sign(&mut self.shell.clone(), &request_json)
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
