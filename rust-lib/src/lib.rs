//! keycard_shell_module: the Keycard Shell behind `logos.signer/1`, over USB. It lists the accounts
//! the person offered from the Shell and has each request signed on the Shell's own screen. It
//! holds no secret: the keys stay on the card inside the Shell.
//!
//! The core is plain Rust, tested with `cargo test --no-default-features --features emulator`
//! against [`emulator`], a Shell in software. The Logos glue is behind `logos_module`.

pub mod accounts;
pub mod answers;
pub mod apdu;
pub mod commands;
pub mod hid;
pub mod link;
pub mod rlp;
pub mod signer;
pub mod store;

#[cfg(feature = "emulator")]
pub mod emulator;

#[cfg(feature = "logos_module")]
mod glue;
