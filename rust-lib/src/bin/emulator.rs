//! keycard-shell-emulator: a Keycard Shell in software on a local TCP port, for doctests. It prints
//! its address, then serves until killed. Point the module at it with KEYCARD_SHELL_EMULATOR.
//!
//!   keycard-shell-emulator [--listen 127.0.0.1:0] [--phrase "<words>"] [--refuse]

use keycard_shell_module::emulator::{Confirm, Emulator, PHRASE};

fn main() {
    let mut args = std::env::args().skip(1);
    let (mut listen, mut phrase, mut confirm) =
        ("127.0.0.1:0".to_string(), PHRASE.to_string(), Confirm::Auto);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--listen" => listen = args.next().expect("--listen <host:port>"),
            "--phrase" => phrase = args.next().expect("--phrase <words>"),
            "--refuse" => confirm = Confirm::Refuse,
            other => panic!("unknown argument {other}"),
        }
    }
    let emulator = Emulator::new(&phrase, confirm);
    let addr = emulator.listen_on(&listen).expect("listen");
    println!("{addr}");
    loop {
        std::thread::park();
    }
}
