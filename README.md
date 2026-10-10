# logos-keycard-shell-module

`keycard_shell_module` is the [Keycard Shell](https://github.com/keycard-tech/keycard-shell) behind
[`logos.signer/1`](https://github.com/logos-co/logos-signer-interface), over USB. The person offers
accounts from the Shell, each key confirmed on it. The signer manager then lists them beside the
keystore's and hands the Shell each request whole: an EVM transaction, a message, typed data or a
PSBT. The Shell shows the request on its own screen and signs once its person confirms there. The
module holds no secret.

- The signer interface: `signer_info`, `signer_accounts`, `sign`, `sign_status`, `sign_result`,
  `cancel_sign`.
- For the Shell's app: `devices`, `add_accounts`, `add_status`, `remove_account`.

See [`docs/specs.md`](docs/specs.md) for the reference, and
[`doctests/keycard-shell-runtime.test.yaml`](doctests/keycard-shell-runtime.test.yaml) for the
round trip through `logoscore` and the signer manager.

```sh
cd rust-lib && cargo test --no-default-features --features emulator
nix build                 # the module
nix build .#emulator      # keycard-shell-emulator, a Shell in software for tests
```

The tests and the doctest run against `keycard-shell-emulator`, written from the Shell firmware
v1.4.0's source. Set `KEYCARD_SHELL_EMULATOR=host:port` to point the module at it. A real Shell is
tested by hand, as the reference describes.

On Linux, give your user the Shell's HID device, for instance:

```
SUBSYSTEM=="hidraw", ATTRS{idVendor}=="1209", ATTRS{idProduct}=="21f7", TAG+="uaccess"
```

Licensed under MIT or Apache-2.0.
