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

### Unified Keycard app

Use `keycard_ui` for USB and reader wallets; the standalone Shell UI is superseded.
`wallet_groups`, `rename_wallet(id, name)` and `forget_wallet(id)` manage local USB wallets.
The group key is `seed:<SHA256(SEC1-uncompressed-master-public-key)>`, matching the reader
module's Keycard key UID. USB serials are connection metadata, independent of wallet identity.
Each seed's wallet (its accounts, name, aliases and Shell serials) is kept in
`accounts.sealed.json`, sealed under the module's key for that seed from the signer manager
(`data_key({ seed: <master key id>, scope: "accounts" })`), and shown only while it is unlocked.
Legacy serial/fingerprint groups, which name no seed, are kept in memory only and stay separate
until `add_accounts` with `identify: true` exports the master public key and verifies each
saved account key. This migration keeps account IDs/labels and wallet names; merged names
are retained in `aliases`. The metadata is committed atomically after all confirmations.
`masterKeyId` optionally constrains an export to a previously selected root. An empty
`families` list is accepted only with `identify: true`. No secret or chain code is stored
for identity. A new identification/export can require several confirmations on the device.
Names and empty identified wallets survive account removal. Signing may use any currently
connected Shell; the signer manager rejects signatures that do not match the selected account.

`add_accounts.account` now selects EVM index `i` at `m/44'/60'/0'/0/i`; Bitcoin semantics
are unchanged. Optional `fingerprint` constrains an export to the chosen wallet before any
accounts are saved. `signer_accounts` supplies public origin metadata to the signer manager.
All USB authorizations still occur on the Shell. QR signing is outside this integration.

Account labels can be changed locally with `rename_account(id, name)`. Names are trimmed, limited to 80 characters, and an empty name clears the label. Keys and derivation paths are unchanged; updated labels are announced to account consumers. In Keycard UI, use **Manage → Rename** beside an account.

### Signing across connections

The signer manager shares saved public Keycard account offers between the reader and USB
Shell providers for each request. It does not copy account files: labels, wallet names and
removal continue to belong to the original saved offer. A matching, paired reader takes
priority over a USB Shell. The reader checks the seed before requesting the PIN and checks
the full master public key again after unlocking.

USB presence does not identify the card inside a Shell. On first use of each USB connection,
the user confirms the master public key. The public root is cached only in memory for that
attachment; later signatures and account exports reuse it. Removal, a changed attachment,
a link failure or module restart clears verification. On macOS, the HID path contains the
IORegistry service entry ID, detecting even a reconnect between polls; other backends also
invalidate on an observed removal or path change. Opening uses the enumerated attachment path.
The UI distinguishes an unverified connection, the verified wallet and a different wallet.
A confirmed mismatching root can advance to another connected Shell; refusal or cancellation
ends the request. Every returned signature is still checked by the signer manager against
the selected account and request before release, including if the seed changes while connected.
Active jobs remain pinned to the provider that started them, even after hotplug.

Only `signer_manager_module` may supply the optional `keycardAccount` public routing metadata
to `sign`. Legacy Shell accounts must first use “Identify wallet…” to establish their full
master key identity. No PIN or pairing data is shared between the providers.

Use **Manage → Verify wallet…** to choose a connected Shell and request a fresh master-key
confirmation even when the connection is already verified. The action clears the prior cache
first; refusal leaves it unverified, and a different root is reported as a wallet mismatch.
The module accepts `add_accounts` with `verifyOnly: true`, empty `families`, and an optional
`masterKeyId` constraint. It reuses the asynchronous `add_status` flow without importing,
renaming or regrouping any saved accounts or wallets.
