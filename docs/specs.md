# keycard_shell_module

The Keycard Shell behind [`logos.signer/1`](https://github.com/logos-co/logos-signer-interface),
over USB. The Shell is Status's hardware wallet: it holds a Keycard, shows every request on its own
screen, and signs only once its person confirms there. This module lists the accounts the person
offered from the Shell, and has each request the signer manager hands it signed on the Shell.

**It holds no secret.** The keys stay on the card inside the Shell. The module keeps the offered
accounts' public material, the account key's public key, and the serial of the Shell each came
from. It never sees a PIN: the person enters it on the Shell.

## The link

The Shell is a USB HID device, vendor `0x1209`, product `0x21f7`, following firmware v1.4.0's
`docs/USB.md`:

- **Frames.** An APDU travels in 64-byte frames: `channel(2) tag(1) sequence(2)`, with the APDU's
  length(2) in the first. The channel is `0x0101`, and the Shell repeats it in its answer.
- **APDUs.** The class is `0xe0`. A payload longer than 255 bytes is chained: P1 is 0 for the first
  chunk and 1 after it. Each intermediate chunk is acknowledged with `0x9000`. An answer longer than
  one response says `0x61XX`, and the module asks GET RESPONSE until it has all of it.
- **Its serial number** is its UID's first 15 bytes in hex. The module tells Shells apart by it
  without opening them.

| Command | INS | What it sends | What it answers |
|---|---|---|---|
| GET DEVICE INFO | `0x06` | nothing | firmware, database date, UID, the Shell's own key; no confirmation |
| GET PUBLIC | `0x02` | a BIP32 path; P2 1 for the chain code | master fingerprint, the key (65 bytes), the chain code; **confirmed on the Shell** |
| SIGN ETH TX | `0x04` | path, then the unsigned transaction, in chunks of at most 150 | `v ‖ r ‖ s` |
| SIGN ETH MSG | `0x08` | path, length, then the message | `v ‖ r ‖ s` |
| SIGN EIP712 | `0x0c` | path, length, then the document's JSON | `v ‖ r ‖ s` |
| SIGN PSBT | `0x0e` | length, then the PSBT, version 0 | the PSBT with the Shell's signatures added |

A legacy transaction's chunk that reaches its EIP-155 fields carries them whole, as the firmware's
own client sends them.

## Accounts

The Shell's app asks for the accounts the person chooses (`add_accounts`). The person confirms each
key on the Shell before it is exported:

- **EVM**: `m/44'/60'/0'/0/0`. Its id is its address, in lowercase.
- **Native segwit** and **taproot**: `m/84'` or `m/86'`, then `0'` for Bitcoin or `1'` for the test
  networks, then the account. The account key and its parent key are both exported. The parent is
  needed for the fingerprint the xpub carries, since GET PUBLIC doesn't give it. That makes two
  confirmations per Bitcoin account. The id is `shell-<fingerprint>-<purpose>-<coin>-<account>`,
  such as `shell-73c5da0a-84-1-0`.

They are kept in `accounts.json` in the module's own directory. An account is `available` while the
Shell it came from is connected. The module looks for Shells every second and a half, announces a
change with `signer_changed` and `signer_accounts_changed`, and keeps every account listed either way.
`remove_account` stops offering one. Nothing on the Shell changes, and it can be offered again.

A Shell holds whatever card is inserted, so a different card behind the same serial signs with other
keys. The manager then refuses its answer, because the signature doesn't recover to the account.

## Signing

`signer_info` says the Shell takes whole requests, never a bare hash: `evm_transaction`,
`evm_message`, `evm_typed_data` and `btc_psbt`. It also says it shows them and collects nothing.

- **EVM.** The module sends the request with the account's path. It reads the recovery id from `v`,
  the way the firmware chose it:
  - the parity, for EIP-2930 and EIP-1559 transactions;
  - `chainId * 2 + 35` kept to its low byte, for a legacy EIP-155 transaction;
  - 27, for messages and typed data.

  A high S is lowered, with the recovery id flipped to match.
- **Bitcoin.** Every input must carry an origin for this wallet's fingerprint, at a path two
  unhardened steps below the account. Otherwise the request is refused as `invalid` before the Shell
  sees it. From the PSBT the Shell returns, the module takes each input's signature by that key: a
  partial signature for native segwit, or the key-path signature for taproot. It names the tweaked
  output key for taproot.
- **Taproot's internal key.** Firmware 1.4.0 signs a taproot input only once the PSBT names its
  internal key, which it tweaks by. The module names it where a wallet left it out: for this
  account's key-path spend, it is the key at the input's own path. An input that names another key,
  or a script tree, is refused as `invalid` before the Shell sees it.

The answer is signatures only. The manager checks each one against the account over its own digest,
and builds the signed transaction or PSBT itself.

One request at a time: while the Shell shows one, another is refused as `busy`. `cancel_sign` drops
the job's answer, but the Shell keeps showing the request until its person answers it, and the next
request waits until it has.

| The Shell answers | The job |
|---|---|
| `0x6982`, declined on the Shell | `refused` |
| `0x6a80` to a PSBT | `refused`: the firmware answers this both when its person declines and when it can't sign, and its screen says which |
| `0x6a80` to anything else | `invalid` |
| `0x6985`, such as no card or a locked one; or no link | `unavailable` |
| the Shell leaves USB mid-request | `unavailable`, saying to turn it on and unlock it: it turns itself off after three minutes without a press, by default |
| `0x6501` | `unsupported` |

Taproot needs a card whose applet signs BIP340, applet 4.0 or later.

## Methods

Every reply is `{ "ok": true, … }` or `{ "ok": false, "error": …, "code"? }`.

The signer interface's methods, as `docs/interface.md` there specifies them:

- `signer_info`: the interface, `keycard_shell`, the families and request kinds above, `showsRequest`, and `collects: nothing`.
- `signer_accounts`: the offered accounts, each `available` while its Shell is connected.
- `sign`: a job, in `confirm_on_device` at once.
- `sign_status`, `sign_result`, `cancel_sign`.

For the Shell's app:

- `devices`: the Shells connected now, `{ ok, devices: [{ serial, firmware?, database?, busy }] }`.
- `add_accounts`: takes `{ families, chain?, account?, label?, serial? }` and returns `{ ok, job }`. `chain` is `main` or `test`, the default `test`. `account` defaults to 0.
- `add_status`: an export's progress, `{ ok, job, state, accounts?, error? }`. The state is `confirm_on_device`, `done` or `failed`.
- `remove_account`: stop offering an account, `{ ok, removed }`.

Who may call which comes from module identity in the new core.

## Events

`signer_accounts_changed` (count) when the offered accounts or their availability change.
`signer_changed` (state) with `connected` or `disconnected`. `sign_progress` (job, state) when a job
settles.

## The emulator

`keycard-shell-emulator` is a Shell in software, behind the `emulator` feature, never in the module.
It answers the commands above over the same frames on a local TCP port, from a BIP39 phrase (by
default the "abandon … about" phrase of BIP84's and BIP86's test vectors). It confirms every request,
declines every one, or waits for a press in tests. `KEYCARD_SHELL_EMULATOR=host:port` points the
module at it instead of USB.

It is written from the firmware's source, not from the device, so it proves the module agrees with
that reading. A real Shell is the proof that both agree with the device: see below. A real Shell on
1.4.0 showed that this reading had missed the firmware's need for a taproot input's internal key; the
emulator now refuses such an input as the firmware does.

## Platforms

- **macOS:** IOKit, through hidapi.
- **Linux:** hidraw, through hidapi's pure-Rust backend, so no libudev. A user needs access to the
  device node, for instance with a udev rule:
  `SUBSYSTEM=="hidraw", ATTRS{idVendor}=="1209", ATTRS{idProduct}=="21f7", TAG+="uaccess"`.
- **Windows:** hidapi's native backend, over `hid.dll`, which `nix-bundle-lgx`'s system-DLL list
  must allow before the portable package ships.

## By hand, with a Shell

1. Plug in a Shell with a card set up, unlock it, and start the module without `KEYCARD_SHELL_EMULATOR`.
   Taproot needs a 4.0 card. A card whose identity Keycard didn't sign first shows the Shell's own
   "not genuine" warning, which the person accepts on the Shell.
2. `devices` lists it with its firmware.
3. `add_accounts` with every family. Confirm each export on the Shell, twice for each Bitcoin
   account. The EVM address and the first receive address should match what the Shell shows for
   that account.
4. The manager consults `keycard_shell_module` by default. Send a regtest PSBT and an Anvil EVM
   transaction through it. Each shows on the Shell, and once confirmed there, the manager settles it
   `approved`.
5. Decline one on the Shell: the request settles `rejected`.

## Build and test

```sh
cd rust-lib && cargo test --no-default-features --features emulator   # against the emulator
nix build                                                             # the module
nix build .#emulator                                                  # the emulator
```
