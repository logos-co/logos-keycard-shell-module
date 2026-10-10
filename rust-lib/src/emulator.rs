//! A Keycard Shell in software, for tests: it answers firmware v1.4.0's USB commands from a BIP39
//! phrase, over the same HID frames on TCP, and waits for its button the way the device does.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

use alloy::dyn_abi::TypedData;
use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::key::{Keypair, TapTweak};
use bitcoin::secp256k1::{All, Message, PublicKey, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::{NetworkKind, Psbt};
use sha3::{Digest, Keccak256};

use crate::apdu;
use crate::hid::{self, Reassembly, FRAME};
use crate::rlp;

/// The phrase BIP84's and BIP86's test vectors use.
pub const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// How its button is pressed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Confirm {
    /// Every request is confirmed at once.
    Auto,
    /// Every request is declined at once.
    Refuse,
    /// Each request waits for [`Emulator::press`].
    Manual,
}

struct State {
    master: Xpriv,
    uid: [u8; 16],
    device_key: PublicKey,
    confirm: Confirm,
    /// What the screen asks the person, while a request waits.
    asking: Option<String>,
    decision: Option<bool>,
    /// A chained command being received: its INS, the path, the bytes so far and how many are due.
    ins: u8,
    path: Vec<u32>,
    data: Vec<u8>,
    due: usize,
    /// An answer longer than one response, for GET RESPONSE.
    out: VecDeque<u8>,
}

#[derive(Clone)]
pub struct Emulator {
    inner: Arc<(Mutex<State>, Condvar)>,
    secp: Arc<Secp256k1<All>>,
}

/// One response: data and a status word.
type Answer = Vec<u8>;

fn sw(code: u16) -> Answer {
    code.to_be_bytes().to_vec()
}

fn ok(mut data: Vec<u8>) -> Answer {
    data.extend_from_slice(&[0x90, 0x00]);
    data
}

impl Emulator {
    pub fn new(phrase: &str, confirm: Confirm) -> Self {
        let mut seed = [0u8; 64];
        pbkdf2::pbkdf2_hmac::<sha2::Sha512>(phrase.as_bytes(), b"mnemonic", 2048, &mut seed);
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(NetworkKind::Main, &seed).expect("a master key");
        let digest = sha256::Hash::hash(&seed).to_byte_array();
        let device = SecretKey::from_slice(&sha256::Hash::hash(&digest).to_byte_array())
            .expect("a device key");
        let state = State {
            master,
            uid: digest[..16].try_into().expect("16 bytes"),
            device_key: device.public_key(&secp),
            confirm,
            asking: None,
            decision: None,
            ins: 0,
            path: Vec::new(),
            data: Vec::new(),
            due: 0,
            out: VecDeque::new(),
        };
        Emulator {
            inner: Arc::new((Mutex::new(state), Condvar::new())),
            secp: Arc::new(secp),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.inner.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Serve the device on a free local port: its `host:port`.
    pub fn listen(&self) -> std::io::Result<String> {
        self.listen_on("127.0.0.1:0")
    }

    pub fn listen_on(&self, addr: &str) -> std::io::Result<String> {
        let listener = TcpListener::bind(addr)?;
        let bound = listener.local_addr()?.to_string();
        let me = self.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let me = me.clone();
                std::thread::spawn(move || me.session(stream));
            }
        });
        Ok(bound)
    }

    /// What its screen asks, while a request waits for the button.
    pub fn asking(&self) -> Option<String> {
        self.state().asking.clone()
    }

    /// Confirm or decline what the screen asks. Ignored when nothing waits. The screen is clear
    /// from then on, so one press answers one question.
    pub fn press(&self, yes: bool) {
        let mut st = self.state();
        if st.asking.take().is_some() {
            st.decision = Some(yes);
            self.inner.1.notify_all();
        }
    }

    pub fn set_confirm(&self, confirm: Confirm) {
        self.state().confirm = confirm;
    }

    pub fn serial(&self) -> String {
        hex::encode(&self.state().uid[..15])
    }

    pub fn fingerprint(&self) -> [u8; 4] {
        let st = self.state();
        st.master.fingerprint(&self.secp).to_bytes()
    }

    fn ask(&self, what: String) -> bool {
        let mut st = self.state();
        match st.confirm {
            Confirm::Auto => return true,
            Confirm::Refuse => return false,
            Confirm::Manual => {}
        }
        st.asking = Some(what);
        st.decision = None;
        while st.decision.is_none() {
            st = self.inner.1.wait(st).unwrap_or_else(|e| e.into_inner());
        }
        st.decision.take().unwrap_or(false)
    }

    /// One host connection: frames in, APDUs handled, frames out.
    fn session(&self, mut stream: TcpStream) {
        let mut buf = [0u8; FRAME];
        loop {
            if stream.read_exact(&mut buf).is_err() {
                return;
            }
            let channel = u16::from_be_bytes([buf[0], buf[1]]);
            let mut r = Reassembly::new(channel);
            let mut apdu = r.push(&buf).ok().flatten();
            while apdu.is_none() {
                if stream.read_exact(&mut buf).is_err() {
                    return;
                }
                match r.push(&buf) {
                    Ok(done) => apdu = done,
                    Err(_) => return,
                }
            }
            let answer = self.handle(&apdu.unwrap_or_default());
            for f in hid::frames(channel, &answer) {
                if stream.write_all(&f).is_err() {
                    return;
                }
            }
        }
    }

    pub fn handle(&self, c: &[u8]) -> Answer {
        if c.len() < 5 {
            return sw(0x6700);
        }
        if c[0] != apdu::CLA {
            return sw(0x6e00);
        }
        let (ins, p1, p2) = (c[1], c[2], c[3]);
        let data = &c[5..5 + (c[4] as usize).min(c.len() - 5)];
        match ins {
            apdu::GET_DEVICE_INFO => self.device_info(),
            apdu::GET_PUBLIC => self.get_public(data, p2 == 1),
            apdu::SIGN_ETH_TX | apdu::SIGN_ETH_MSG | apdu::SIGN_EIP712 | apdu::SIGN_PSBT => {
                self.chained(ins, p1 == 0, data)
            }
            apdu::GET_RESPONSE => self.get_response(),
            _ => sw(0x6d00),
        }
    }

    fn device_info(&self) -> Answer {
        let st = self.state();
        let mut d = vec![1, 4, 0];
        d.extend_from_slice(&20_261_010u32.to_be_bytes());
        d.extend_from_slice(&st.uid);
        d.extend_from_slice(&st.device_key.serialize());
        ok(d)
    }

    fn read_path(data: &[u8]) -> Option<(Vec<u32>, usize)> {
        let n = *data.first()? as usize;
        if n > 10 {
            return None;
        }
        let path = (0..n)
            .map(|i| {
                data.get(1 + 4 * i..5 + 4 * i)
                    .map(|b| u32::from_be_bytes(b.try_into().unwrap()))
            })
            .collect::<Option<Vec<_>>>()?;
        Some((path, 1 + 4 * n))
    }

    fn derive(&self, path: &[u32]) -> Xpriv {
        let path: DerivationPath = path
            .iter()
            .map(|i| ChildNumber::from(*i))
            .collect::<Vec<_>>()
            .into();
        let master = self.state().master;
        master
            .derive_priv(&self.secp, &path)
            .expect("a key at the path")
    }

    fn get_public(&self, data: &[u8], extended: bool) -> Answer {
        let Some((path, _)) = Self::read_path(data) else {
            return sw(0x6a80);
        };
        if !self.ask(format!("export {}", crate::accounts::path_string(&path))) {
            return sw(0x6982);
        }
        let key = self.derive(&path);
        let mut d = vec![4];
        d.extend_from_slice(&self.fingerprint());
        d.push(65);
        d.extend_from_slice(
            &key.private_key
                .public_key(&self.secp)
                .serialize_uncompressed(),
        );
        if extended {
            d.push(32);
            d.extend_from_slice(key.chain_code.as_bytes());
        } else {
            d.push(0);
        }
        ok(d)
    }

    /// A chained signing command: gather its chunks, then ask, then sign.
    fn chained(&self, ins: u8, first: bool, data: &[u8]) -> Answer {
        {
            let mut st = self.state();
            if first {
                st.ins = ins;
                st.data.clear();
                st.path.clear();
                let body = if ins == apdu::SIGN_PSBT {
                    let Some(len) = data.get(..4) else {
                        return sw(0x6a80);
                    };
                    st.due = u32::from_be_bytes(len.try_into().unwrap()) as usize;
                    &data[4..]
                } else {
                    let Some((path, at)) = Self::read_path(data) else {
                        return sw(0x6a80);
                    };
                    st.path = path;
                    if ins == apdu::SIGN_ETH_TX {
                        st.due = 0;
                        &data[at..]
                    } else {
                        let Some(len) = data.get(at..at + 4) else {
                            return sw(0x6a80);
                        };
                        st.due = u32::from_be_bytes(len.try_into().unwrap()) as usize;
                        &data[at + 4..]
                    }
                };
                st.data.extend_from_slice(body);
            } else {
                if st.ins != ins {
                    return sw(0x6985);
                }
                st.data.extend_from_slice(data);
            }
            if st.ins == apdu::SIGN_ETH_TX {
                st.due = rlp::tx_len(&st.data).unwrap_or(usize::MAX);
            }
            if st.data.len() < st.due {
                return ok(Vec::new());
            }
            if st.data.len() > st.due {
                return sw(0x6a80);
            }
        }
        let (path, payload) = {
            let st = self.state();
            (st.path.clone(), st.data.clone())
        };
        match ins {
            apdu::SIGN_ETH_TX => self.sign_evm(&path, &payload, "transaction"),
            apdu::SIGN_ETH_MSG => self.sign_evm(&path, &payload, "message"),
            apdu::SIGN_EIP712 => self.sign_evm(&path, &payload, "typed data"),
            _ => self.sign_psbt(&payload),
        }
    }

    fn sign_evm(&self, path: &[u32], payload: &[u8], what: &str) -> Answer {
        let (digest, base) = match what {
            "transaction" => {
                let base = match payload.first() {
                    Some(0x01 | 0x02) => 0u32,
                    _ => match rlp::eip155_chain_id(payload) {
                        Some(id) => (id as u32).wrapping_mul(2).wrapping_add(35),
                        None => 27,
                    },
                };
                (Keccak256::digest(payload).into(), base)
            }
            "message" => {
                let mut m = format!("\x19Ethereum Signed Message:\n{}", payload.len()).into_bytes();
                m.extend_from_slice(payload);
                (Keccak256::digest(&m).into(), 27)
            }
            _ => match serde_json::from_slice::<TypedData>(payload)
                .ok()
                .and_then(|t| t.eip712_signing_hash().ok())
            {
                Some(h) => (h.0, 27),
                None => return sw(0x6982),
            },
        };
        if !self.ask(format!("sign {what}")) {
            return sw(0x6982);
        }
        let key = self.derive(path).private_key;
        let (id, sig) = self
            .secp
            .sign_ecdsa_recoverable(&Message::from_digest(digest), &key)
            .serialize_compact();
        let mut d = vec![(base.wrapping_add(id.to_i32() as u32) & 0xff) as u8];
        d.extend_from_slice(&sig);
        ok(d)
    }

    /// Sign every input with a key of this wallet, as the firmware does. A refusal and a PSBT it
    /// can't sign both answer 0x6a80.
    fn sign_psbt(&self, bytes: &[u8]) -> Answer {
        let Ok(mut psbt) = Psbt::deserialize(bytes) else {
            return sw(0x6a80);
        };
        let fp = self.fingerprint();
        let prevouts: Option<Vec<_>> = psbt.inputs.iter().map(|i| i.witness_utxo.clone()).collect();
        let Some(prevouts) = prevouts else {
            return sw(0x6a80);
        };
        let mut cache = SighashCache::new(psbt.unsigned_tx.clone());
        let mut signed = 0;
        let mut sigs = Vec::new();
        for (i, input) in psbt.inputs.iter().enumerate() {
            let mine = |(f, p): &bitcoin::bip32::KeySource| (f.to_bytes() == fp).then(|| p.clone());
            if let Some((key, path)) = input
                .bip32_derivation
                .iter()
                .find_map(|(k, s)| mine(s).map(|p| (*k, p)))
            {
                let Ok(h) = cache.p2wpkh_signature_hash(
                    i,
                    &prevouts[i].script_pubkey,
                    prevouts[i].value,
                    EcdsaSighashType::All,
                ) else {
                    return sw(0x6a80);
                };
                let sk = self
                    .state()
                    .master
                    .derive_priv(&self.secp, &path)
                    .expect("key")
                    .private_key;
                let sig = self
                    .secp
                    .sign_ecdsa(&Message::from_digest(h.to_byte_array()), &sk);
                sigs.push((i, Some((key, sig)), None));
                signed += 1;
            } else if let Some(path) = input.tap_key_origins.values().find_map(|(_, s)| mine(s)) {
                let Ok(h) = cache.taproot_key_spend_signature_hash(
                    i,
                    &Prevouts::All(&prevouts),
                    TapSighashType::Default,
                ) else {
                    return sw(0x6a80);
                };
                let sk = self
                    .state()
                    .master
                    .derive_priv(&self.secp, &path)
                    .expect("key")
                    .private_key;
                let tweaked = Keypair::from_secret_key(&self.secp, &sk).tap_tweak(&self.secp, None);
                let sig = self.secp.sign_schnorr_no_aux_rand(
                    &Message::from_digest(h.to_byte_array()),
                    &tweaked.to_keypair(),
                );
                sigs.push((i, None, Some(sig)));
                signed += 1;
            }
        }
        if signed == 0 || !self.ask("sign PSBT".into()) {
            return sw(0x6a80);
        }
        for (i, ecdsa, schnorr) in sigs {
            if let Some((key, signature)) = ecdsa {
                psbt.inputs[i].partial_sigs.insert(
                    bitcoin::PublicKey::new(key),
                    bitcoin::ecdsa::Signature {
                        signature,
                        sighash_type: EcdsaSighashType::All,
                    },
                );
            }
            if let Some(signature) = schnorr {
                psbt.inputs[i].tap_key_sig = Some(bitcoin::taproot::Signature {
                    signature,
                    sighash_type: TapSighashType::Default,
                });
            }
        }
        self.state().out = psbt.serialize().into();
        self.get_response()
    }

    /// The next 253 bytes of a long answer, with 0x61XX while more remain.
    fn get_response(&self) -> Answer {
        let mut st = self.state();
        if st.out.is_empty() {
            return sw(0x6985);
        }
        let n = st.out.len().min(253);
        let mut d: Vec<u8> = st.out.drain(..n).collect();
        if st.out.is_empty() {
            d.extend_from_slice(&[0x90, 0x00]);
        } else {
            let left = st.out.len().min(255) as u8;
            d.extend_from_slice(&[0x61, left]);
        }
        d
    }
}

/// The emulator's own key derivation, for tests that check what it exported.
pub fn master_from_phrase(phrase: &str) -> Xpriv {
    let mut seed = [0u8; 64];
    pbkdf2::pbkdf2_hmac::<sha2::Sha512>(phrase.as_bytes(), b"mnemonic", 2048, &mut seed);
    Xpriv::new_master(NetworkKind::Main, &seed).expect("a master key")
}
