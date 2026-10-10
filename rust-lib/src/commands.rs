//! The Shell's commands over [`Transport`], with the layouts its firmware v1.4.0 uses.

use bitcoin::secp256k1::PublicKey;

use crate::apdu::{self, path_bytes, send, ShellError, Transport};

/// What GET DEVICE INFO says. Asking needs no confirmation on the Shell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceInfo {
    pub firmware: [u8; 3],
    /// A date, YYYYMMDD: the token and chain database's version.
    pub database: u32,
    pub uid: [u8; 16],
    /// The Shell's own key, for checking the device is genuine.
    pub public_key: [u8; 33],
}

impl DeviceInfo {
    pub fn firmware_version(&self) -> String {
        let [a, b, c] = self.firmware;
        format!("{a}.{b}.{c}")
    }

    /// The USB serial number string: the UID's first 15 bytes, in lowercase hex.
    pub fn serial(&self) -> String {
        hex::encode(&self.uid[..15])
    }
}

pub fn device_info(t: &mut dyn Transport) -> apdu::Result<DeviceInfo> {
    let r = send(t, apdu::GET_DEVICE_INFO, 0, &[vec![]])?;
    if r.len() < 56 {
        return Err(ShellError::Link(format!("device info: {} bytes", r.len())));
    }
    Ok(DeviceInfo {
        firmware: [r[0], r[1], r[2]],
        database: u32::from_be_bytes([r[3], r[4], r[5], r[6]]),
        uid: r[7..23].try_into().expect("16 bytes"),
        public_key: r[23..56].try_into().expect("33 bytes"),
    })
}

/// A key the Shell exported, after the person confirmed it on its screen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exported {
    /// The master key's fingerprint.
    pub fingerprint: [u8; 4],
    pub key: PublicKey,
    pub chain_code: Option<[u8; 32]>,
}

pub fn get_public(t: &mut dyn Transport, path: &[u32], extended: bool) -> apdu::Result<Exported> {
    let r = send(t, apdu::GET_PUBLIC, u8::from(extended), &[path_bytes(path)])?;
    let bad = |why: &str| ShellError::Link(format!("public key: {why}"));
    let field = |at: usize| -> apdu::Result<(&[u8], usize)> {
        let len = *r.get(at).ok_or_else(|| bad("short"))? as usize;
        let body = r.get(at + 1..at + 1 + len).ok_or_else(|| bad("short"))?;
        Ok((body, at + 1 + len))
    };
    let (fp, at) = field(0)?;
    let (key, at) = field(at)?;
    let (chain, _) = field(at)?;
    Ok(Exported {
        fingerprint: fp
            .try_into()
            .map_err(|_| bad("a fingerprint of another size"))?,
        key: PublicKey::from_slice(key).map_err(|_| bad("not a public key"))?,
        chain_code: match chain.len() {
            0 => None,
            32 => Some(chain.try_into().expect("32 bytes")),
            _ => return Err(bad("a chain code of another size")),
        },
    })
}

/// A 65-byte `v ‖ r ‖ s` answer.
pub type Vrs = [u8; 65];

fn vrs(r: Vec<u8>) -> apdu::Result<Vrs> {
    r.get(..65)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| ShellError::Link(format!("signature: {} bytes", r.len())))
}

/// An EVM transaction, its unsigned bytes in chunks of at most 150, as the firmware's own client
/// sends them; the chunk that reaches a legacy transaction's EIP-155 fields carries them whole.
pub fn sign_eth_tx(t: &mut dyn Transport, path: &[u32], tx: &[u8]) -> apdu::Result<Vrs> {
    let head = path_bytes(path);
    let vrs_at = crate::rlp::eip155_offset(tx).unwrap_or(0);
    let mut chunks = Vec::new();
    let mut at = 0;
    while at < tx.len() {
        let room = if at == 0 { 150 - head.len() } else { 150 };
        let mut size = room.min(tx.len() - at);
        if vrs_at != 0 && at + size >= vrs_at {
            size = tx.len() - at;
        }
        let mut c = if at == 0 { head.clone() } else { Vec::new() };
        c.extend_from_slice(&tx[at..at + size]);
        chunks.push(c);
        at += size;
    }
    vrs(send(t, apdu::SIGN_ETH_TX, 0, &chunks)?)
}

/// `personal_sign` over `message`, which the Shell shows.
pub fn sign_eth_message(t: &mut dyn Transport, path: &[u32], message: &[u8]) -> apdu::Result<Vrs> {
    vrs(send(t, apdu::SIGN_ETH_MSG, 0, &with_length(path, message))?)
}

/// An EIP-712 document, as its JSON.
pub fn sign_eip712(t: &mut dyn Transport, path: &[u32], json: &[u8]) -> apdu::Result<Vrs> {
    vrs(send(t, apdu::SIGN_EIP712, 0, &with_length(path, json))?)
}

/// A PSBT, version 0. The answer is the whole PSBT with the Shell's signatures added.
pub fn sign_psbt(t: &mut dyn Transport, psbt: &[u8]) -> apdu::Result<Vec<u8>> {
    let len = (psbt.len() as u32).to_be_bytes();
    send(t, apdu::SIGN_PSBT, 0, &apdu::chunks_after(&len, psbt))
}

fn with_length(path: &[u32], payload: &[u8]) -> Vec<Vec<u8>> {
    let mut head = path_bytes(path);
    head.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    apdu::chunks_after(&head, payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_legacy_eip155_transaction_has_its_chain_fields_found() {
        // rlp([nonce 9, gasPrice 20 gwei, gas 21000, to, value 1 ether, data, chainId 1, 0, 0]),
        // EIP-155's own example.
        let tx = hex::decode(
            "ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080",
        )
        .unwrap();
        assert_eq!(crate::rlp::eip155_offset(&tx), Some(tx.len() - 3));
        assert_eq!(crate::rlp::eip155_offset(&[0x02, 0xc0]), None, "typed");
    }

    #[test]
    fn a_device_info_answer_is_read_field_by_field() {
        struct One(Vec<u8>);
        impl Transport for One {
            fn exchange(&mut self, _: &[u8]) -> apdu::Result<Vec<u8>> {
                Ok(self.0.clone())
            }
        }
        let mut r = vec![1, 4, 0, 0x01, 0x35, 0x28, 0x92];
        r.extend((0..16).map(|i| i as u8));
        r.extend([2; 33]);
        r.extend([0x90, 0x00]);
        let info = device_info(&mut One(r)).unwrap();
        assert_eq!(info.firmware_version(), "1.4.0");
        assert_eq!(info.database, 20_261_010);
        assert_eq!(info.serial(), "000102030405060708090a0b0c0d0e");
    }
}
