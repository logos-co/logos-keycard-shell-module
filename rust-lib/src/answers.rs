//! The Shell's answers as `logos.signer/1` signatures: an EVM `v ‖ r ‖ s` with its recovery id,
//! and each input's signature from the PSBT the Shell hands back. The manager checks them all.

use bitcoin::key::TapTweak;
use bitcoin::secp256k1::{ecdsa, PublicKey, Secp256k1, XOnlyPublicKey};
use bitcoin::Psbt;
use logos_signer_interface::Signature;

use crate::commands::Vrs;

/// How the Shell picked `v` (its firmware's `core_eth_get_tx_v_base`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VBase {
    /// EIP-2930 and EIP-1559: `v` is the parity.
    Typed,
    /// A legacy transaction: `chainId * 2 + 35`, kept to its low byte, or 27 without EIP-155.
    Legacy { chain_id: Option<u64> },
    /// `personal_sign` and EIP-712: 27.
    Message,
}

impl VBase {
    /// What a transaction's first byte and EIP-155 fields say.
    pub fn of_tx(tx: &[u8], chain_id: u64) -> VBase {
        match tx.first() {
            Some(0x01 | 0x02) => VBase::Typed,
            _ if crate::rlp::eip155_offset(tx).is_some() => VBase::Legacy {
                chain_id: Some(chain_id),
            },
            _ => VBase::Legacy { chain_id: None },
        }
    }

    fn byte(self) -> u8 {
        match self {
            VBase::Typed => 0,
            VBase::Message | VBase::Legacy { chain_id: None } => 27,
            VBase::Legacy { chain_id: Some(id) } => {
                (id.wrapping_mul(2).wrapping_add(35) & 0xff) as u8
            }
        }
    }
}

/// `r ‖ s` with low S, and the recovery id, flipped with S when S had to be lowered.
pub fn evm_signature(answer: &Vrs, base: VBase, pubkey: &PublicKey) -> Result<Signature, String> {
    let id = answer[0].wrapping_sub(base.byte());
    if id > 1 {
        return Err(format!(
            "a v of {} where {} or {} was due",
            answer[0],
            base.byte(),
            base.byte().wrapping_add(1)
        ));
    }
    let given = ecdsa::Signature::from_compact(&answer[1..])
        .map_err(|_| "not an ECDSA signature".to_string())?;
    let mut low = given;
    low.normalize_s();
    let id = if low == given { id } else { id ^ 1 };
    Ok(Signature {
        item: 0,
        signature: hex::encode(low.serialize_compact()),
        recovery_id: Some(id),
        pubkey: hex::encode(pubkey.serialize()),
    })
}

/// The signature the Shell added to each input, by the key at that input's origin under `fingerprint`.
/// An input it left unsigned has none; the manager then refuses the answer.
pub fn psbt_signatures(signed: &Psbt, fingerprint: [u8; 4]) -> Vec<Signature> {
    let secp = Secp256k1::verification_only();
    let mut out = Vec::new();
    for (i, input) in signed.inputs.iter().enumerate() {
        let ours = |fp: &bitcoin::bip32::Fingerprint| fp.to_bytes() == fingerprint;
        for (key, (fp, _)) in &input.bip32_derivation {
            if let (true, Some(sig)) = (
                ours(fp),
                input.partial_sigs.get(&bitcoin::PublicKey::new(*key)),
            ) {
                out.push(Signature {
                    item: i,
                    signature: hex::encode(sig.signature.serialize_compact()),
                    recovery_id: None,
                    pubkey: hex::encode(key.serialize()),
                });
            }
        }
        let internal: Option<XOnlyPublicKey> = input
            .tap_key_origins
            .iter()
            .find(|(_, (_, (fp, _)))| ours(fp))
            .map(|(k, _)| *k);
        if let (Some(internal), Some(sig)) = (internal, input.tap_key_sig) {
            let (output, _) = internal.tap_tweak(&secp, input.tap_merkle_root);
            out.push(Signature {
                item: i,
                signature: hex::encode(sig.signature.serialize()),
                recovery_id: None,
                pubkey: hex::encode(output.to_x_only_public_key().serialize()),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Message, SecretKey};

    fn signed(digest: [u8; 32]) -> (Vrs, PublicKey, ecdsa::Signature) {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11; 32]).unwrap();
        let sig = secp.sign_ecdsa(&Message::from_digest(digest), &sk);
        let mut a = [0u8; 65];
        a[1..].copy_from_slice(&sig.serialize_compact());
        (a, PublicKey::from_secret_key(&secp, &sk), sig)
    }

    #[test]
    fn v_gives_the_recovery_id_for_each_base() {
        let (mut a, key, _) = signed([7; 32]);
        for (base, v) in [
            (VBase::Typed, 1),
            (VBase::Message, 28),
            (VBase::Legacy { chain_id: Some(1) }, 38),
            // 2 * 11155111 + 35 = 22310257, whose low byte is 0x71.
            (
                VBase::Legacy {
                    chain_id: Some(11_155_111),
                },
                0x72,
            ),
        ] {
            a[0] = v;
            assert_eq!(
                evm_signature(&a, base, &key).unwrap().recovery_id,
                Some(1),
                "{base:?}"
            );
        }
        a[0] = 30;
        assert!(
            evm_signature(&a, VBase::Message, &key).is_err(),
            "a v two past its base"
        );
    }

    #[test]
    fn a_high_s_is_lowered_and_its_recovery_id_flipped() {
        let (mut a, key, low) = signed([9; 32]);
        // n - s, the same signature with high S.
        let n = hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
            .unwrap();
        let s = &low.serialize_compact()[32..];
        let mut high = [0u8; 32];
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let d = n[i] as i16 - s[i] as i16 - borrow;
            high[i] = d.rem_euclid(256) as u8;
            borrow = i16::from(d < 0);
        }
        a[33..].copy_from_slice(&high);
        a[0] = 27;
        let out = evm_signature(&a, VBase::Message, &key).unwrap();
        assert_eq!(out.signature, hex::encode(low.serialize_compact()));
        assert_eq!(out.recovery_id, Some(1));
    }
}
