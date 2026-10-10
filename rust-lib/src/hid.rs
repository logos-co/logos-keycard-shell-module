//! The Shell's HID framing (its firmware's docs/USB.md): an APDU travels in 64-byte frames, each
//! `channel(2) tag(1) sequence(2)`, the first also carrying the APDU's length(2), all big endian.

use crate::apdu::ShellError;

pub const FRAME: usize = 64;
pub const CHANNEL: u16 = 0x0101;
const TAG_APDU: u8 = 0x05;
const HEAD: usize = 5;

/// The frames that carry one APDU, the last one zero-padded.
pub fn frames(channel: u16, apdu: &[u8]) -> Vec<[u8; FRAME]> {
    let mut data = Vec::with_capacity(apdu.len() + 2);
    data.extend_from_slice(&(apdu.len() as u16).to_be_bytes());
    data.extend_from_slice(apdu);
    data.chunks(FRAME - HEAD)
        .enumerate()
        .map(|(seq, chunk)| {
            let mut f = [0u8; FRAME];
            f[..2].copy_from_slice(&channel.to_be_bytes());
            f[2] = TAG_APDU;
            f[3..HEAD].copy_from_slice(&(seq as u16).to_be_bytes());
            f[HEAD..HEAD + chunk.len()].copy_from_slice(chunk);
            f
        })
        .collect()
}

/// One APDU rebuilt from its frames, each checked for its channel, tag and sequence.
pub struct Reassembly {
    channel: u16,
    len: Option<usize>,
    seq: u16,
    buf: Vec<u8>,
}

impl Reassembly {
    pub fn new(channel: u16) -> Self {
        Reassembly {
            channel,
            len: None,
            seq: 0,
            buf: Vec::new(),
        }
    }

    /// The APDU once its last frame arrives; padding past its length is dropped.
    pub fn push(&mut self, f: &[u8]) -> Result<Option<Vec<u8>>, ShellError> {
        let bad = |why: &str| ShellError::Link(format!("frame: {why}"));
        if f.len() < HEAD + 2 {
            return Err(bad("too short"));
        }
        if u16::from_be_bytes([f[0], f[1]]) != self.channel {
            return Err(bad("another channel"));
        }
        if f[2] != TAG_APDU {
            return Err(bad("not an APDU"));
        }
        if u16::from_be_bytes([f[3], f[4]]) != self.seq {
            return Err(bad("out of sequence"));
        }
        let data = match self.len {
            None => {
                self.len = Some(u16::from_be_bytes([f[5], f[6]]) as usize);
                &f[HEAD + 2..]
            }
            Some(_) => &f[HEAD..],
        };
        self.seq += 1;
        let want = self.len.unwrap_or_default();
        let take = data.len().min(want - self.buf.len());
        self.buf.extend_from_slice(&data[..take]);
        Ok((self.buf.len() == want).then(|| std::mem::take(&mut self.buf)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_apdu_fits_one_frame_with_its_length() {
        let f = frames(CHANNEL, &[0xe0, 0x06, 0x00, 0x00, 0x00]);
        assert_eq!(f.len(), 1);
        assert_eq!(
            &f[0][..12],
            &[0x01, 0x01, 0x05, 0x00, 0x00, 0x00, 0x05, 0xe0, 0x06, 0x00, 0x00, 0x00]
        );
        assert!(f[0][12..].iter().all(|b| *b == 0), "zero padding");
    }

    #[test]
    fn the_first_frame_carries_57_bytes_and_the_rest_59() {
        let apdu: Vec<u8> = (0..=200u8).collect();
        let f = frames(CHANNEL, &apdu);
        // 2 + 201 bytes over 59-byte payloads: four frames.
        assert_eq!(f.len(), 4);
        assert_eq!(&f[0][7..], &apdu[..57]);
        assert_eq!(&f[1][3..5], &[0, 1]);
        assert_eq!(&f[1][5..], &apdu[57..116]);
        let mut r = Reassembly::new(CHANNEL);
        let mut out = None;
        for frame in &f {
            assert!(out.is_none(), "complete before the last frame");
            out = r.push(frame).unwrap();
        }
        assert_eq!(out.unwrap(), apdu);
    }

    #[test]
    fn a_frame_out_of_place_is_refused() {
        let f = frames(CHANNEL, &[0u8; 100]);
        assert!(
            Reassembly::new(0x0202).push(&f[0]).is_err(),
            "another channel"
        );
        assert!(
            Reassembly::new(CHANNEL).push(&f[1]).is_err(),
            "sequence 1 first"
        );
        let mut ping = f[0];
        ping[2] = 0x02;
        assert!(
            Reassembly::new(CHANNEL).push(&ping).is_err(),
            "a ping is no APDU"
        );
    }
}
