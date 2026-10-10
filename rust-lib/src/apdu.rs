//! The Shell's command layer: ISO 7816-like APDUs with CLA 0xe0, payloads chained in chunks of
//! at most 255 bytes (P1 = 0 first, then 1), and long answers fetched with GET RESPONSE.

pub const CLA: u8 = 0xe0;
pub const GET_PUBLIC: u8 = 0x02;
pub const SIGN_ETH_TX: u8 = 0x04;
pub const GET_DEVICE_INFO: u8 = 0x06;
pub const SIGN_ETH_MSG: u8 = 0x08;
pub const SIGN_EIP712: u8 = 0x0c;
pub const SIGN_PSBT: u8 = 0x0e;
pub const GET_RESPONSE: u8 = 0xc0;

/// Why the Shell, or the link to it, gave no answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShellError {
    /// 0x6982: the person declined on the Shell.
    Denied,
    /// 0x6985: not now, such as with no card inserted or the card locked.
    Conditions,
    /// 0x6a80: the Shell couldn't read the request. For a PSBT it is also its answer when the
    /// person declines: its screen says which.
    InvalidData,
    /// 0x6501: a feature this Shell doesn't have.
    Unsupported,
    /// Any other status word.
    Status(u16),
    /// Unplugged, timed out, or frames that don't fit together.
    Link(String),
    /// The job was given up while the Shell waited.
    Cancelled,
}

impl std::fmt::Display for ShellError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShellError::Denied => f.write_str("declined on the Keycard Shell"),
            ShellError::Conditions => {
                f.write_str("the Keycard Shell can't do this now: is its card in and unlocked?")
            }
            ShellError::InvalidData => f.write_str("the Keycard Shell could not read the request"),
            ShellError::Unsupported => {
                f.write_str("this Keycard Shell's firmware doesn't support it")
            }
            ShellError::Status(sw) => write!(f, "the Keycard Shell answered {sw:04x}"),
            ShellError::Link(why) => write!(f, "Keycard Shell link: {why}"),
            ShellError::Cancelled => f.write_str("cancelled"),
        }
    }
}

pub type Result<T> = std::result::Result<T, ShellError>;

/// One C-APDU and its R-APDU, which ends in the status word.
pub trait Transport: Send {
    fn exchange(&mut self, apdu: &[u8]) -> Result<Vec<u8>>;
}

pub fn command(ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    debug_assert!(data.len() <= 255, "a chunk is at most 255 bytes");
    let mut c = Vec::with_capacity(5 + data.len());
    c.extend_from_slice(&[CLA, ins, p1, p2, data.len() as u8]);
    c.extend_from_slice(data);
    c
}

/// A response's data and its status word.
pub fn split(r: &[u8]) -> Result<(&[u8], u16)> {
    if r.len() < 2 {
        return Err(ShellError::Link("an answer without a status word".into()));
    }
    let (data, sw) = r.split_at(r.len() - 2);
    Ok((data, u16::from_be_bytes([sw[0], sw[1]])))
}

pub fn status(sw: u16) -> Result<()> {
    match sw {
        0x9000 => Ok(()),
        0x6982 => Err(ShellError::Denied),
        0x6985 => Err(ShellError::Conditions),
        0x6a80 => Err(ShellError::InvalidData),
        0x6501 => Err(ShellError::Unsupported),
        other => Err(ShellError::Status(other)),
    }
}

/// Send `chunks` as one chained command and return the whole answer: every intermediate chunk
/// must be acknowledged with 0x9000, and 0x61XX on the last means GET RESPONSE until it ends.
pub fn send(t: &mut dyn Transport, ins: u8, p2: u8, chunks: &[Vec<u8>]) -> Result<Vec<u8>> {
    let mut last = None;
    for (i, chunk) in chunks.iter().enumerate() {
        let r = t.exchange(&command(ins, u8::from(i > 0), p2, chunk))?;
        let (data, sw) = split(&r)?;
        if i + 1 < chunks.len() {
            status(sw)?;
        } else {
            last = Some((data.to_vec(), sw));
        }
    }
    let (mut data, mut sw) = last.ok_or_else(|| ShellError::Link("nothing to send".into()))?;
    while sw >> 8 == 0x61 {
        let r = t.exchange(&command(GET_RESPONSE, 0, 0, &[]))?;
        let (more, next) = split(&r)?;
        data.extend_from_slice(more);
        sw = next;
    }
    status(sw)?;
    Ok(data)
}

/// `payload` in chunks of at most 255 bytes, the first starting with `head`.
pub fn chunks_after(head: &[u8], payload: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let first = (255 - head.len()).min(payload.len());
    let mut c = head.to_vec();
    c.extend_from_slice(&payload[..first]);
    out.push(c);
    out.extend(payload[first..].chunks(255).map(<[u8]>::to_vec));
    out
}

/// A BIP32 path as the Shell takes it: its length, then each index, big endian.
pub fn path_bytes(path: &[u32]) -> Vec<u8> {
    let mut b = vec![path.len() as u8];
    for i in path {
        b.extend_from_slice(&i.to_be_bytes());
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Answers each command from a script, and records what it was sent.
    struct Script {
        answers: Vec<Vec<u8>>,
        sent: Vec<Vec<u8>>,
    }

    impl Transport for Script {
        fn exchange(&mut self, apdu: &[u8]) -> Result<Vec<u8>> {
            self.sent.push(apdu.to_vec());
            Ok(self.answers.remove(0))
        }
    }

    #[test]
    fn a_chained_command_marks_later_chunks_and_follows_get_response() {
        let mut t = Script {
            answers: vec![
                vec![0x90, 0x00],
                vec![1, 2, 0x61, 0x03],
                vec![3, 0x90, 0x00],
            ],
            sent: Vec::new(),
        };
        let out = send(&mut t, SIGN_PSBT, 0, &[vec![0xaa], vec![0xbb]]).unwrap();
        assert_eq!(out, vec![1, 2, 3]);
        assert_eq!(t.sent[0], vec![0xe0, 0x0e, 0x00, 0x00, 0x01, 0xaa]);
        assert_eq!(t.sent[1], vec![0xe0, 0x0e, 0x01, 0x00, 0x01, 0xbb]);
        assert_eq!(t.sent[2], vec![0xe0, 0xc0, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn a_status_word_names_what_went_wrong() {
        let mut t = Script {
            answers: vec![vec![0x69, 0x82]],
            sent: Vec::new(),
        };
        assert_eq!(
            send(&mut t, GET_PUBLIC, 0, &[vec![]]),
            Err(ShellError::Denied)
        );
    }

    #[test]
    fn chunks_hold_255_bytes_with_the_head_in_the_first() {
        let c = chunks_after(&[9; 21], &[1; 600]);
        assert_eq!(
            c.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![255, 255, 111]
        );
        assert_eq!(&c[0][..21], &[9; 21]);
        assert_eq!(
            path_bytes(&[0x8000_002c, 60]),
            vec![2, 0x80, 0, 0, 0x2c, 0, 0, 0, 60]
        );
    }
}
