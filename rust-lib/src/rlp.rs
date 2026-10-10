//! Just enough RLP to find a transaction's fields: where its list ends, and where a legacy
//! transaction's EIP-155 fields begin.

/// Where a legacy EIP-155 transaction's `chainId, 0, 0` begin: its seventh field. `None` for a
/// typed transaction or a legacy one without them.
pub fn eip155_offset(tx: &[u8]) -> Option<usize> {
    let (start, end) = list_payload(tx)?;
    let mut at = start;
    let mut index = 0;
    while at < end {
        if index == 6 {
            return Some(at);
        }
        at = item_end(tx, at)?;
        index += 1;
    }
    None
}

/// The payload of the RLP list `b` starts with: `(start, end)`.
pub fn list_payload(b: &[u8]) -> Option<(usize, usize)> {
    let first = *b.first()?;
    let (start, len) = match first {
        0xc0..=0xf7 => (1, (first - 0xc0) as usize),
        0xf8..=0xff => {
            let n = (first - 0xf7) as usize;
            (1 + n, be_len(b.get(1..1 + n)?)?)
        }
        _ => return None,
    };
    Some((start, start.checked_add(len)?)).filter(|(_, end)| *end <= b.len())
}

/// Where the RLP item starting at `at` ends.
pub fn item_end(b: &[u8], at: usize) -> Option<usize> {
    let first = *b.get(at)?;
    let end = match first {
        0x00..=0x7f => at + 1,
        0x80..=0xb7 => at + 1 + (first - 0x80) as usize,
        0xb8..=0xbf => {
            let n = (first - 0xb7) as usize;
            at + 1 + n + be_len(b.get(at + 1..at + 1 + n)?)?
        }
        0xc0..=0xf7 => at + 1 + (first - 0xc0) as usize,
        0xf8..=0xff => {
            let n = (first - 0xf7) as usize;
            at + 1 + n + be_len(b.get(at + 1..at + 1 + n)?)?
        }
    };
    (end <= b.len()).then_some(end)
}

fn be_len(b: &[u8]) -> Option<usize> {
    if b.is_empty() || b.len() > 8 {
        return None;
    }
    Some(b.iter().fold(0usize, |n, x| (n << 8) | *x as usize))
}

/// The length of the whole transaction `tx` starts with, its type byte included, once enough of
/// it has come to say.
pub fn tx_len(tx: &[u8]) -> Option<usize> {
    let typed = matches!(tx.first(), Some(0x01 | 0x02));
    let list = if typed { tx.get(1..)? } else { tx };
    let first = *list.first()?;
    let total = match first {
        0xc0..=0xf7 => 1 + (first - 0xc0) as usize,
        0xf8..=0xff => {
            let n = (first - 0xf7) as usize;
            1 + n + be_len(list.get(1..1 + n)?)?
        }
        _ => return None,
    };
    Some(total + usize::from(typed))
}

/// The seventh field of a legacy transaction, read as a number: its EIP-155 chain id.
pub fn eip155_chain_id(tx: &[u8]) -> Option<u64> {
    let at = eip155_offset(tx)?;
    let end = item_end(tx, at)?;
    let body = match tx[at] {
        b @ 0x00..=0x7f => return Some(b as u64),
        0x80..=0xb7 => &tx[at + 1..end],
        _ => return None,
    };
    (body.len() <= 8).then(|| body.iter().fold(0u64, |n, x| (n << 8) | *x as u64))
}
