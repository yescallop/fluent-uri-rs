use super::EncodingError;
use alloc::vec::Vec;

pub(crate) const fn validate_estr(s: &[u8]) -> Result<(), EncodingError> {
    let mut i = 0;
    while i < s.len() {
        let x = s[i];
        if x == b'%' {
            if i + 2 >= s.len() {
                return Err(EncodingError { index: i });
            }
            let (hi, lo) = (s[i + 1], s[i + 2]);

            if !hi.is_ascii_hexdigit() || !lo.is_ascii_hexdigit() {
                return Err(EncodingError { index: i });
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    Ok(())
}

const fn gen_octet_table(hi: bool) -> [u8; 256] {
    let mut out = [0xff; 256];
    let shift = if hi { 4 } else { 0 };

    let mut i = 0;
    while i < 10 {
        out[(i + b'0') as usize] = i << shift;
        i += 1;
    }
    while i < 16 {
        out[(i - 10 + b'A') as usize] = i << shift;
        out[(i - 10 + b'a') as usize] = i << shift;
        i += 1;
    }
    out
}

const OCTET_TABLE_HI: &[u8; 256] = &gen_octet_table(true);
pub(crate) const OCTET_TABLE_LO: &[u8; 256] = &gen_octet_table(false);

/// Decodes a percent-encoded octet, assuming that the bytes are hexadecimal.
fn decode_octet(hi: u8, lo: u8) -> u8 {
    debug_assert!(hi.is_ascii_hexdigit() && lo.is_ascii_hexdigit());
    OCTET_TABLE_HI[hi as usize] | OCTET_TABLE_LO[lo as usize]
}

/// Decodes a percent-encoded string, assuming that the string is properly encoded.
pub(crate) fn decode(s: &[u8]) -> Option<Vec<u8>> {
    // Skip bytes that are not '%'.
    let mut i = match s.iter().position(|&x| x == b'%') {
        Some(i) => i,
        None => return None,
    };

    let mut buf = Vec::with_capacity(s.len());
    buf.extend_from_slice(&s[..i]);

    while i < s.len() {
        let x = s[i];
        if x == b'%' {
            buf.push(decode_octet(s[i + 1], s[i + 2]));
            i += 3;
        } else {
            buf.push(x);
            i += 1;
        }
    }
    Some(buf)
}
