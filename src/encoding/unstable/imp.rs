use crate::encoding::{
    table::{Table, HEXDIG},
    *,
};

const fn gen_hex_table() -> [u8; 512] {
    const HEX_DIGITS: &[u8; 16] = b"0123456789ABCDEF";

    let mut i = 0;
    let mut out = [0; 512];
    while i < 256 {
        out[i * 2] = HEX_DIGITS[i >> 4];
        out[i * 2 + 1] = HEX_DIGITS[i & 15];
        i += 1;
    }
    out
}

pub(crate) static HEX_TABLE: &[u8; 512] = &gen_hex_table();

/// Pushes a percent-encoded byte without checking bounds.
///
/// # Safety
///
/// `v.len() + 3` must not exceed `v.capacity()`.
unsafe fn push_pct_encoded(v: &mut Vec<u8>, x: u8) {
    let len = v.len();
    debug_assert!(len + 2 < v.capacity());
    // SAFETY: The caller must ensure that the capacity is enough.
    unsafe {
        let ptr = v.as_mut_ptr().add(len);
        *ptr = b'%';
        *ptr.add(1) = HEX_TABLE[x as usize * 2];
        *ptr.add(2) = HEX_TABLE[x as usize * 2 + 1];

        v.set_len(len + 3);
    }
}

pub(super) fn encode<'a>(s: &'a [u8], table: &Table) -> Cow<'a, str> {
    // Skip the allowed bytes.
    let i = match s.iter().position(|&x| !table.allows(x)) {
        Some(i) => i,
        // SAFETY: All bytes are checked to be less than 128 (ASCII).
        None => return Cow::Borrowed(unsafe { str::from_utf8_unchecked(s) }),
    };

    unsafe {
        // SAFETY: `i` cannot exceed `s.len()` since `i < s.len()`.
        let mut buf = copy_new(s, i, true);
        _encode(s, i, table, &mut buf);
        // SAFETY: The bytes should all be ASCII and thus valid UTF-8.
        Cow::Owned(String::from_utf8_unchecked(buf))
    }
}

pub(super) fn encode_to<'a>(s: &[u8], table: &Table, buf: &'a mut Vec<u8>) {
    // Skip the allowed bytes.
    let i = match s.iter().position(|&x| !table.allows(x)) {
        Some(i) => i,
        None => return buf.extend_from_slice(s),
    };
    unsafe {
        // SAFETY: `i` cannot exceed `s.len()` since `i < s.len()`.
        copy(s, buf, i, true);
        _encode(s, i, table, buf);
    }
}

unsafe fn _encode(s: &[u8], mut i: usize, table: &Table, buf: &mut Vec<u8>) {
    while i < s.len() {
        let x = s[i];
        // SAFETY: The maximum output length is triple the input length.
        unsafe {
            if table.allows(x) {
                push(buf, x);
            } else {
                push_pct_encoded(buf, x);
            }
        }
        i += 1;
    }
}

pub(super) fn decode(s: &[u8]) -> Result<Cow<'_, [u8]>> {
    // Skip bytes that are not '%'.
    let i = match s.iter().position(|&x| x == b'%') {
        Some(i) => i,
        None => return Ok(Cow::Borrowed(s)),
    };
    // SAFETY: `i` cannot exceed `s.len()` since `i < s.len()`.
    let mut buf = unsafe { copy_new(s, i, false) };

    unsafe { _decode(s, i, &mut buf, true)? }
    Ok(Cow::Owned(buf))
}

pub(super) fn decode_with<'a>(s: &[u8], buf: &'a mut Vec<u8>) -> Result<Option<&'a [u8]>> {
    // Skip bytes that are not '%'.
    let i = match s.iter().position(|&x| x == b'%') {
        Some(i) => i,
        None => return Ok(None),
    };

    let start = buf.len();

    unsafe {
        // SAFETY: `i` cannot exceed `s.len()` since `i < s.len()`.
        copy(s, buf, i, false);
        _decode(s, i, buf, true)?;
        // SAFETY: The length is non-decreasing.
        Ok(Some(buf.get_unchecked(start..)))
    }
}

/// Decodes a percent-encoded string with a buffer assuming validity.
///
/// If the string needs no decoding, this function returns `None`
/// and no bytes will be appended to the buffer.
///
/// # Safety
///
/// This function does not check that the string is properly encoded.
/// Any invalid encoded octet in the string will result in undefined behavior.
pub unsafe fn decode_with_unchecked<'a>(s: &[u8], buf: &'a mut Vec<u8>) -> Option<&'a [u8]> {
    // Skip bytes that are not '%'.
    let i = match s.iter().position(|&x| x == b'%') {
        Some(i) => i,
        None => return None,
    };

    let start = buf.len();

    unsafe {
        // SAFETY: `i` cannot exceed `s.len()` since `i < s.len()`.
        copy(s, buf, i, false);
        // SAFETY: The caller must ensure that the string is properly encoded.
        _decode(s, i, buf, false).unwrap();
        // SAFETY: The length is non-decreasing.
        Some(buf.get_unchecked(start..))
    }
}

pub(super) fn validate_enc(s: &[u8], table: &Table) -> Result<()> {
    let mut i = 0;
    while i < s.len() {
        let x = s[i];
        if x == b'%' {
            if i + 2 >= s.len() {
                err!(i, InvalidOctet);
            }
            // SAFETY: We have checked that `i + 2 < s.len()`.
            // Overflow should be impossible because we cannot have that large a slice.
            let (hi, lo) = unsafe { (*s.get_unchecked(i + 1), *s.get_unchecked(i + 2)) };

            if HEXDIG.get(hi) & HEXDIG.get(lo) == 0 {
                err!(i, InvalidOctet);
            }
            i += 3;
        } else {
            if !table.allows(x) {
                err!(i, UnexpectedChar);
            }
            i += 1;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const RAW: &[u8] = "te😃a 测1`~!@试#$%st^&+=".as_bytes();
    const ENCODED: &[u8] = b"te%F0%9F%98%83a%20%E6%B5%8B1%60~!@%E8%AF%95%23$%25st%5E&+=";

    #[test]
    fn enc_dec_validate() {
        let s = encode(RAW, table::QUERY_FRAGMENT);
        assert_eq!(ENCODED, s.as_bytes());

        let mut buf = Vec::new();
        encode_to(RAW, table::QUERY_FRAGMENT, &mut buf);
        assert_eq!(ENCODED, buf);

        assert!(validate(&*s, table::QUERY_FRAGMENT).is_ok());

        assert_eq!(Ok(RAW), decode(ENCODED).as_deref());

        let mut buf = Vec::new();
        assert_eq!(Ok(Some(RAW)), decode_with(ENCODED, &mut buf));
        assert_eq!(buf, RAW);

        assert_eq!(Some(RAW), unsafe { decode_unchecked(ENCODED).as_deref() });

        let mut buf = Vec::new();
        assert_eq!(Some(RAW), unsafe {
            decode_with_unchecked(ENCODED, &mut buf)
        });
        assert_eq!(buf, RAW);

        assert_eq!(Ok(b"\x2d\xe6\xb5" as _), decode(b"%2D%E6%B5").as_deref());

        let s = b"%2d%";
        assert_eq!(3, decode(s).unwrap_err().index());

        let s = b"%2d%fg";
        assert_eq!(3, decode(s).unwrap_err().index());

        // We used to use slot 0 to indicate that percent-encoded octets are allowed,
        // which was totally wrong since it just allows zero bytes. Glad we fixed it.
        assert!(validate("\0", table::QUERY_FRAGMENT).is_err());
    }
}
