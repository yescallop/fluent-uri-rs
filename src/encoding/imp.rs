use crate::Result;

use super::{
    err,
    table::{Table, HEXDIG},
};
use beef::Cow;
use std::{ptr, str};

const fn gen_octet_table(hi: bool) -> [u8; 256] {
    let mut out = [0xFF; 256];
    let shift = (hi as u8) * 4;

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

static OCTET_TABLE_HI: &[u8; 256] = &gen_octet_table(true);
pub(crate) static OCTET_TABLE_LO: &[u8; 256] = &gen_octet_table(false);

/// Decodes a percent-encoded octet assuming validity.
fn decode_octet_unchecked(hi: u8, lo: u8) -> u8 {
    OCTET_TABLE_HI[hi as usize] | OCTET_TABLE_LO[lo as usize]
}

/// Decodes a percent-encoded octet.
fn decode_octet(mut hi: u8, mut lo: u8) -> Option<u8> {
    hi = OCTET_TABLE_HI[hi as usize];
    lo = OCTET_TABLE_LO[lo as usize];
    if hi & 1 == 0 && lo & 0x80 == 0 {
        Some(hi | lo)
    } else {
        None
    }
}

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

pub(super) static HEX_TABLE: &[u8; 512] = &gen_hex_table();

fn calc_capacity(s: &[u8], triple: bool) -> usize {
    #[cold]
    fn capacity_overflow() -> ! {
        panic!("capacity overflow")
    }

    if triple {
        if s.len() > isize::MAX as usize / 3 {
            capacity_overflow();
        }
        s.len() * 3
    } else {
        s.len()
    }
}

/// Copies the first `i` bytes from `s` into a new buffer.
///
/// Set `triple` to `true` if triple capacity is needed.
///
/// # Safety
///
/// `i` must not exceed `s.len()`.
unsafe fn copy_new(s: &[u8], i: usize, triple: bool) -> Vec<u8> {
    let cap = calc_capacity(s, triple);
    let mut buf = Vec::with_capacity(cap);

    unsafe {
        // SAFETY: Since `i <= s.len() <= buf.capacity()`, `s` is valid
        // for reads of `i` bytes, and `buf` is valid for writes of `i` bytes.
        // Newly allocated `buf` cannot overlap with `s`.
        ptr::copy_nonoverlapping(s.as_ptr(), buf.as_mut_ptr(), i);
        // The first `i` bytes are now initialized so it's safe to set the length.
        buf.set_len(i);
    }
    buf
}

/// Copies the first `i` bytes from `s` into a buffer.
///
/// Set `triple` to `true` if triple capacity is needed.
///
/// # Safety
///
/// `i` must not exceed `s.len()`.
unsafe fn copy(s: &[u8], buf: &mut Vec<u8>, i: usize, triple: bool) {
    let cap = calc_capacity(s, triple);
    buf.reserve(cap);

    unsafe {
        let dst = buf.as_mut_ptr().add(buf.len());
        // SAFETY: Since `i <= s.len() <= buf.capacity() - buf.len()`, `s` is valid
        // for reads of `i` bytes, and `dst` is valid for writes of `i` bytes.
        // Mutable reference `buf` cannot overlap with immutable `s`.
        ptr::copy_nonoverlapping(s.as_ptr(), dst, i);
        // The appended `i` bytes are now initialized so it's safe to set the length.
        buf.set_len(buf.len() + i);
    }
}

/// Pushes a raw byte without checking bounds.
///
/// # Safety
///
/// `v.len() + 1` must not exceed `v.capacity()`.
unsafe fn push(v: &mut Vec<u8>, x: u8) {
    let len = v.len();
    debug_assert!(len < v.capacity());
    // SAFETY: The caller must ensure that the capacity is enough.
    unsafe {
        *v.as_mut_ptr().add(len) = x;
        v.set_len(len + 1);
    }
}

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
        None => return Cow::borrowed(unsafe { str::from_utf8_unchecked(s) }),
    };

    unsafe {
        // SAFETY: `i` cannot exceed `s.len()` since `i < s.len()`.
        let mut buf = copy_new(s, i, true);
        _encode(s, i, table, &mut buf);
        // SAFETY: The bytes should all be ASCII and thus valid UTF-8.
        Cow::owned(String::from_utf8_unchecked(buf))
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

/// Decodes a percent-encoded string assuming validity.
///
/// # Safety
///
/// This function does not check that the string is properly encoded.
/// Any invalid encoded octet in the string will result in undefined behavior.
pub unsafe fn decode_unchecked(s: &[u8]) -> Cow<'_, [u8]> {
    // Skip bytes that are not '%'.
    let i = match s.iter().position(|&x| x == b'%') {
        Some(i) => i,
        None => return Cow::borrowed(s),
    };
    // SAFETY: `i` cannot exceed `s.len()` since `i < s.len()`.
    let mut buf = unsafe { copy_new(s, i, false) };

    // SAFETY: The caller must ensure that the string is properly encoded.
    unsafe { _decode(s, i, &mut buf, false).unwrap() }
    Cow::owned(buf)
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

pub(super) fn decode(s: &[u8]) -> Result<Cow<'_, [u8]>> {
    // Skip bytes that are not '%'.
    let i = match s.iter().position(|&x| x == b'%') {
        Some(i) => i,
        None => return Ok(Cow::borrowed(s)),
    };
    // SAFETY: `i` cannot exceed `s.len()` since `i < s.len()`.
    let mut buf = unsafe { copy_new(s, i, false) };

    unsafe { _decode(s, i, &mut buf, true)? }
    Ok(Cow::owned(buf))
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

unsafe fn _decode(s: &[u8], mut i: usize, buf: &mut Vec<u8>, checked: bool) -> Result<()> {
    while i < s.len() {
        let x = s[i];
        if x == b'%' {
            let octet = if checked {
                if i + 2 >= s.len() {
                    err!(i, InvalidOctet);
                }
                // SAFETY: We have checked that `i + 2 < s.len()`.
                // Overflow should be impossible because we cannot have that large a slice.
                let (hi, lo) = unsafe { (*s.get_unchecked(i + 1), *s.get_unchecked(i + 2)) };

                match decode_octet(hi, lo) {
                    Some(o) => o,
                    None => err!(i, InvalidOctet),
                }
            } else {
                // SAFETY: The caller must ensure that the string is properly encoded.
                let (hi, lo) = unsafe { (*s.get_unchecked(i + 1), *s.get_unchecked(i + 2)) };
                decode_octet_unchecked(hi, lo)
            };

            // SAFETY: The output will never be longer than the input.
            unsafe { push(buf, octet) }
            i += 3;
        } else {
            // SAFETY: The output will never be longer than the input.
            unsafe { push(buf, x) }
            i += 1;
        }
    }
    Ok(())
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

pub(super) const fn validate_estr(s: &[u8]) -> bool {
    let mut i = 0;
    while i < s.len() {
        let x = s[i];
        if x == b'%' {
            if i + 2 >= s.len() {
                return false;
            }
            let (hi, lo) = (s[i + 1], s[i + 2]);

            if HEXDIG.get(hi) & HEXDIG.get(lo) == 0 {
                return false;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    true
}
