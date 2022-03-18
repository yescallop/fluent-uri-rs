use crate::{Result, SyntaxError, SyntaxErrorKind::*};

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

static HEX_TABLE: &[u8; 512] = &gen_hex_table();

/// Copies the first `i` bytes from `s` into a `Vec` and returns it.
///
/// Set `triple` to `true` if triple capacity is needed.
///
/// # Safety
///
/// `i` must not exceed `s.len()`.
unsafe fn copy(s: &[u8], i: usize, triple: bool) -> Vec<u8> {
    let mut cap = s.len();
    debug_assert!(i <= cap);
    if triple {
        cap = match cap.checked_mul(3) {
            Some(cap) => cap,
            // We must panic here since an insufficient capacity may cause UB.
            None => panic!("capacity overflow"),
        };
    }
    let mut v = Vec::with_capacity(cap);

    unsafe {
        // SAFETY: Since `i <= s.len() <= v.capacity()`, `s` is valid for reads
        // of `i` bytes, and `v` is valid for writes of `i` bytes.
        // Newly allocated `v` cannot overlap with `s`.
        ptr::copy_nonoverlapping(s.as_ptr(), v.as_mut_ptr(), i);
        // The first `i` bytes are now initialized so it's safe to set the length.
        v.set_len(i);
    }
    v
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

pub(crate) fn encode<'a>(s: &'a [u8], table: &Table) -> Cow<'a, str> {
    // Skip the allowed bytes.
    let mut i = match s.iter().position(|&x| !table.contains(x)) {
        Some(i) => i,
        // SAFETY: All bytes are checked to be less than 128 (ASCII).
        None => return Cow::borrowed(unsafe { str::from_utf8_unchecked(s) }),
    };

    // SAFETY: `i` cannot exceed `s.len()` since `i < s.len()`.
    let mut res = unsafe { copy(s, i, true) };

    while i < s.len() {
        let x = s[i];
        // SAFETY: The maximum output length is triple the input length.
        unsafe {
            if table.contains(x) {
                push(&mut res, x);
            } else {
                push_pct_encoded(&mut res, x);
            }
        }
        i += 1;
    }
    // SAFETY: The bytes should all be ASCII and thus valid UTF-8.
    Cow::owned(unsafe { String::from_utf8_unchecked(res) })
}

/// Decodes a percent-encoded string assuming validity.
///
/// # Safety
///
/// This function does not check that the string is properly encoded.
/// Any invalid encoded octet in the string will result in undefined behavior.
pub unsafe fn decode_unchecked(s: &[u8]) -> Cow<'_, [u8]> {
    // Skip bytes that are not '%'.
    let mut i = match s.iter().position(|&x| x == b'%') {
        Some(i) => i,
        None => return Cow::borrowed(s),
    };

    // SAFETY: `i` cannot exceed `s.len()` since `i < s.len()`.
    let mut res = unsafe { copy(s, i, false) };
    let ptr = s.as_ptr();

    while i < s.len() {
        // SAFETY: We have checked `i < s.len()`.
        let x = unsafe { *ptr.add(i) };
        if x == b'%' {
            // SAFETY: The caller must ensure that the string is properly encoded.
            let (hi, lo) = unsafe { (*ptr.add(i + 1), *ptr.add(i + 2)) };

            let octet = decode_octet_unchecked(hi, lo);

            // SAFETY: The output will never be longer than the input.
            unsafe { push(&mut res, octet) }
            i += 3;
        } else {
            // SAFETY: The output will never be longer than the input.
            unsafe { push(&mut res, x) }
            i += 1;
        }
    }
    Cow::owned(res)
}

/// Decodes a percent-encoded string.
pub fn decode(s: &str) -> Result<Cow<'_, [u8]>> {
    // Skip bytes that are not '%'.
    let mut i = match s.bytes().position(|x| x == b'%') {
        Some(i) => i,
        None => return Ok(Cow::borrowed(s.as_bytes())),
    };
    let s = s.as_bytes();

    // SAFETY: `i` cannot exceed `s.len()` since `i < s.len()`.
    let mut res = unsafe { copy(s, i, false) };

    while i < s.len() {
        let x = s[i];
        if x == b'%' {
            let (hi, lo) = match (s.get(i + 1), s.get(i + 2)) {
                (Some(&hi), Some(&lo)) => (hi, lo),
                _ => err!(i, InvalidOctet),
            };

            let octet = match decode_octet(hi, lo) {
                Some(o) => o,
                None => err!(i, InvalidOctet),
            };

            // SAFETY: The output will never be longer than the input.
            unsafe { push(&mut res, octet) }
            i += 3;
        } else {
            // SAFETY: The output will never be longer than the input.
            unsafe { push(&mut res, x) }
            i += 1;
        }
    }
    Ok(Cow::owned(res))
}

/// Checks if all characters in a string are allowed by the given table.
pub fn validate(s: &str, table: &Table) -> Result<()> {
    let s = s.as_bytes();
    if s.is_empty() {
        return Ok(());
    }

    if !table.allow_enc() {
        match s.iter().position(|&x| !table.contains(x)) {
            Some(i) => err!(i, UnexpectedChar),
            None => return Ok(()),
        }
    }

    let mut i = 0;
    while i < s.len() {
        let x = s[i];
        if x == b'%' {
            match (s.get(i + 1), s.get(i + 2)) {
                (Some(&hi), Some(&lo)) if HEXDIG.get(hi) & HEXDIG.get(lo) != 0 => (),
                _ => err!(i, InvalidOctet),
            }
            i += 3;
        } else {
            if !table.contains(x) {
                err!(i, UnexpectedChar);
            }
            i += 1;
        }
    }
    Ok(())
}

pub(crate) const fn validate_const(s: &[u8]) -> bool {
    if s.is_empty() {
        return true;
    }

    let mut i = 0;
    while i < s.len() {
        let x = s[i];
        if x == b'%' {
            if i + 2 >= s.len() {
                return false;
            }
            let (hi, lo) = (s[i + 1], s[i + 2]);

            if !hi.is_ascii_hexdigit() || !lo.is_ascii_hexdigit() {
                return false;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    true
}
