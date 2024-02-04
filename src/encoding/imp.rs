use super::table;
use core::ptr;

pub(super) const fn validate_estr(s: &[u8]) -> bool {
    let mut i = 0;
    while i < s.len() {
        let x = s[i];
        if x == b'%' {
            if i + 2 >= s.len() {
                return false;
            }
            let (hi, lo) = (s[i + 1], s[i + 2]);

            if table::HEXDIG.get(hi) & table::HEXDIG.get(lo) == 0 {
                return false;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    true
}

/// Copies the first `i` bytes from `s` into a new buffer.
///
/// # Safety
///
/// `i` must not exceed `s.len()`.
unsafe fn copy_new(s: &[u8], i: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(s.len());

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

const fn gen_octet_table(hi: bool) -> [u8; 256] {
    let mut out = [0xFF; 256];
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

/// Decodes a percent-encoded octet assuming validity.
fn decode_octet_unchecked(hi: u8, lo: u8) -> u8 {
    OCTET_TABLE_HI[hi as usize] | OCTET_TABLE_LO[lo as usize]
}

/// Pushes a raw byte without checking bounds.
///
/// # Safety
///
/// `v.len() + 1` must not exceed `v.capacity()`.
unsafe fn push(v: &mut Vec<u8>, x: u8) {
    debug_assert!(v.len() < v.capacity());
    // SAFETY: The caller must ensure that the capacity is enough.
    unsafe {
        *v.as_mut_ptr().add(v.len()) = x;
        v.set_len(v.len() + 1);
    }
}

/// Decodes a percent-encoded string assuming validity.
///
/// # Safety
///
/// This function does not check that the string is properly encoded.
/// Any invalid encoded octet in the string will result in undefined behavior.
pub(super) unsafe fn decode_unchecked(s: &[u8]) -> Option<Vec<u8>> {
    // Skip bytes that are not '%'.
    let mut i = match s.iter().position(|&x| x == b'%') {
        Some(i) => i,
        None => return None,
    };
    // SAFETY: `i` cannot exceed `s.len()`.
    let mut buf = unsafe { copy_new(s, i) };

    while i < s.len() {
        let x = s[i];
        if x == b'%' {
            // SAFETY: The caller must ensure that the string is properly encoded.
            let (hi, lo) = unsafe { (*s.get_unchecked(i + 1), *s.get_unchecked(i + 2)) };
            let octet = decode_octet_unchecked(hi, lo);

            // SAFETY: The output will never be longer than the input.
            unsafe { push(&mut buf, octet) }
            i += 3;
        } else {
            // SAFETY: The output will never be longer than the input.
            unsafe { push(&mut buf, x) }
            i += 1;
        }
    }
    Some(buf)
}
