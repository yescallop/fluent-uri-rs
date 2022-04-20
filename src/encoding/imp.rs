use crate::Result;

use super::{err, table::HEXDIG};
use std::ptr;

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
pub(crate) unsafe fn copy_new(s: &[u8], i: usize, triple: bool) -> Vec<u8> {
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
pub(crate) unsafe fn copy(s: &[u8], buf: &mut Vec<u8>, i: usize, triple: bool) {
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
pub(crate) unsafe fn push(v: &mut Vec<u8>, x: u8) {
    let len = v.len();
    debug_assert!(len < v.capacity());
    // SAFETY: The caller must ensure that the capacity is enough.
    unsafe {
        *v.as_mut_ptr().add(len) = x;
        v.set_len(len + 1);
    }
}

/// Decodes a percent-encoded string assuming validity.
///
/// # Safety
///
/// This function does not check that the string is properly encoded.
/// Any invalid encoded octet in the string will result in undefined behavior.
pub unsafe fn decode_unchecked(s: &[u8]) -> Option<Vec<u8>> {
    // Skip bytes that are not '%'.
    let i = match s.iter().position(|&x| x == b'%') {
        Some(i) => i,
        None => return None,
    };
    // SAFETY: `i` cannot exceed `s.len()` since `i < s.len()`.
    let mut buf = unsafe { copy_new(s, i, false) };

    // SAFETY: The caller must ensure that the string is properly encoded.
    unsafe { _decode(s, i, &mut buf, false).unwrap() }
    Some(buf)
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

pub(crate) unsafe fn _decode(
    s: &[u8],
    mut i: usize,
    buf: &mut Vec<u8>,
    checked: bool,
) -> Result<()> {
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

/// Decodes a percent-encoded string in-place assuming validity.
///
/// Returns the length of decoded bytes to the left.
///
/// # Safety
///
/// This function does not check that the string is properly encoded.
/// Any invalid encoded octet in the string will result in undefined behavior.
pub unsafe fn decode_in_place_unchecked(s: &mut [u8]) -> usize {
    // Skip bytes that are not '%'.
    let mut i = match s.iter().position(|&x| x == b'%') {
        Some(i) => i,
        None => return s.len(),
    };
    let mut dst = i;

    while i < s.len() {
        let x = s[i];
        let octet = if x == b'%' {
            // SAFETY: The caller must ensure that the string is properly encoded.
            let (hi, lo) = unsafe { (*s.get_unchecked(i + 1), *s.get_unchecked(i + 2)) };
            i += 3;
            decode_octet_unchecked(hi, lo)
        } else {
            i += 1;
            x
        };
        // SAFETY: `dst <= i < len` holds.
        unsafe { *s.get_unchecked_mut(dst) = octet }
        dst += 1;
    }
    dst
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub const RAW: &[u8] = "te😃a 测1`~!@试#$%st^&+=".as_bytes();
    pub const ENCODED: &[u8] = b"te%F0%9F%98%83a%20%E6%B5%8B1%60~!@%E8%AF%95%23$%25st%5E&+=";

    #[test]
    fn dec_unchecked() {
        assert_eq!(Some(RAW), unsafe { decode_unchecked(ENCODED).as_deref() });

        let mut buf = Vec::new();
        assert_eq!(Some(RAW), unsafe {
            decode_with_unchecked(ENCODED, &mut buf)
        });
        assert_eq!(buf, RAW);
    }
}
