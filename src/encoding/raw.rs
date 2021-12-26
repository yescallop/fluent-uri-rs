use super::{
    chr,
    table::{Table, HEXDIG},
};
use std::{borrow::Cow, ptr, str};

pub(crate) type RawResult<T> = Result<T, *const u8>;

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

static OCTET_HI: &[u8; 256] = &gen_octet_table(true);
pub(crate) static OCTET_LO: &[u8; 256] = &gen_octet_table(false);

/// Decodes a percent-encoded octet assuming validity.
#[inline]
fn decode_octet_unchecked(hi: u8, lo: u8) -> u8 {
    OCTET_HI[hi as usize] | OCTET_LO[lo as usize]
}

/// Decodes a percent-encoded octet.
#[inline]
fn decode_octet(mut hi: u8, mut lo: u8) -> Option<u8> {
    hi = OCTET_HI[hi as usize];
    lo = OCTET_LO[lo as usize];
    if hi != 0xFF && lo != 0xFF {
        Some(hi | lo)
    } else {
        None
    }
}

/// Copies the first `i` bytes from `s` into a `Vec` and returns it.
///
/// Set `triple` to `true` if triple capacity is needed.
///
/// # Safety
///
/// `i` must not exceed `s.len()`.
#[inline]
unsafe fn copy(s: &[u8], i: usize, triple: bool) -> Vec<u8> {
    let mut cap = s.len();
    debug_assert!(i <= cap);
    if triple {
        if let Some(more) = cap.checked_mul(3) {
            cap = more;
        }
    }
    let mut v = Vec::with_capacity(cap);

    // SAFETY: Since `i <= s.len() <= v.capacity()`,
    // `s` is valid for reads of `i` bytes, and `v` is valid for writes of `i` bytes.
    // Newly allocated `v` cannot overlap with `s`.
    ptr::copy_nonoverlapping(s.as_ptr(), v.as_mut_ptr(), i);
    // The first `i` bytes are now initialized so it's safe to set the length.
    v.set_len(i);
    v
}

/// Pushes a raw byte without checking bounds.
///
/// # Safety
///
/// `v.len() + 1` must not exceed `v.capacity()`.
#[inline]
unsafe fn push(v: &mut Vec<u8>, x: u8) {
    let len = v.len();
    debug_assert!(len < v.capacity());
    *v.as_mut_ptr().add(len) = x;
    v.set_len(len + 1);
}

/// Pushes a percent-encoded byte without checking bounds.
///
/// # Safety
///
/// `v.len() + 3` must not exceed `v.capacity()`.
#[inline]
unsafe fn push_pct_encoded(v: &mut Vec<u8>, x: u8) {
    const HEX_DIGITS: &[u8; 16] = b"0123456789ABCDEF";

    let len = v.len();
    debug_assert!(len + 2 < v.capacity());
    let ptr = v.as_mut_ptr().add(len);

    let b = x as usize;
    *ptr = b'%';
    *ptr.add(1) = HEX_DIGITS[(b >> 4) & 15];
    *ptr.add(2) = HEX_DIGITS[b & 15];

    v.set_len(len + 3);
}

/// Encodes any characters in a byte sequence that are not allowed by the given mask.
pub fn encode<'a, S: AsRef<[u8]> + ?Sized>(s: &'a S, table: &Table) -> Cow<'a, str> {
    assert!(table.allow_enc(), "mask not for encoding");
    let s = s.as_ref();

    // Skip the allowed bytes.
    let mut i = match s.iter().position(|&x| !table.contains(x)) {
        Some(i) => i,
        // SAFETY: All bytes are checked to be less than 128 (ASCII).
        None => return Cow::Borrowed(unsafe { str::from_utf8_unchecked(s) }),
    };

    // SAFETY: `i` cannot exceed `s.len()` since `i < s.len()`.
    let mut res = unsafe { copy(s, i, true) };

    while i < s.len() {
        let x = s[i];
        // SAFETY: The maximum length of the output is triple that of the input.
        unsafe {
            if table.contains(x) {
                push(&mut res, x);
            } else {
                push_pct_encoded(&mut res, x);
            }
        }
        i += 1;
    }
    // SAFETY: The bytes should all be ASCII thus valid UTF-8.
    Cow::Owned(unsafe { String::from_utf8_unchecked(res) })
}

/// Decodes a percent-encoded string assuming validity.
///
/// # Safety
///
/// This function does not check that the string is properly encoded.
/// Any invalid encoded octet in the string will result in undefined behavior.
pub unsafe fn decode_unchecked(s: &[u8]) -> Cow<'_, [u8]> {
    // Skip bytes that are not '%'.
    let mut i = match chr(s, b'%') {
        Some(i) => i,
        None => return Cow::Borrowed(s),
    };

    let mut res = copy(s, i, false);
    let v = &mut res;
    let ptr = s.as_ptr();

    while i < s.len() {
        let x = *ptr.add(i);
        if x == b'%' {
            let (hi, lo) = (*ptr.add(i + 1), *ptr.add(i + 2));

            let octet = decode_octet_unchecked(hi, lo);

            push(v, octet);
            i += 2;
        } else {
            push(v, x);
        }
        i += 1;
    }
    Cow::Owned(res)
}

pub(super) fn decode(s: &str) -> RawResult<Cow<'_, [u8]>> {
    // Skip bytes that are not '%'.
    let mut i = match chr(s.as_bytes(), b'%') {
        Some(i) => i,
        None => return Ok(Cow::Borrowed(s.as_bytes())),
    };

    // SAFETY: `i` cannot exceed `s.len()` since `i < s.len()`.
    let mut res = unsafe { copy(s.as_bytes(), i, false) };
    let v = &mut res;
    let ptr = s.as_ptr();

    while i < s.len() {
        let cur = unsafe { ptr.add(i) };
        // SAFETY: Dereferencing is safe since `i < s.len()`.
        let x = unsafe { *cur };
        if x == b'%' {
            if i + 2 >= s.len() {
                return Err(cur);
            }
            // SAFETY: Dereferencing is safe since `i + 1 < i + 2 < s.len()`.
            let (hi, lo) = unsafe { (*ptr.add(i + 1), *ptr.add(i + 2)) };

            let octet = decode_octet(hi, lo).ok_or(cur)?;

            // SAFETY: The output will never be longer than the input.
            unsafe { push(v, octet) }
            i += 2;
        } else {
            // SAFETY: The output will never be longer than the input.
            unsafe { push(v, x) }
        }
        i += 1;
    }
    Ok(Cow::Owned(res))
}

pub(crate) fn validate(s: &[u8], table: &Table) -> RawResult<()> {
    if s.is_empty() {
        return Ok(());
    }

    if !table.allow_enc() {
        return validate_by(s, |&x| table.contains(x));
    }

    let ptr = s.as_ptr();
    let mut i = 0;

    while i < s.len() {
        let cur = unsafe { ptr.add(i) };
        // SAFETY: Dereferencing is safe since `i < s.len()`.
        let x = unsafe { *cur };
        if x == b'%' {
            if i + 2 >= s.len() {
                return Err(cur);
            }
            // SAFETY: Dereferencing is safe since `i + 1 < i + 2 < s.len()`.
            let (hi, lo) = unsafe { (*ptr.add(i + 1), *ptr.add(i + 2)) };

            if !HEXDIG.contains(hi) || !HEXDIG.contains(lo) {
                return Err(cur);
            }
        } else if !table.contains(x) {
            return Err(cur);
        }
        i += 1;
    }
    Ok(())
}

fn validate_by(s: &[u8], pred: impl Fn(&u8) -> bool) -> RawResult<()> {
    match s.iter().position(|b| !pred(b)) {
        Some(i) => err!(s, i),
        None => Ok(()),
    }
}

pub(crate) trait Validator {
    fn validate(self, s: &[u8]) -> RawResult<()>;
}

impl Validator for &Table {
    #[inline]
    fn validate(self, s: &[u8]) -> RawResult<()> {
        validate(s, &self)
    }
}

impl<T: Fn(&u8) -> bool> Validator for T {
    #[inline]
    fn validate(self, s: &[u8]) -> RawResult<()> {
        validate_by(s, self)
    }
}
