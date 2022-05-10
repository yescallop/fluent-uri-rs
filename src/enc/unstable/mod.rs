use std::borrow::Cow;

use super::{err, table::Table, Result};

mod imp;
pub use imp::*;

/// A percent-encoded, growable string.
pub mod estring;

mod internal {
    pub trait Buf {
        unsafe fn as_mut_vec(&mut self) -> &mut Vec<u8>;
    }

    impl Buf for Vec<u8> {
        #[inline]
        unsafe fn as_mut_vec(&mut self) -> &mut Vec<u8> {
            self
        }
    }

    impl Buf for String {
        #[inline]
        unsafe fn as_mut_vec(&mut self) -> &mut Vec<u8> {
            // SAFETY: The caller must not mess up the string.
            unsafe { self.as_mut_vec() }
        }
    }
}

/// Percent-encodes a byte sequence.
///
/// # Panics
///
/// Panics if the table is not for encoding.
#[inline]
pub fn encode<'a, S: AsRef<[u8]> + ?Sized>(s: &'a S, table: &Table) -> Cow<'a, str> {
    assert!(table.allows_enc(), "table not for encoding");
    imp::encode(s.as_ref(), table)
}

/// Percent-encodes a byte sequence to a buffer.
///
/// The buffer may either be a [`String`] or a [`Vec<u8>`].
///
/// # Panics
///
/// Panics if the table is not for encoding.
#[inline]
pub fn encode_to<'a, S: AsRef<[u8]> + ?Sized, B: internal::Buf>(
    s: &S,
    table: &Table,
    buf: &'a mut B,
) {
    assert!(table.allows_enc(), "table not for encoding");
    // SAFETY: The encoded bytes are valid UTF-8.
    let buf = unsafe { buf.as_mut_vec() };
    imp::encode_to(s.as_ref(), table, buf)
}

/// Decodes a percent-encoded string.
#[inline]
pub fn decode<S: AsRef<[u8]> + ?Sized>(s: &S) -> Result<Cow<'_, [u8]>> {
    imp::decode(s.as_ref())
}

/// Decodes a percent-encoded string with a buffer.
///
/// If the string needs no decoding, this function returns `Ok(None)`
/// and no bytes will be appended to the buffer.
#[inline]
pub fn decode_with<'a, S: AsRef<[u8]> + ?Sized>(
    s: &S,
    buf: &'a mut Vec<u8>,
) -> Result<Option<&'a [u8]>> {
    imp::decode_with(s.as_ref(), buf)
}

/// Checks if all characters in a string are allowed by the given table.
#[inline]
pub fn validate<S: AsRef<[u8]> + ?Sized>(s: &S, table: &Table) -> Result<()> {
    let s = s.as_ref();
    if table.allows_enc() {
        imp::validate_enc(s, table)
    } else {
        match s.iter().position(|&x| !table.allows(x)) {
            Some(i) => err!(i, UnexpectedChar),
            None => Ok(()),
        }
    }
}
