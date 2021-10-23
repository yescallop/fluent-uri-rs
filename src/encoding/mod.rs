/// Character tables from RFC 3986 and RFC 6874.
pub mod table;

#[macro_use]
pub(crate) mod macros;

pub(crate) mod raw;

use crate::ParseError;
use std::{
    borrow::Cow,
    error::Error,
    fmt,
    str::{self, Utf8Error},
};

pub use raw::{decode_unchecked, encode};

/// Decodes a percent-encoded string.
#[inline]
pub fn decode(s: &str) -> Result<Cow<'_, [u8]>, ParseError> {
    raw::decode(s).map_err(|ptr| unsafe { ParseError::from_raw(ptr, s) })
}

/// Checks if all characters in the string are in the given table.
#[inline]
pub fn validate(s: &str, table: &Table) -> Result<(), ParseError> {
    raw::validate(s.as_bytes(), table).map_err(|ptr| unsafe { ParseError::from_raw(ptr, s) })
}

/// Percent-encoded string slices.
#[derive(Debug, PartialEq, Eq)]
pub struct EStr {
    inner: [u8],
}

impl AsRef<str> for EStr {
    #[inline]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl PartialEq<str> for EStr {
    #[inline]
    fn eq(&self, other: &str) -> bool {
        &self.inner == other.as_bytes()
    }
}

impl<'a> fmt::Display for EStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl EStr {
    /// Converts a string slice to an `EStr` without checking that all
    /// percent-encoded octets in the string are valid.
    ///
    /// # Safety
    ///
    /// The `decode` function assumes that the string is properly encoded,
    /// and parses the encoded octets without checking bounds or validating them.
    /// Any invalid encoded octet in the string will result in undefined behavior.
    #[inline]
    pub unsafe fn new_unchecked(s: &str) -> &EStr {
        &*(s as *const str as *const EStr)
    }

    /// Yields the underlying string slice.
    #[inline]
    pub fn as_str(&self) -> &str {
        // SAFETY: An `EStr` may only be created through `new_unchecked`,
        // of which the caller must guarantee that the string is properly encoded.
        unsafe { str::from_utf8_unchecked(&self.inner) }
    }

    /// Decodes the `EStr` as bytes.
    #[inline]
    pub fn decode(&self) -> Cow<'_, [u8]> {
        // SAFETY: An `EStr` may only be created through `new_unchecked`,
        // of which the caller must guarantee that the string is properly encoded.
        unsafe { decode_unchecked(&self.inner) }
    }

    /// Decodes the `EStr` and converts the decoded bytes to a string.
    #[inline]
    pub fn decode_utf8(&self) -> Result<Cow<'_, str>, DecodeUtf8Error<'_>> {
        // FIXME: A (maybe) more efficient approach: only validating encoded sequences.
        let bytes = self.decode();
        match bytes {
            Cow::Borrowed(v) => match str::from_utf8(v) {
                Ok(s) => Ok(Cow::Borrowed(s)),
                Err(error) => Err(DecodeUtf8Error { bytes, error }),
            },
            Cow::Owned(v) => match String::from_utf8(v) {
                Ok(s) => Ok(Cow::Owned(s)),
                Err(e) => Err(DecodeUtf8Error {
                    error: e.utf8_error(),
                    bytes: Cow::Owned(e.into_bytes()),
                }),
            },
        }
    }

    /// Splits the `EStr` on the occurrences of the specified delimiter.
    ///
    /// # Panics
    ///
    /// Panics if the delimiter is not a [reserved] character.
    ///
    /// [reserved]: https://datatracker.ietf.org/doc/html/rfc3986/#section-2.2
    #[inline]
    pub fn split(&self, delim: char) -> Split<'_> {
        assert!(
            delim.is_ascii() && table::RESERVED.contains(delim as u8),
            "splitting with non-reserved character"
        );

        Split {
            s: &self.inner,
            delim: delim as u8,
            finished: false,
        }
    }

    /// Splits the `EStr` on the first occurrence of the specified delimiter and
    /// returns prefix before delimiter and suffix after delimiter.
    ///
    /// # Panics
    ///
    /// Panics if the delimiter is not a [reserved] character.
    ///
    /// [reserved]: https://datatracker.ietf.org/doc/html/rfc3986/#section-2.2
    #[inline]
    pub fn split_once(&self, delim: char) -> Option<(&EStr, &EStr)> {
        assert!(
            delim.is_ascii() && table::RESERVED.contains(delim as u8),
            "splitting with non-reserved character"
        );

        let i = chr(&self.inner, delim as u8)?;
        let (head, tail) = (&self.inner[..i], &self.inner[i + 1..]);
        // SAFETY: Splitting at an ASCII character leaves valid UTF-8.
        unsafe { Some((EStr::from_bytes(head), EStr::from_bytes(tail))) }
    }

    #[inline]
    unsafe fn from_bytes(s: &[u8]) -> &EStr {
        &*(s as *const [u8] as *const EStr)
    }
}

/// An error returned when attempting to call [`decode_utf8`] on an `EStr`
/// that contains any encoded sequence that is not valid UTF-8.
///
/// [`decode_utf8`]: EStr::decode_utf8
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DecodeUtf8Error<'a> {
    bytes: Cow<'a, [u8]>,
    error: Utf8Error,
}

impl<'a> DecodeUtf8Error<'a> {
    /// Returns a slice of bytes that were attempted to convert to a `Cow<str>`.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the bytes that were attempted to convert to a `Cow<str>`.
    #[inline]
    pub fn into_bytes(self) -> Cow<'a, [u8]> {
        self.bytes
    }

    /// Returns the underlying `Utf8Error`.
    #[inline]
    pub fn utf8_error(&self) -> Utf8Error {
        self.error
    }
}

impl<'a> Error for DecodeUtf8Error<'a> {}

impl<'a> fmt::Display for DecodeUtf8Error<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.error)
    }
}

/// An iterator over substrings of an `EStr` separated by a delimiter.
pub struct Split<'a> {
    s: &'a [u8],
    delim: u8,
    finished: bool,
}

impl<'a> Iterator for Split<'a> {
    type Item = &'a EStr;

    #[inline]
    fn next(&mut self) -> Option<&'a EStr> {
        if self.finished {
            return None;
        }
        let res = match take!(head, self.s, self.delim) {
            Some(x) => x,
            None => {
                self.finished = true;
                self.s
            }
        };
        // SAFETY: Splitting at an ASCII character leaves valid UTF-8.
        Some(unsafe { EStr::from_bytes(res) })
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.finished {
            (0, Some(0))
        } else {
            (1, Some(self.s.len() + 1))
        }
    }
}

impl<'a> DoubleEndedIterator for Split<'a> {
    #[inline]
    fn next_back(&mut self) -> Option<&'a EStr> {
        if self.finished {
            return None;
        }
        let res = match take!(r, tail, self.s, self.delim) {
            Some(x) => x,
            None => {
                self.finished = true;
                self.s
            }
        };
        // SAFETY: Splitting at an ASCII character leaves valid UTF-8.
        Some(unsafe { EStr::from_bytes(res) })
    }
}

// Memchr wrappers with unreachable hints.
// A bunch of unsafe blocks can be avoided in this way.
//
// FIXME: Due to some unknown reason, unreachable hints here would actually
// cause regression in performance.

// use std::hint;

use self::table::Table;

#[inline]
pub(crate) fn chr(s: &[u8], b: u8) -> Option<usize> {
    memchr::memchr(b, s).map(|i| {
        // if i >= s.len() {
        //     unsafe { hint::unreachable_unchecked() }
        // }
        i
    })
}

#[inline]
pub(crate) fn rchr(s: &[u8], b: u8) -> Option<usize> {
    memchr::memrchr(b, s).map(|i| {
        // if i >= s.len() {
        //     unsafe { hint::unreachable_unchecked() }
        // }
        i
    })
}

#[inline]
pub(crate) fn chr_until(s: &[u8], b: u8, end: u8) -> Option<usize> {
    memchr::memchr2(b, end, s).and_then(|i| {
        // if i >= s.len() {
        //     unsafe { hint::unreachable_unchecked() }
        // }
        if s[i] == b {
            Some(i)
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{table::*, *};

    #[test]
    fn enc_dec() {
        // TODO: Fuzz test
        let raw = "te😃a 测1`~!@试#$%st^&+=";
        let s = encode(raw, QUERY_FRAGMENT);
        assert_eq!(
            "te%F0%9F%98%83a%20%E6%B5%8B1%60~!@%E8%AF%95%23$%25st%5E&+=",
            s
        );
        assert!(validate(&s, QUERY_FRAGMENT).is_ok());
        assert_eq!(Ok(raw.as_bytes()), decode(&s).as_deref());
        assert_eq!(raw.as_bytes(), unsafe { &*decode_unchecked(s.as_bytes()) });

        assert_eq!(Ok(b"\x2d\xe6\xb5" as _), decode("%2D%E6%B5").as_deref());

        let s = "%2d%";
        assert_eq!(3, decode(s).unwrap_err().index());
    }

    #[test]
    fn split() {
        let s = "id=3&name=%E5%BC%A0%E4%B8%89";
        let s = unsafe { EStr::new_unchecked(s) };
        let mut split = s.split('&');

        let it = split.next().unwrap();
        assert_eq!(it, "id=3");
        assert_eq!(it.decode(), b"id=3" as &[u8]);
        assert_eq!(it.decode_utf8().as_deref(), Ok("id=3"));

        let (k, v) = it.split_once('=').unwrap();
        assert_eq!(k, "id");
        assert_eq!(v, "3");

        let it = split.next().unwrap();
        assert_eq!(it, "name=%E5%BC%A0%E4%B8%89");
        assert_eq!(it.decode_utf8().unwrap(), "name=张三");

        let (k, v) = it.split_once('=').unwrap();
        assert_eq!(k.decode_utf8().unwrap(), "name");
        assert_eq!(v.decode_utf8().unwrap(), "张三");
    }
}
