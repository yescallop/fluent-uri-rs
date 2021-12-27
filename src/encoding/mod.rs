/// Character tables from RFC 3986 and RFC 6874.
pub mod table;

#[macro_use]
pub(crate) mod macros;

pub(crate) mod raw;

use crate::ParseError;
use beef::Cow;
use std::{
    borrow,
    error::Error,
    fmt, hash,
    str::{self, Utf8Error},
};

pub use raw::decode_unchecked;

/// Encodes any characters in a byte sequence that are not allowed by the given mask.
///
/// # Panics
///
/// Panics if the table is not for encoding.
#[inline]
pub fn encode<'a, S: AsRef<[u8]> + ?Sized>(s: &'a S, table: &Table) -> Cow<'a, str> {
    assert!(table.allow_enc(), "table not for encoding");
    raw::encode(s.as_ref(), table)
}

/// Decodes a percent-encoded string.
#[inline]
pub fn decode(s: &str) -> Result<Cow<'_, [u8]>, ParseError> {
    raw::decode(s).map_err(|ptr| ParseError::from_raw(ptr, s))
}

/// Checks if all characters in a string are allowed by the given table.
#[inline]
pub fn validate(s: &str, table: &Table) -> Result<(), ParseError> {
    raw::validate(s.as_bytes(), table).map_err(|ptr| ParseError::from_raw(ptr, s))
}

/// Percent-encoded string slices.
#[derive(Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct EStr {
    inner: str,
}

impl AsRef<str> for EStr {
    #[inline]
    fn as_ref(&self) -> &str {
        &self.inner
    }
}

impl PartialEq<str> for EStr {
    #[inline]
    fn eq(&self, other: &str) -> bool {
        self.inner == *other
    }
}

impl<'a> fmt::Display for EStr {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Default for &EStr {
    #[inline]
    fn default() -> Self {
        // SAFETY: A empty str is valid as `EStr`.
        unsafe { EStr::new_unchecked("") }
    }
}

impl hash::Hash for EStr {
    #[inline]
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.inner.hash(state)
    }
}

impl borrow::Borrow<str> for &EStr {
    #[inline]
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl EStr {
    /// Converts a string slice to an `EStr` without checking that the string is properly encoded.
    ///
    /// # Safety
    ///
    /// The `decode` function assumes that the string is properly encoded,
    /// and parses the encoded octets without checking bounds or validating them.
    /// Any invalid encoded octet in the string will result in undefined behavior.
    // FIXME: Make this const after the feature `const_raw_ptr_deref` gets stabilized.
    #[inline]
    pub unsafe fn new_unchecked(s: &str) -> &EStr {
        // SAFETY: The caller must ensure that the string is properly encoded.
        unsafe { &*(s as *const str as *const EStr) }
    }

    /// Yields the underlying string slice.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.inner
    }

    /// Decodes the `EStr` as bytes.
    #[inline]
    pub fn decode(&self) -> Cow<'_, [u8]> {
        // SAFETY: An `EStr` may only be created through `new_unchecked`,
        // of which the caller must guarantee that the string is properly encoded.
        unsafe { decode_unchecked(self.inner.as_bytes()) }
    }

    /// Decodes the `EStr` and converts the decoded bytes to a string.
    ///
    /// An error is returned if the `EStr` contains any encoded sequence that is not valid UTF-8.
    pub fn decode_utf8(&self) -> Result<Cow<'_, str>, DecodeUtf8Error<'_>> {
        // FIXME: A (maybe) more efficient approach: only validating encoded sequences.
        let bytes = self.decode();
        if bytes.is_borrowed() {
            let bytes = bytes.unwrap_borrowed();
            match str::from_utf8(bytes) {
                Ok(s) => Ok(Cow::borrowed(s)),
                Err(e) => Err(DecodeUtf8Error {
                    bytes: Cow::borrowed(bytes),
                    error: e,
                }),
            }
        } else {
            match String::from_utf8(bytes.into_owned()) {
                Ok(s) => Ok(Cow::owned(s)),
                Err(e) => Err(DecodeUtf8Error {
                    error: e.utf8_error(),
                    bytes: Cow::owned(e.into_bytes()),
                }),
            }
        }
    }

    /// Splits the `EStr` on the occurrences of the specified delimiter.
    ///
    /// # Panics
    ///
    /// Panics if the delimiter is not a [reserved] character.
    ///
    /// [reserved]: https://datatracker.ietf.org/doc/html/rfc3986/#section-2.2
    ///
    /// # Examples
    ///
    /// ```
    /// use std::collections::HashMap;
    /// use fluent_uri::encoding::EStr;
    ///
    /// let s = "name=%E5%BC%A0%E4%B8%89&speech=%C2%A1Ol%C3%A9!";
    /// let map: HashMap<_, _> = unsafe { EStr::new_unchecked(s) }
    ///     .split('&')
    ///     .filter_map(|s| s.split_once('='))
    ///     .filter_map(|p| p.decode_utf8())
    ///     .collect();
    /// assert_eq!(map["name"], "张三");
    /// assert_eq!(map["speech"], "¡Olé!");
    /// ```
    #[inline]
    pub fn split(&self, delim: char) -> Split<'_> {
        assert!(
            delim.is_ascii() && table::RESERVED.contains(delim as u8),
            "splitting with non-reserved character"
        );

        Split {
            s: self.inner.as_bytes(),
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
    pub fn split_once(&self, delim: char) -> Option<EStrPair<'_>> {
        assert!(
            delim.is_ascii() && table::RESERVED.contains(delim as u8),
            "splitting with non-reserved character"
        );
        let bytes = self.inner.as_bytes();

        let i = chr(bytes, delim as u8)?;
        let (head, tail) = (&bytes[..i], &bytes[i + 1..]);
        // SAFETY: Splitting at a reserved character leaves valid percent-encoded UTF-8.
        unsafe { Some(EStrPair(EStr::from_bytes(head), EStr::from_bytes(tail))) }
    }

    /// Converts a byte slice into an `EStr` assuming validity.
    unsafe fn from_bytes(s: &[u8]) -> &EStr {
        // SAFETY: The caller must ensure that the byte slice is valid percent-encoded UTF-8.
        unsafe { &*(s as *const [u8] as *const EStr) }
    }
}

/// A pair of `EStr`s.
#[derive(Debug, Clone, Copy)]
pub struct EStrPair<'a>(pub &'a EStr, pub &'a EStr);

impl<'a> EStrPair<'a> {
    /// Yields the underlying pair of string slices.
    #[inline]
    pub fn as_strs(self) -> (&'a str, &'a str) {
        (self.0.as_str(), self.1.as_str())
    }

    /// Decodes the `EStr` pair as bytes.
    #[inline]
    pub fn decode(self) -> (Cow<'a, [u8]>, Cow<'a, [u8]>) {
        (self.0.decode(), self.1.decode())
    }

    /// Decodes the `EStr` and converts the decoded bytes to strings.
    ///
    /// `None` is returned if either `EStr` contains any encoded sequence that is not valid UTF-8.
    pub fn decode_utf8(self) -> Option<(Cow<'a, str>, Cow<'a, str>)> {
        self.0.decode_utf8().ok().zip(self.1.decode_utf8().ok())
    }
}

/// An error returned by [`EStr::decode_utf8`].
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
        // SAFETY: Splitting at a reserved character leaves valid percent-encoded UTF-8.
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
        // SAFETY: Splitting at a reserved character leaves valid percent-encoded UTF-8.
        Some(unsafe { EStr::from_bytes(res) })
    }
}

// Memchr wrappers with unreachable hints.
// A bunch of unsafe blocks can be avoided in this way.

use std::hint;

use self::table::Table;

pub(crate) fn chr(s: &[u8], b: u8) -> Option<usize> {
    memchr::memchr(b, s).map(|i| {
        if i >= s.len() {
            unsafe { hint::unreachable_unchecked() }
        }
        i
    })
}

pub(crate) fn rchr(s: &[u8], b: u8) -> Option<usize> {
    memchr::memrchr(b, s).map(|i| {
        if i >= s.len() {
            unsafe { hint::unreachable_unchecked() }
        }
        i
    })
}

pub(crate) fn chr_until(s: &[u8], b: u8, end: u8) -> Option<usize> {
    memchr::memchr2(b, end, s).and_then(|i| {
        if i >= s.len() {
            unsafe { hint::unreachable_unchecked() }
        }
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

        let EStrPair(k, v) = it.split_once('=').unwrap();
        assert_eq!(k, "id");
        assert_eq!(v, "3");

        let it = split.next().unwrap();
        assert_eq!(it, "name=%E5%BC%A0%E4%B8%89");
        assert_eq!(it.decode_utf8().unwrap(), "name=张三");

        let EStrPair(k, v) = it.split_once('=').unwrap();
        assert_eq!(k.decode_utf8().unwrap(), "name");
        assert_eq!(v.decode_utf8().unwrap(), "张三");
    }
}
