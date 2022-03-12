/// Character tables from RFC 3986 and RFC 6874.
pub mod table;

#[macro_use]
pub(crate) mod macros;

pub(crate) mod raw;

use crate::ParseError;
use beef::Cow;
use std::{
    borrow::{self, Cow::*},
    fmt, hash, str,
    string::FromUtf8Error,
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
    raw::decode(s).map_err(|(ptr, kind)| ParseError::from_raw(s, ptr, kind))
}

/// Checks if all characters in a string are allowed by the given table.
#[inline]
pub fn validate(s: &str, table: &Table) -> Result<(), ParseError> {
    raw::validate(s.as_bytes(), table).map_err(|(ptr, kind)| ParseError::from_raw(s, ptr, kind))
}

/// Percent-encoded string slices.
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

impl PartialEq<EStr> for EStr {
    #[inline]
    fn eq(&self, other: &EStr) -> bool {
        self.inner == other.inner
    }
}

impl PartialEq<str> for EStr {
    #[inline]
    fn eq(&self, other: &str) -> bool {
        self.inner == *other
    }
}

impl Eq for EStr {}

impl fmt::Debug for EStr {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), f)
    }
}

impl fmt::Display for EStr {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.as_str(), f)
    }
}

impl Default for &EStr {
    #[inline]
    fn default() -> Self {
        EStr::EMPTY
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
    /// An empty `EStr`.
    pub const EMPTY: &'static EStr = unsafe {
        // SAFETY: A empty str is valid as `EStr`.
        EStr::new_unchecked("")
    };

    /// Converts a string slice to an `EStr`.
    ///
    /// # Panics
    ///
    /// Panics if the string is not properly encoded.
    pub const fn new(s: &str) -> &EStr {
        if raw::validate_const(s.as_bytes()).is_ok() {
            // SAFETY: We have done the validation.
            unsafe { EStr::new_unchecked(s) }
        } else {
            panic!("invalid percent-encoded string");
        }
    }

    /// Converts a string slice to an `EStr` without checking that the string is properly encoded.
    ///
    /// # Safety
    ///
    /// The `decode` function assumes that the string is properly encoded,
    /// and parses the encoded octets without checking bounds or validating them.
    /// Any invalid encoded octet in the string will result in undefined behavior.
    #[inline]
    pub const unsafe fn new_unchecked(s: &str) -> &EStr {
        // SAFETY: The caller must ensure that the string is properly encoded.
        unsafe { &*(s as *const str as *const EStr) }
    }

    /// Converts a byte slice into an `EStr` assuming validity.
    // This function should be inlined since it is called by inlined public functions.
    #[inline]
    unsafe fn from_bytes(s: &[u8]) -> &EStr {
        // SAFETY: The caller must ensure that the byte slice is valid percent-encoded UTF-8.
        unsafe { &*(s as *const [u8] as *const EStr) }
    }

    /// Yields the underlying string slice.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.inner
    }

    /// Decodes the `EStr`.
    #[inline]
    pub fn decode(&self) -> Decode<'_> {
        // SAFETY: An `EStr` may only be created through `new_unchecked`,
        // of which the caller must guarantee that the string is properly encoded.
        Decode(unsafe { decode_unchecked(self.inner.as_bytes()) })
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
    /// let s = "name=%E5%BC%A0%E4%B8%89&speech=%C2%A1Ol%C3%A9%21";
    /// let map: HashMap<_, _> = EStr::new(s)
    ///     .split('&')
    ///     .filter_map(|s| s.split_once('='))
    ///     .map(|(k, v)| (k.decode(), v.decode()))
    ///     .filter_map(|(k, v)| k.into_utf8().ok().zip(v.into_utf8().ok()))
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
    pub fn split_once(&self, delim: char) -> Option<(&EStr, &EStr)> {
        assert!(
            delim.is_ascii() && table::RESERVED.contains(delim as u8),
            "splitting with non-reserved character"
        );
        let bytes = self.inner.as_bytes();

        let i = chr(bytes, delim as u8)?;
        let (head, tail) = (&bytes[..i], &bytes[i + 1..]);
        // SAFETY: Splitting at a reserved character leaves valid percent-encoded UTF-8.
        unsafe { Some((EStr::from_bytes(head), EStr::from_bytes(tail))) }
    }
}

/// A wrapper for decoded bytes.
pub struct Decode<'a>(Cow<'a, [u8]>);

impl<'a> Decode<'a> {
    /// Returns a reference to the decoded bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Yields the underlying decoded bytes.
    #[inline]
    pub fn into_bytes(self) -> Cow<'a, [u8]> {
        self.0
    }

    /// Converts the decoded bytes to a string.
    ///
    /// An error is returned if the decoded bytes are not valid UTF-8.
    #[inline]
    pub fn into_utf8(self) -> Result<Cow<'a, str>, FromUtf8Error> {
        // FIXME: A (maybe) more efficient approach: only validating encoded sequences.
        if self.0.is_borrowed() {
            let bytes = self.0.unwrap_borrowed();
            // SAFETY: If the bytes are borrowed, they must be valid UTF-8.
            Ok(Cow::borrowed(unsafe { str::from_utf8_unchecked(bytes) }))
        } else {
            String::from_utf8(self.0.into_owned()).map(Cow::owned)
        }
    }

    /// Converts the decoded bytes to a string lossily.
    #[inline]
    pub fn into_utf8_lossy(self) -> Cow<'a, str> {
        if self.0.is_borrowed() {
            let bytes = self.0.unwrap_borrowed();
            // SAFETY: If the bytes are borrowed, they must be valid UTF-8.
            Cow::borrowed(unsafe { str::from_utf8_unchecked(bytes) })
        } else {
            let bytes = self.0.into_owned();
            Cow::owned(match String::from_utf8_lossy(&bytes) {
                // SAFETY: If a borrowed string slice is returned, the bytes must be valid UTF-8.
                Borrowed(_) => unsafe { String::from_utf8_unchecked(bytes) },
                Owned(s) => s,
            })
        }
    }

    /// Converts the decoded bytes to a string assuming validity.
    ///
    /// # Safety
    ///
    /// The decoded bytes must be valid UTF-8.
    #[inline]
    pub unsafe fn into_utf8_unchecked(self) -> Cow<'a, str> {
        if self.0.is_borrowed() {
            let bytes = self.0.unwrap_borrowed();
            // SAFETY: If the bytes are borrowed, they must be valid UTF-8.
            Cow::borrowed(unsafe { str::from_utf8_unchecked(bytes) })
        } else {
            let bytes = self.0.into_owned();
            // SAFETY: The caller must ensure that the decoded bytes are valid UTF-8.
            Cow::owned(unsafe { String::from_utf8_unchecked(bytes) })
        }
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
        let res = match take!(rev, tail, self.s, self.delim) {
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

// This function should be inlined since it is called by an inlined public function.
#[inline]
pub(crate) fn chr(s: &[u8], b: u8) -> Option<usize> {
    memchr::memchr(b, s).map(|i| {
        if i >= s.len() {
            unsafe { hint::unreachable_unchecked() }
        }
        i
    })
}

// This function should be inlined since it is called by an inlined public function.
#[inline]
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
    fn enc_dec_validate() {
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

        // We used to use slot 0 to indicate that percent-encoded octets are allowed,
        // which was totally wrong since it just allows zero bytes. Glad we fixed it.
        assert!(validate("\0", QUERY_FRAGMENT).is_err());
    }

    #[test]
    fn split() {
        let s = EStr::new("id=3&name=%E5%BC%A0%E4%B8%89");
        let mut split = s.split('&');

        let it = split.next().unwrap();
        assert_eq!(it, "id=3");
        assert_eq!(it.decode().as_bytes(), b"id=3");
        assert_eq!(it.decode().into_utf8().as_deref(), Ok("id=3"));

        let (k, v) = it.split_once('=').unwrap();
        assert_eq!(k, "id");
        assert_eq!(v, "3");

        let it = split.next().unwrap();
        assert_eq!(it, "name=%E5%BC%A0%E4%B8%89");
        assert_eq!(it.decode().into_utf8().unwrap(), "name=张三");

        let (k, v) = it.split_once('=').unwrap();
        assert_eq!(k.decode().into_utf8().unwrap(), "name");
        assert_eq!(v.decode().into_utf8().unwrap(), "张三");
    }
}
