//! Percent-encoding utilities.

pub mod encoder;
mod estring;
pub(crate) mod imp;
pub mod table;

use alloc::{
    borrow::Cow,
    string::{FromUtf8Error, String},
    vec::Vec,
};
use core::{cmp::Ordering, fmt, hash, iter::FusedIterator, str};
use ref_cast::{ref_cast_custom, RefCastCustom};

pub use estring::EString;

/// An error occurred when validating percent-encoded strings.
#[derive(Clone, Copy, Debug)]
pub struct EncodingError {
    index: usize,
}

impl fmt::Display for EncodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid percent-encoded octet at index {}", self.index)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for EncodingError {}

/// Percent-encoded string slices.
#[derive(RefCastCustom)]
#[repr(transparent)]
pub struct EStr {
    inner: str,
}

impl AsRef<EStr> for EStr {
    #[inline]
    fn as_ref(&self) -> &EStr {
        self
    }
}

impl AsRef<str> for EStr {
    #[inline]
    fn as_ref(&self) -> &str {
        &self.inner
    }
}

impl AsRef<[u8]> for EStr {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.inner.as_bytes()
    }
}

impl PartialEq for EStr {
    #[inline]
    fn eq(&self, other: &EStr) -> bool {
        self.inner == other.inner
    }
}

impl PartialEq<str> for EStr {
    #[inline]
    fn eq(&self, other: &str) -> bool {
        &self.inner == other
    }
}

impl PartialEq<EStr> for str {
    #[inline]
    fn eq(&self, other: &EStr) -> bool {
        self == &other.inner
    }
}

impl Eq for EStr {}

impl hash::Hash for EStr {
    #[inline]
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.inner.hash(state)
    }
}

/// Implements comparison operations on `EStr`s.
///
/// `EStr`s are compared [lexicographically](Ord#lexicographical-comparison) by their byte values.
/// Normalization is **not** performed prior to comparison.
impl PartialOrd for EStr {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Implements ordering on `EStr`s.
///
/// `EStr`s are ordered [lexicographically](Ord#lexicographical-comparison) by their byte values.
/// Normalization is **not** performed prior to ordering.
impl Ord for EStr {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.inner.cmp(&other.inner)
    }
}

impl Default for &EStr {
    /// Creates an empty `EStr`.
    #[inline]
    fn default() -> Self {
        EStr::new_validated("")
    }
}

impl EStr {
    /// Converts a string slice to `EStr`.
    ///
    /// Returns `Err` if the string is not properly encoded.
    pub const fn from_encoded(s: &str) -> Result<&EStr, EncodingError> {
        match imp::validate_estr(s.as_bytes()) {
            Ok(_) => Ok(EStr::new_validated(s)),
            Err(e) => Err(e),
        }
    }

    /// Converts a string slice to `EStr` assuming validity.
    #[ref_cast_custom]
    #[inline]
    pub(crate) const fn new_validated(s: &str) -> &EStr;

    /// Yields the underlying string slice.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.inner
    }

    /// Decodes the `EStr`.
    ///
    /// This function allocates only when there is any percent-encoded octet in the `EStr`.
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::encoding::EStr;
    ///
    /// let dec = EStr::from_encoded("%C2%A1Hola%21").unwrap().decode();
    /// assert_eq!(dec.as_bytes(), &[0xc2, 0xa1, 0x48, 0x6f, 0x6c, 0x61, 0x21]);
    /// assert_eq!(dec.into_string()?, "¡Hola!");
    /// # Ok::<_, std::string::FromUtf8Error>(())
    /// ```
    #[inline]
    pub fn decode(&self) -> Decode<'_> {
        match imp::decode(self.inner.as_bytes()) {
            Some(vec) => Decode::Owned(vec),
            None => Decode::Borrowed(self.as_str()),
        }
    }

    /// Returns an iterator over subslices of the `EStr` separated by the given delimiter.
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
    /// use fluent_uri::encoding::EStr;
    ///
    /// assert!(EStr::from_encoded("a,b,c").unwrap().split(',').eq(["a", "b", "c"]));
    /// assert!(EStr::from_encoded(",").unwrap().split(',').eq(["", ""]));
    /// ```
    #[inline]
    pub fn split(&self, delim: char) -> Split<'_> {
        assert!(
            delim.is_ascii() && table::RESERVED.allows(delim as u8),
            "splitting with non-reserved character"
        );
        Split {
            inner: self.inner.split(delim),
        }
    }

    /// Splits the `EStr` on the first occurrence of the given delimiter and
    /// returns prefix before delimiter and suffix after delimiter.
    ///
    /// Returns `None` if the delimiter is not found.
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
    /// use fluent_uri::encoding::EStr;
    ///
    /// let (k, v) = EStr::from_encoded("key=value").unwrap().split_once('=').unwrap();
    /// assert_eq!(k, "key");
    /// assert_eq!(v, "value");
    ///
    /// assert!(EStr::from_encoded("abc").unwrap().split_once(';').is_none());
    /// ```
    #[inline]
    pub fn split_once(&self, delim: char) -> Option<(&EStr, &EStr)> {
        assert!(
            delim.is_ascii() && table::RESERVED.allows(delim as u8),
            "splitting with non-reserved character"
        );
        self.inner
            .split_once(delim)
            .map(|(a, b)| (EStr::new_validated(a), EStr::new_validated(b)))
    }
}

/// A wrapper of percent-decoded bytes.
///
/// This enum is created by the [`decode`] method on [`EStr`].
///
/// [`decode`]: EStr::decode
#[derive(Clone, Debug)]
pub enum Decode<'a> {
    /// No percent-encoded octets are decoded.
    Borrowed(&'a str),
    /// One or more percent-encoded octets are decoded.
    Owned(Vec<u8>),
}

impl<'a> Decode<'a> {
    /// Returns a reference to the decoded bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Borrowed(s) => s.as_bytes(),
            Self::Owned(vec) => vec,
        }
    }

    /// Consumes this `Decode` and yields the underlying decoded bytes.
    #[inline]
    pub fn into_bytes(self) -> Cow<'a, [u8]> {
        match self {
            Self::Borrowed(s) => Cow::Borrowed(s.as_bytes()),
            Self::Owned(vec) => Cow::Owned(vec),
        }
    }

    /// Converts the decoded bytes to a string.
    ///
    /// Returns `Err` if the decoded bytes are not valid UTF-8.
    #[inline]
    pub fn into_string(self) -> Result<Cow<'a, str>, FromUtf8Error> {
        match self {
            Self::Borrowed(s) => Ok(Cow::Borrowed(s)),
            Self::Owned(vec) => String::from_utf8(vec).map(Cow::Owned),
        }
    }
}

/// An iterator over subslices of an [`EStr`] separated by a delimiter.
///
/// This struct is created by the [`split`] method on [`EStr`].
///
/// [`split`]: EStr::split
#[derive(Clone, Debug)]
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct Split<'a> {
    inner: str::Split<'a, char>,
}

impl<'a> Iterator for Split<'a> {
    type Item = &'a EStr;

    #[inline]
    fn next(&mut self) -> Option<&'a EStr> {
        self.inner.next().map(EStr::new_validated)
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<'a> DoubleEndedIterator for Split<'a> {
    #[inline]
    fn next_back(&mut self) -> Option<&'a EStr> {
        self.inner.next_back().map(EStr::new_validated)
    }
}

impl FusedIterator for Split<'_> {}
