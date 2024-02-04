pub(crate) mod imp;
pub(crate) mod table;

use alloc::{
    borrow::Cow,
    string::{FromUtf8Error, String},
    vec::Vec,
};
use core::{borrow::Borrow, cmp::Ordering, hash, iter::FusedIterator, str};
use ref_cast::{ref_cast_custom, RefCastCustom};

/// Percent-encoded string slices.
#[derive(RefCastCustom)]
#[repr(transparent)]
pub struct EStr {
    inner: [u8],
}

impl AsRef<str> for EStr {
    #[inline]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<[u8]> for EStr {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl Borrow<str> for &EStr {
    #[inline]
    fn borrow(&self) -> &str {
        self.as_str()
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
        self.as_str() == other
    }
}

impl PartialEq<EStr> for str {
    #[inline]
    fn eq(&self, other: &EStr) -> bool {
        self == other.as_str()
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
/// `EStr`s are compared [lexicographically](Ord#lexicographical-comparison) by their byte values.
/// Normalization is **not** performed prior to comparison.
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
        EStr::EMPTY
    }
}

impl EStr {
    const EMPTY: &'static EStr = match EStr::new("") {
        Some(s) => s,
        None => unreachable!(),
    };

    /// Converts a string slice to an `EStr`.
    ///
    /// Returns `None` if the string is not properly encoded.
    #[inline]
    pub const fn new(s: &str) -> Option<&EStr> {
        if imp::validate_estr(s.as_bytes()) {
            // SAFETY: The validation is done.
            Some(unsafe { EStr::new_unchecked(s.as_bytes()) })
        } else {
            None
        }
    }

    /// Converts a byte sequence into an `EStr` assuming validity.
    #[ref_cast_custom]
    #[inline]
    pub(crate) const unsafe fn new_unchecked(s: &[u8]) -> &EStr;

    /// Yields the underlying string slice.
    #[inline]
    pub fn as_str(&self) -> &str {
        // SAFETY: The validation is done.
        unsafe { str::from_utf8_unchecked(&self.inner) }
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
    /// let dec = EStr::new("%C2%A1Hola%21").unwrap().decode();
    /// assert_eq!(dec.as_bytes(), &[0xc2, 0xa1, 0x48, 0x6f, 0x6c, 0x61, 0x21]);
    /// assert_eq!(dec.into_string()?, "¡Hola!");
    /// # Ok::<_, std::string::FromUtf8Error>(())
    /// ```
    #[inline]
    pub fn decode(&self) -> Decode<'_> {
        // SAFETY: `EStr::new_unchecked` ensures that the string is properly encoded.
        match unsafe { imp::decode_unchecked(&self.inner) } {
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
    /// assert!(EStr::new("a,b,c").unwrap().split(',').eq(["a", "b", "c"]));
    /// assert!(EStr::new(",").unwrap().split(',').eq(["", ""]));
    /// ```
    #[inline]
    pub fn split(&self, delim: char) -> Split<'_> {
        assert!(
            delim.is_ascii() && table::RESERVED.allows(delim as u8),
            "splitting with non-reserved character"
        );

        Split {
            s: &self.inner,
            delim: delim as u8,
            finished: false,
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
    /// let (k, v) = EStr::new("key=value").unwrap().split_once('=').unwrap();
    /// assert_eq!(k, "key");
    /// assert_eq!(v, "value");
    ///
    /// assert!(EStr::new("abc").unwrap().split_once(';').is_none());
    /// ```
    #[inline]
    pub fn split_once(&self, delim: char) -> Option<(&EStr, &EStr)> {
        assert!(
            delim.is_ascii() && table::RESERVED.allows(delim as u8),
            "splitting with non-reserved character"
        );
        let bytes = &self.inner;

        let i = bytes.iter().position(|&x| x == delim as u8)?;
        let (head, tail) = (&bytes[..i], &bytes[i + 1..]);
        // SAFETY: Splitting at a reserved character leaves valid percent-encoded UTF-8.
        unsafe { Some((EStr::new_unchecked(head), EStr::new_unchecked(tail))) }
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
    /// An error is returned if the decoded bytes are not valid UTF-8.
    #[inline]
    pub fn into_string(self) -> Result<Cow<'a, str>, FromUtf8Error> {
        // A (maybe) more efficient approach: only validating encoded sequences.
        match self {
            Self::Borrowed(s) => Ok(Cow::Borrowed(s)),
            Self::Owned(vec) => String::from_utf8(vec).map(Cow::Owned),
        }
    }

    /// Converts the decoded bytes to a string lossily.
    #[inline]
    pub fn into_string_lossy(self) -> Cow<'a, str> {
        match self {
            Self::Borrowed(s) => Cow::Borrowed(s),
            Self::Owned(vec) => Cow::Owned(match String::from_utf8_lossy(&vec) {
                // SAFETY: If a borrowed string slice is returned, the bytes must be valid UTF-8.
                Cow::Borrowed(_) => unsafe { String::from_utf8_unchecked(vec) },
                Cow::Owned(string) => string,
            }),
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
    s: &'a [u8],
    delim: u8,
    pub(crate) finished: bool,
}

impl<'a> Iterator for Split<'a> {
    type Item = &'a EStr;

    #[inline]
    fn next(&mut self) -> Option<&'a EStr> {
        if self.finished {
            return None;
        }

        let head;
        match self.s.iter().position(|&x| x == self.delim) {
            Some(i) => {
                head = &self.s[..i];
                self.s = &self.s[i + 1..];
            }
            None => {
                self.finished = true;
                head = self.s;
            }
        }
        // SAFETY: Splitting at a reserved character leaves valid percent-encoded UTF-8.
        Some(unsafe { EStr::new_unchecked(head) })
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

        let tail;
        match self.s.iter().rposition(|&x| x == self.delim) {
            Some(i) => {
                tail = &self.s[i + 1..];
                self.s = &self.s[..i];
            }
            None => {
                self.finished = true;
                tail = self.s;
            }
        }
        // SAFETY: Splitting at a reserved character leaves valid percent-encoded UTF-8.
        Some(unsafe { EStr::new_unchecked(tail) })
    }
}

impl FusedIterator for Split<'_> {}
