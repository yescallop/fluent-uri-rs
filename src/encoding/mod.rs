#[cfg(feature = "unstable")]
pub mod table;
#[cfg(not(feature = "unstable"))]
pub(crate) mod table;

mod imp;
#[cfg(feature = "unstable")]
pub use imp::*;
#[cfg(not(feature = "unstable"))]
pub(crate) use imp::*;

#[cfg(feature = "unstable")]
mod unstable;
#[cfg(feature = "unstable")]
pub use unstable::*;

use crate::Result;
use std::{
    borrow::{self, Cow},
    fmt, hash, mem,
    ops::Deref,
    str::{self, Utf8Error},
    string::FromUtf8Error,
};

/// Returns immediately with a syntax error.
macro_rules! err {
    ($index:expr, $kind:ident) => {
        return Err(crate::SyntaxError {
            index: $index as usize,
            kind: crate::SyntaxErrorKind::$kind,
        })
    };
}

pub(crate) use err;

/// Percent-encoded string slices.
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

impl PartialEq<EStr> for EStr {
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
    pub const EMPTY: &'static EStr = EStr::new("");

    /// Converts a string slice to an `EStr`.
    ///
    /// # Panics
    ///
    /// Panics if the string is not properly encoded.
    pub const fn new(s: &str) -> &EStr {
        if imp::validate_estr(s.as_bytes()) {
            // SAFETY: We have done the validation.
            unsafe { EStr::new_unchecked(s.as_bytes()) }
        } else {
            panic!("invalid percent-encoded string");
        }
    }

    /// Converts a byte slice into an `EStr` assuming validity.
    #[inline]
    pub(crate) const unsafe fn new_unchecked(s: &[u8]) -> &EStr {
        // SAFETY: The caller must ensure that the byte slice is valid percent-encoded UTF-8.
        unsafe { &*(s as *const [u8] as *const EStr) }
    }

    /// Yields the underlying string slice.
    #[inline]
    pub fn as_str(&self) -> &str {
        // SAFETY: We have done the validation.
        unsafe { str::from_utf8_unchecked(&self.inner) }
    }

    /// Decodes the `EStr`.
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::encoding::EStr;
    ///
    /// let dec = EStr::new("%C2%BF").decode();
    /// assert_eq!(dec.as_bytes(), &[0xc2, 0xbf]);
    /// assert_eq!(dec.into_string()?, "¿");
    /// # Ok::<_, std::string::FromUtf8Error>(())
    /// ```
    #[inline]
    pub fn decode(&self) -> Decode<'_> {
        // SAFETY: An `EStr` may only be created through `new_unchecked`,
        // of which the caller must guarantee that the string is properly encoded.
        Decode(unsafe { decode_unchecked(&self.inner) })
    }

    /// Decodes the `EStr` with a buffer.
    ///
    /// If the string needs no decoding, this function returns `None`
    /// and no bytes will be appended to the buffer.
    ///
    /// Note that the buffer is not cleared prior to decoding.
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::encoding::EStr;
    ///
    /// let mut buf = Vec::new();
    /// let dec = EStr::new("233").decode_with(&mut buf);
    /// assert_eq!(dec.to_str()?, "233");
    /// assert!(!dec.decoded_any());
    /// assert!(buf.is_empty());
    ///
    /// let dec = EStr::new("2%333").decode_with(&mut buf);
    /// assert_eq!(dec.to_str()?, "233");
    /// assert!(dec.decoded_any());
    /// assert_eq!(buf, b"233");
    /// # Ok::<_, std::str::Utf8Error>(())
    /// ```
    #[inline]
    pub fn decode_with<'dst>(&self, buf: &'dst mut Vec<u8>) -> DecodeRef<'_, 'dst> {
        // SAFETY: An `EStr` may only be created through `new_unchecked`,
        // of which the caller must guarantee that the string is properly encoded.
        let decoded = unsafe { decode_with_unchecked(&self.inner, buf) };

        match decoded {
            Some(s) => DecodeRef::Dst(s),
            None => DecodeRef::Src(self),
        }
    }

    /// Returns an iterator over subslices separated by the given delimiter.
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
    ///     .filter_map(|(k, v)| k.into_string().ok().zip(v.into_string().ok()))
    ///     .collect();
    /// assert_eq!(map["name"], "张三");
    /// assert_eq!(map["speech"], "¡Olé!");
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
    /// let (k, v) = EStr::new("key=value").split_once('=').unwrap();
    /// assert_eq!(k, "key");
    /// assert_eq!(v, "value");
    ///
    /// assert!(EStr::new("abc").split_once(';').is_none());
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

/// A wrapper around a mutable `EStr` slice that allows in-place percent-decoding.
#[repr(transparent)]
#[derive(Debug)]
pub struct EStrMut<'a>(&'a mut EStr);

impl<'a> Deref for EStrMut<'a> {
    type Target = EStr;
    #[inline]
    fn deref(&self) -> &EStr {
        self.0
    }
}

impl<'a> EStrMut<'a> {
    /// Converts a byte slice into an `EStrMut` assuming validity.
    #[inline]
    pub(crate) unsafe fn new(s: &mut [u8]) -> EStrMut<'_> {
        // SAFETY: The caller must ensure that the byte slice is valid percent-encoded UTF-8.
        EStrMut(unsafe { &mut *(s as *mut [u8] as *mut EStr) })
    }

    /// Consumes this `EStrMut` and yields the underlying mutable byte slice.
    #[inline]
    pub fn into_mut_bytes(self) -> &'a mut [u8] {
        &mut self.0.inner
    }

    /// Decodes the `EStrMut` in-place.
    #[inline]
    pub fn decode_in_place(self) -> DecodeInPlace<'a> {
        let bytes = self.into_mut_bytes();
        // SAFETY: An `EStrMut` may only be created through `new`,
        // of which the caller must guarantee that the string is properly encoded.
        let len = unsafe { imp::decode_in_place_unchecked(bytes) };
        if len == bytes.len() {
            // SAFETY: Nothing is decoded so the bytes are valid percent-encoded UTF-8.
            DecodeInPlace::Src(unsafe { EStrMut::new(bytes) })
        } else {
            // SAFETY: The length must be less.
            DecodeInPlace::Dst(unsafe { bytes.get_unchecked_mut(..len) })
        }
    }

    /// Returns an iterator over mutable subslices separated by the given delimiter.
    ///
    /// # Panics
    ///
    /// Panics if the delimiter is not a [reserved] character.
    ///
    /// [reserved]: https://datatracker.ietf.org/doc/html/rfc3986/#section-2.2
    #[inline]
    pub fn split_mut(self, delim: char) -> SplitMut<'a> {
        assert!(
            delim.is_ascii() && table::RESERVED.allows(delim as u8),
            "splitting with non-reserved character"
        );

        SplitMut {
            s: self.into_mut_bytes(),
            delim: delim as u8,
            finished: false,
        }
    }

    /// Splits the `EStrMut` on the first occurrence of the given delimiter and
    /// returns prefix before delimiter and suffix after delimiter.
    ///
    /// Returns `Err(self)` if the delimiter is not found.
    ///
    /// # Panics
    ///
    /// Panics if the delimiter is not a [reserved] character.
    ///
    /// [reserved]: https://datatracker.ietf.org/doc/html/rfc3986/#section-2.2
    #[inline]
    pub fn split_once_mut(self, delim: char) -> Result<(Self, Self), Self> {
        assert!(
            delim.is_ascii() && table::RESERVED.allows(delim as u8),
            "splitting with non-reserved character"
        );

        let i = match self.as_str().bytes().position(|x| x == delim as u8) {
            Some(i) => i,
            None => return Err(self),
        };
        let (head, tail) = self.into_mut_bytes().split_at_mut(i);
        // SAFETY: Splitting at a reserved character leaves valid percent-encoded UTF-8.
        unsafe { Ok((EStrMut::new(head), EStrMut::new(&mut tail[1..]))) }
    }
}

/// A wrapper of percent-decoded bytes.
///
/// This struct is created by calling [`decode`] on an `EStr`.
///
/// [`decode`]: EStr::decode
#[derive(Debug)]
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

    /// Returns `true` if anything is decoded, i.e., the underlying `Cow` is owned.
    #[inline]
    pub fn decoded_any(&self) -> bool {
        matches!(self.0, Cow::Owned(_))
    }

    /// Converts the decoded bytes to a string.
    ///
    /// An error is returned if the decoded bytes are not valid UTF-8.
    #[inline]
    pub fn into_string(self) -> Result<Cow<'a, str>, FromUtf8Error> {
        // FIXME: A (maybe) more efficient approach: only validating encoded sequences.
        match self.0 {
            // SAFETY: If the bytes are borrowed, they must be valid UTF-8.
            Cow::Borrowed(bytes) => Ok(Cow::Borrowed(unsafe { str::from_utf8_unchecked(bytes) })),
            Cow::Owned(vec) => String::from_utf8(vec).map(Cow::Owned),
        }
    }

    /// Converts the decoded bytes to a string lossily.
    pub fn into_string_lossy(self) -> Cow<'a, str> {
        match self.0 {
            // SAFETY: If the bytes are borrowed, they must be valid UTF-8.
            Cow::Borrowed(bytes) => Cow::Borrowed(unsafe { str::from_utf8_unchecked(bytes) }),
            Cow::Owned(vec) => match String::from_utf8_lossy(&vec) {
                // SAFETY: If a borrowed string slice is returned, the bytes must be valid UTF-8.
                Cow::Borrowed(_) => Cow::Owned(unsafe { String::from_utf8_unchecked(vec) }),
                Cow::Owned(string) => Cow::Owned(string),
            },
        }
    }
}

/// A wrapper of borrowed percent-decoded bytes.
///
/// This enum is created by calling [`decode_with`] on an `EStr`.
///
/// [`decode_with`]: EStr::decode_with
#[derive(Clone, Copy, Debug)]
pub enum DecodeRef<'src, 'dst> {
    /// Nothing decoded, i.e., borrowed from the source.
    Src(&'src EStr),
    /// Something decoded, i.e., borrowed from the buffer.
    Dst(&'dst [u8]),
}

impl<'src, 'dst> DecodeRef<'src, 'dst> {
    /// Returns a reference to the decoded bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        match *self {
            Self::Src(s) => s.as_str().as_bytes(),
            Self::Dst(s) => s,
        }
    }

    /// Returns `true` if anything is decoded.
    #[inline]
    pub fn decoded_any(&self) -> bool {
        matches!(self, Self::Dst(_))
    }

    /// Converts the decoded bytes to a string slice.
    ///
    /// An error is returned if the decoded bytes are not valid UTF-8.
    #[inline]
    pub fn to_str(&self) -> Result<&str, Utf8Error> {
        match *self {
            Self::Src(s) => Ok(s.as_str()),
            Self::Dst(s) => str::from_utf8(s),
        }
    }

    /// Converts the decoded bytes to a string lossily.
    #[inline]
    pub fn to_string_lossy(&self) -> Cow<'_, str> {
        match *self {
            Self::Src(s) => Cow::Borrowed(s.as_str()),
            Self::Dst(s) => String::from_utf8_lossy(s),
        }
    }
}

/// A wrapper of in-place percent-decoded bytes.
///
/// This enum is created by calling [`decode_in_place`] on an `EStrMut`.
///
/// [`decode_in_place`]: EStrMut::decode_in_place
#[derive(Debug)]
pub enum DecodeInPlace<'a> {
    /// Nothing decoded.
    Src(EStrMut<'a>),
    /// Something decoded.
    Dst(&'a mut [u8]),
}

impl<'a> DecodeInPlace<'a> {
    /// Returns a reference to the decoded bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Src(s) => s.as_str().as_bytes(),
            Self::Dst(s) => s,
        }
    }

    /// Consumes this `DecodeInPlace` and yields the underlying mutable byte slice.
    #[inline]
    pub fn into_mut_bytes(self) -> &'a mut [u8] {
        match self {
            Self::Src(s) => s.into_mut_bytes(),
            Self::Dst(s) => s,
        }
    }

    /// Returns `true` if anything is decoded.
    #[inline]
    pub fn decoded_any(&self) -> bool {
        matches!(self, Self::Dst(_))
    }

    /// Converts the decoded bytes to a string slice.
    ///
    /// An error is returned if the decoded bytes are not valid UTF-8.
    #[inline]
    pub fn to_str(&self) -> Result<&str, Utf8Error> {
        match self {
            Self::Src(s) => Ok(s.as_str()),
            Self::Dst(s) => str::from_utf8(s),
        }
    }

    /// Converts the decoded bytes to a string lossily.
    #[inline]
    pub fn to_string_lossy(&self) -> Cow<'_, str> {
        match self {
            Self::Src(s) => Cow::Borrowed(s.as_str()),
            Self::Dst(s) => String::from_utf8_lossy(s),
        }
    }
}

/// An iterator over subslices of an `EStr` separated by a delimiter.
///
/// This struct is created by calling [`split`] on an `EStr`.
///
/// [`split`]: EStr::split
#[derive(Debug)]
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

/// An iterator over mutable subslices of an `EStrMut` separated by a delimiter.
///
/// This struct is created by calling [`split_mut`] on an `EStrMut`.
///
/// [`split_mut`]: EStrMut::split_mut
#[derive(Debug)]
pub struct SplitMut<'a> {
    s: &'a mut [u8],
    delim: u8,
    pub(crate) finished: bool,
}

impl<'a> Iterator for SplitMut<'a> {
    type Item = EStrMut<'a>;

    #[inline]
    fn next(&mut self) -> Option<EStrMut<'a>> {
        if self.finished {
            return None;
        }

        let head = match self.s.iter().position(|&x| x == self.delim) {
            Some(i) => {
                let tmp = mem::take(&mut self.s);
                let (head, tail) = tmp.split_at_mut(i);
                self.s = &mut tail[1..];
                head
            }
            None => {
                self.finished = true;
                mem::take(&mut self.s)
            }
        };
        // SAFETY: Splitting at a reserved character leaves valid percent-encoded UTF-8.
        Some(unsafe { EStrMut::new(head) })
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

impl<'a> DoubleEndedIterator for SplitMut<'a> {
    #[inline]
    fn next_back(&mut self) -> Option<EStrMut<'a>> {
        if self.finished {
            return None;
        }

        let tail = match self.s.iter().rposition(|&x| x == self.delim) {
            Some(i) => {
                let tmp = mem::take(&mut self.s);
                let (head, tail) = tmp.split_at_mut(i);
                self.s = head;
                &mut tail[1..]
            }
            None => {
                self.finished = true;
                mem::take(&mut self.s)
            }
        };
        // SAFETY: Splitting at a reserved character leaves valid percent-encoded UTF-8.
        Some(unsafe { EStrMut::new(tail) })
    }
}
