//! Utilities for percent-encoding.

pub mod encoder;
mod estring;
mod imp;
pub(crate) mod table;

pub use estring::EString;

pub(crate) use imp::{decode_octet, OCTET_TABLE_LO};

use alloc::{
    borrow::{Cow, ToOwned},
    string::{FromUtf8Error, String},
    vec::Vec,
};
use core::{cmp::Ordering, hash, iter::FusedIterator, marker::PhantomData, str};
use encoder::Path;
use ref_cast::{ref_cast_custom, RefCastCustom};

/// A table specifying the byte patterns allowed in a string.
#[derive(Clone, Copy, Debug)]
pub struct Table {
    arr: [u8; 256],
    allows_enc: bool,
}

/// A trait used by [`EStr`] and [`EString`] to specify the table used for encoding.
///
/// [`EStr`]: EStr
/// [`EString`]: EString
///
/// # Sub-encoders
///
/// A sub-encoder `SubE` of `E` is an encoder such that `SubE::TABLE` is a [subset] of `E::TABLE`.
///
/// [subset]: Table::is_subset
pub trait Encoder: 'static {
    /// The table used for encoding.
    const TABLE: &'static Table;
}

/// Percent-encoded string slices.
///
/// The owned variant of `EStr` is [`EString`]. See its documentation
/// if you want to build a percent-encoded string from scratch.
///
/// # Type parameter
///
/// The `EStr<E>` type is parameterized over a type `E` that implements [`Encoder`].
/// The associated constant `E::TABLE` of type [`Table`] specifies the byte patterns
/// allowed in a string. In short, the underlying byte sequence of an `EStr<E>` slice
/// can be formed by joining any number of the following byte sequences:
///
/// - `[x]` where `E::TABLE.allows(x)`.
/// - `[b'%', hi, lo]` where `E::TABLE.allows_enc() && hi.is_ascii_hexdigit() && lo.is_ascii_hexdigit()`.
///
/// # Comparison
///
/// `EStr` slices are compared [lexicographically](Ord#lexicographical-comparison)
/// by their byte values. Normalization is **not** performed prior to comparison.
///
/// # Examples
///
/// Parse key-value pairs from a query string into a hash map:
///
/// ```
/// use fluent_uri::encoding::{encoder::Query, EStr};
/// use std::collections::HashMap;
///
/// let query = "name=%E5%BC%A0%E4%B8%89&speech=%C2%A1Ol%C3%A9%21";
/// let map: HashMap<_, _> = EStr::<Query>::new(query)
///     .split('&')
///     .map(|s| s.split_once('=').unwrap_or((s, EStr::new(""))))
///     .map(|(k, v)| (k.decode().into_string_lossy(), v.decode().into_string_lossy()))
///     .collect();
/// assert_eq!(map["name"], "张三");
/// assert_eq!(map["speech"], "¡Olé!");
/// ```
#[derive(RefCastCustom)]
#[repr(transparent)]
pub struct EStr<E: Encoder> {
    encoder: PhantomData<E>,
    inner: str,
}

struct Assert<L: Encoder, R: Encoder> {
    _marker: PhantomData<(L, R)>,
}

impl<L: Encoder, R: Encoder> Assert<L, R> {
    const LEFT_IS_SUB_ENCODER_OF_RIGHT: () =
        assert!(L::TABLE.is_subset(R::TABLE), "not a sub-encoder");
}

impl<E: Encoder> EStr<E> {
    const ASSERT_ALLOWS_ENC: () = assert!(
        E::TABLE.allows_enc(),
        "table does not allow percent-encoded octets"
    );

    /// Converts a string slice to an `EStr` slice assuming validity.
    #[ref_cast_custom]
    pub(crate) const fn new_validated(s: &str) -> &Self;

    /// Converts a string slice to an `EStr` slice.
    ///
    /// This function *panics* on invalid input and should only be used
    /// when you know that the string is properly percent-encoded.
    /// If you want to build a percent-encoded string from scratch,
    /// use [`EString`] instead.
    ///
    /// # Panics
    ///
    /// Panics if the string is not properly encoded with `E`.
    /// For a non-panicking variant, use [`try_new`](Self::try_new).
    #[must_use]
    pub const fn new(s: &str) -> &Self {
        match Self::try_new(s) {
            Some(s) => s,
            None => panic!("improperly encoded string"),
        }
    }

    /// Converts a string slice to an `EStr` slice, returning `None` if the conversion fails.
    ///
    /// This is the non-panicking variant of [`new`](Self::new).
    #[must_use]
    pub const fn try_new(s: &str) -> Option<&Self> {
        if E::TABLE.validate(s.as_bytes()) {
            Some(EStr::new_validated(s))
        } else {
            None
        }
    }

    /// Yields the underlying string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.inner
    }

    /// Returns the length of the `EStr` slice in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Checks whether the `EStr` slice is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Upcasts the `EStr` slice to associate with the given super-encoder.
    ///
    /// # Panics
    ///
    /// Panics at compile time if `E` is not a [sub-encoder](Encoder#sub-encoders) of `SuperE`.
    #[cfg(fluent_uri_unstable)]
    #[must_use]
    pub fn upcast<SuperE: Encoder>(&self) -> &EStr<SuperE> {
        let () = Assert::<E, SuperE>::LEFT_IS_SUB_ENCODER_OF_RIGHT;
        EStr::new_validated(self.as_str())
    }

    /// Decodes the `EStr` slice.
    ///
    /// Always **split** before decoding, as otherwise the data may be
    /// mistaken for component delimiters.
    ///
    /// This method allocates only when the slice contains any percent-encoded octet.
    ///
    /// Note that this method will **not** decode `U+002B` (+) as `0x20` (space).
    ///
    /// # Panics
    ///
    /// Panics at compile time if `E::TABLE` does not [allow percent-encoded octets].
    ///
    /// [allow percent-encoded octets]: Table::allows_enc
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::encoding::{encoder::Path, EStr};
    ///
    /// let dec = EStr::<Path>::new("%C2%A1Hola%21").decode();
    /// assert_eq!(dec.as_bytes(), &[0xc2, 0xa1, 0x48, 0x6f, 0x6c, 0x61, 0x21]);
    /// assert_eq!(dec.into_string()?, "¡Hola!");
    /// # Ok::<_, std::string::FromUtf8Error>(())
    /// ```
    #[must_use]
    pub fn decode(&self) -> Decode<'_> {
        let () = Self::ASSERT_ALLOWS_ENC;

        match imp::decode(self.inner.as_bytes()) {
            Some(vec) => Decode::Owned(vec),
            None => Decode::Borrowed(self.as_str()),
        }
    }

    /// Returns an iterator over subslices of the `EStr` slice separated by the given delimiter.
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
    /// use fluent_uri::encoding::{encoder::Path, EStr};
    ///
    /// assert!(EStr::<Path>::new("a,b,c").split(',').eq(["a", "b", "c"]));
    /// assert!(EStr::<Path>::new(",").split(',').eq(["", ""]));
    /// assert!(EStr::<Path>::new("").split(',').eq([""]));
    /// ```
    pub fn split(&self, delim: char) -> Split<'_, E> {
        assert!(
            delim.is_ascii() && table::RESERVED.allows(delim as u8),
            "splitting with non-reserved character"
        );
        Split {
            inner: self.inner.split(delim),
            encoder: PhantomData,
        }
    }

    /// Splits the `EStr` slice on the first occurrence of the given delimiter and
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
    /// use fluent_uri::encoding::{encoder::Path, EStr};
    ///
    /// assert_eq!(
    ///     EStr::<Path>::new("foo;bar;baz").split_once(';'),
    ///     Some((EStr::new("foo"), EStr::new("bar;baz")))
    /// );
    ///
    /// assert_eq!(EStr::<Path>::new("foo").split_once(';'), None);
    /// ```
    #[must_use]
    pub fn split_once(&self, delim: char) -> Option<(&Self, &Self)> {
        assert!(
            delim.is_ascii() && table::RESERVED.allows(delim as u8),
            "splitting with non-reserved character"
        );
        self.inner
            .split_once(delim)
            .map(|(a, b)| (Self::new_validated(a), Self::new_validated(b)))
    }

    /// Splits the `EStr` slice on the last occurrence of the given delimiter and
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
    /// use fluent_uri::encoding::{encoder::Path, EStr};
    ///
    /// assert_eq!(
    ///     EStr::<Path>::new("foo;bar;baz").rsplit_once(';'),
    ///     Some((EStr::new("foo;bar"), EStr::new("baz")))
    /// );
    ///
    /// assert_eq!(EStr::<Path>::new("foo").rsplit_once(';'), None);
    /// ```
    #[must_use]
    pub fn rsplit_once(&self, delim: char) -> Option<(&Self, &Self)> {
        assert!(
            delim.is_ascii() && table::RESERVED.allows(delim as u8),
            "splitting with non-reserved character"
        );
        self.inner
            .rsplit_once(delim)
            .map(|(a, b)| (Self::new_validated(a), Self::new_validated(b)))
    }
}

impl<E: Encoder> AsRef<Self> for EStr<E> {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl<E: Encoder> AsRef<str> for EStr<E> {
    fn as_ref(&self) -> &str {
        &self.inner
    }
}

impl<E: Encoder> PartialEq for EStr<E> {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl<E: Encoder> PartialEq<str> for EStr<E> {
    fn eq(&self, other: &str) -> bool {
        &self.inner == other
    }
}

impl<E: Encoder> PartialEq<EStr<E>> for str {
    fn eq(&self, other: &EStr<E>) -> bool {
        self == &other.inner
    }
}

impl<E: Encoder> Eq for EStr<E> {}

impl<E: Encoder> hash::Hash for EStr<E> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.inner.hash(state);
    }
}

impl<E: Encoder> PartialOrd for EStr<E> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<E: Encoder> Ord for EStr<E> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.inner.cmp(&other.inner)
    }
}

impl<E: Encoder> Default for &EStr<E> {
    /// Creates an empty `EStr` slice.
    fn default() -> Self {
        EStr::new_validated("")
    }
}

impl<E: Encoder> ToOwned for EStr<E> {
    type Owned = EString<E>;

    fn to_owned(&self) -> EString<E> {
        EString::new_validated(self.inner.to_owned())
    }

    fn clone_into(&self, target: &mut EString<E>) {
        self.inner.clone_into(&mut target.buf);
    }
}

/// Extension methods for the [path] component of URI reference.
///
/// [path]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.3
impl EStr<Path> {
    /// Checks whether the path is absolute, i.e., starting with `'/'`.
    #[inline]
    #[must_use]
    pub fn is_absolute(&self) -> bool {
        self.inner.starts_with('/')
    }

    /// Checks whether the path is rootless, i.e., not starting with `'/'`.
    #[inline]
    #[must_use]
    pub fn is_rootless(&self) -> bool {
        !self.inner.starts_with('/')
    }

    /// Returns an iterator over the [path segments].
    ///
    /// [path segments]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.3
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// // An empty path has no segments.
    /// let uri = Uri::parse("")?;
    /// assert_eq!(uri.path().segments().next(), None);
    ///
    /// // Segments are separated by '/'.
    /// let uri = Uri::parse("a/b/c")?;
    /// assert!(uri.path().segments().eq(["a", "b", "c"]));
    ///
    /// // The empty string before a preceding '/' is not a segment.
    /// // However, segments can be empty in the other cases.
    /// let uri = Uri::parse("/path/to//dir/")?;
    /// assert!(uri.path().segments().eq(["path", "to", "", "dir", ""]));
    /// # Ok::<_, fluent_uri::error::ParseError>(())
    /// ```
    #[cfg(fluent_uri_unstable)]
    #[inline]
    pub fn segments(&self) -> Split<'_, Path> {
        let path_stripped = self.inner.strip_prefix('/').unwrap_or(&self.inner);

        let mut split = EStr::new_validated(path_stripped).split('/');
        if self.inner.is_empty() {
            split.next();
        }
        split
    }
}

/// A wrapper of percent-decoded bytes.
///
/// This enum is created by [`EStr::decode`].
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
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Borrowed(s) => s.as_bytes(),
            Self::Owned(vec) => vec,
        }
    }

    /// Consumes this `Decode` and yields the underlying decoded bytes.
    #[inline]
    #[must_use]
    pub fn into_bytes(self) -> Cow<'a, [u8]> {
        match self {
            Self::Borrowed(s) => Cow::Borrowed(s.as_bytes()),
            Self::Owned(vec) => Cow::Owned(vec),
        }
    }

    /// Converts the decoded bytes to a string.
    ///
    /// Returns `Err` if the bytes are not valid UTF-8.
    #[inline]
    pub fn into_string(self) -> Result<Cow<'a, str>, FromUtf8Error> {
        match self {
            Self::Borrowed(s) => Ok(Cow::Borrowed(s)),
            Self::Owned(vec) => String::from_utf8(vec).map(Cow::Owned),
        }
    }

    /// Converts the decoded bytes to a string, including invalid characters.
    ///
    /// This calls [`String::from_utf8_lossy`] if the bytes are not valid UTF-8.
    #[must_use]
    pub fn into_string_lossy(self) -> Cow<'a, str> {
        match self.into_string() {
            Ok(string) => string,
            Err(e) => Cow::Owned(String::from_utf8_lossy(e.as_bytes()).into_owned()),
        }
    }
}

/// An iterator over subslices of an [`EStr`] slice separated by a delimiter.
///
/// This struct is created by [`EStr::split`].
#[derive(Clone, Debug)]
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct Split<'a, E: Encoder> {
    inner: str::Split<'a, char>,
    encoder: PhantomData<E>,
}

impl<'a, E: Encoder> Iterator for Split<'a, E> {
    type Item = &'a EStr<E>;

    fn next(&mut self) -> Option<&'a EStr<E>> {
        self.inner.next().map(EStr::new_validated)
    }
}

impl<'a, E: Encoder> DoubleEndedIterator for Split<'a, E> {
    fn next_back(&mut self) -> Option<&'a EStr<E>> {
        self.inner.next_back().map(EStr::new_validated)
    }
}

impl<E: Encoder> FusedIterator for Split<'_, E> {}
