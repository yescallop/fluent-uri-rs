use super::{Assert, EStr, Encoder};
use alloc::{borrow::ToOwned, string::String};
use core::{borrow::Borrow, cmp::Ordering, hash, marker::PhantomData, ops::Deref};

/// A percent-encoded, growable string.
///
/// The borrowed counterpart of `EString` is [`EStr`].
/// See its documentation for the meaning of the type parameter `E`.
///
/// # Comparison
///
/// `EString`s are compared [lexicographically](Ord#lexicographical-comparison)
/// by their byte values. Normalization is **not** performed prior to comparison.
///
/// # Examples
///
/// Encode key-value pairs to a query string and use it to build a URI reference:
///
/// ```
/// use fluent_uri::{
///     encoding::{
///         encoder::{Data, Query},
///         EStr, EString, Encoder, Table,
///     },
///     UriRef,
/// };
///
/// let pairs = [("name", "张三"), ("speech", "¡Olé!")];
/// let mut buf = EString::<Query>::new();
/// for (k, v) in pairs {
///     if !buf.is_empty() {
///         buf.push_byte(b'&');
///     }
///
///     // WARNING: Absolutely do not confuse data with delimiters! Use `Data`
///     // to encode data contained in a URI unless you know what you're doing!
///     //
///     // `Data` preserves only unreserved characters and encodes the others,
///     // which is always safe to use but may be wasteful of memory because
///     // usually not all reserved characters are used as delimiters and you can
///     // choose to preserve some of them. See below for an example of creating
///     // a custom encoder based on an existing one.
///     buf.encode::<Data>(k);
///     buf.push_byte(b'=');
///     buf.encode::<Data>(v);
/// }
///
/// assert_eq!(buf, "name=%E5%BC%A0%E4%B8%89&speech=%C2%A1Ol%C3%A9%21");
///
/// let uri_ref = UriRef::builder()
///     .path(EStr::EMPTY)
///     .query(&buf)
///     .build()
///     .unwrap();
/// assert_eq!(uri_ref.as_str(), "?name=%E5%BC%A0%E4%B8%89&speech=%C2%A1Ol%C3%A9%21");
/// ```
///
/// Encode a path whose segments may contain the slash (`'/'`) character
/// by using a custom encoder:
///
/// ```
/// use fluent_uri::encoding::{encoder::Path, EString, Encoder, Table};
///
/// struct PathSegment;
///
/// impl Encoder for PathSegment {
///     const TABLE: &'static Table = &Path::TABLE.sub(&Table::gen(b"/"));
/// }
///
/// let mut path = EString::<Path>::new();
/// path.push_byte(b'/');
/// path.encode::<PathSegment>("foo/bar");
///
/// assert_eq!(path, "/foo%2Fbar");
/// ```
#[derive(Clone, Default)]
pub struct EString<E: Encoder> {
    pub(crate) buf: String,
    encoder: PhantomData<E>,
}

impl<E: Encoder> Deref for EString<E> {
    type Target = EStr<E>;

    fn deref(&self) -> &EStr<E> {
        EStr::new_validated(&self.buf)
    }
}

impl<E: Encoder> EString<E> {
    pub(crate) fn new_validated(buf: String) -> Self {
        EString {
            buf,
            encoder: PhantomData,
        }
    }

    /// Creates a new empty `EString`.
    #[must_use]
    pub fn new() -> Self {
        Self::new_validated(String::new())
    }

    /// Coerces to an `EStr` slice.
    #[must_use]
    pub fn as_estr(&self) -> &EStr<E> {
        self
    }

    /// Encodes a byte sequence with a sub-encoder and appends the result onto the end of this `EString`.
    ///
    /// A byte will be percent-encoded if and only if `SubE::TABLE` does not [allow] it.
    /// When encoding data, make sure that `SubE::TABLE` does not [allow] the component delimiters
    /// that delimit the data.
    ///
    /// Note that this method will **not** encode `0x20` (space) as `U+002B` (+).
    ///
    /// [allow]: super::Table::allows
    ///
    /// # Panics
    ///
    /// Panics at compile time if `SubE` is not a [sub-encoder](Encoder#sub-encoders) of `E`,
    /// or if `SubE::TABLE` does not [allow percent-encoded octets].
    ///
    /// [allow percent-encoded octets]: super::Table::allows_enc
    pub fn encode<SubE: Encoder>(&mut self, s: &(impl AsRef<[u8]> + ?Sized)) {
        let () = Assert::<SubE, E>::LEFT_IS_SUB_ENCODER_OF_RIGHT;
        let () = EStr::<SubE>::ASSERT_ALLOWS_ENC;

        for &x in s.as_ref() {
            SubE::TABLE.encode(x, &mut self.buf);
        }
    }

    /// Appends an unencoded byte onto the end of this `EString`.
    ///
    /// # Panics
    ///
    /// Panics if `E::TABLE` does not [allow] the byte.
    ///
    /// [allow]: super::Table::allows
    pub fn push_byte(&mut self, x: u8) {
        assert!(E::TABLE.allows(x), "table does not allow the byte");
        self.buf.push(x as char);
    }

    /// Appends an `EStr` slice onto the end of this `EString`.
    pub fn push_estr(&mut self, s: &EStr<E>) {
        self.buf.push_str(s.as_str());
    }

    /// Consumes this `EString` and yields the underlying `String`.
    #[must_use]
    pub fn into_string(self) -> String {
        self.buf
    }
}

impl<E: Encoder> AsRef<EStr<E>> for EString<E> {
    fn as_ref(&self) -> &EStr<E> {
        self
    }
}

impl<E: Encoder> AsRef<str> for EString<E> {
    fn as_ref(&self) -> &str {
        &self.buf
    }
}

impl<E: Encoder> Borrow<EStr<E>> for EString<E> {
    fn borrow(&self) -> &EStr<E> {
        self
    }
}

impl<E: Encoder> From<&EStr<E>> for EString<E> {
    fn from(s: &EStr<E>) -> Self {
        s.to_owned()
    }
}

impl<E: Encoder> PartialEq for EString<E> {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl<E: Encoder> PartialEq<EStr<E>> for EString<E> {
    fn eq(&self, other: &EStr<E>) -> bool {
        self.as_str() == other.as_str()
    }
}

impl<E: Encoder> PartialEq<EString<E>> for EStr<E> {
    fn eq(&self, other: &EString<E>) -> bool {
        self.as_str() == other.as_str()
    }
}

impl<E: Encoder> PartialEq<&EStr<E>> for EString<E> {
    fn eq(&self, other: &&EStr<E>) -> bool {
        self.as_str() == other.as_str()
    }
}

impl<E: Encoder> PartialEq<EString<E>> for &EStr<E> {
    fn eq(&self, other: &EString<E>) -> bool {
        self.as_str() == other.as_str()
    }
}

impl<E: Encoder> PartialEq<str> for EString<E> {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl<E: Encoder> PartialEq<EString<E>> for str {
    fn eq(&self, other: &EString<E>) -> bool {
        self == other.as_str()
    }
}

impl<E: Encoder> PartialEq<&str> for EString<E> {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl<E: Encoder> PartialEq<EString<E>> for &str {
    fn eq(&self, other: &EString<E>) -> bool {
        *self == other.as_str()
    }
}

impl<E: Encoder> Eq for EString<E> {}

impl<E: Encoder> hash::Hash for EString<E> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.buf.hash(state);
    }
}

impl<E: Encoder> PartialOrd for EString<E> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<E: Encoder> Ord for EString<E> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.inner.cmp(&other.inner)
    }
}
