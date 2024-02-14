use super::{encoder::Encoder, Assert, EStr};
use alloc::{borrow::ToOwned, string::String};
use core::{borrow::Borrow, cmp::Ordering, hash, marker::PhantomData, ops::Deref};

/// A percent-encoded, growable string.
///
/// # Examples
///
/// Encode key-value pairs to a query string.
///
/// ```
/// use fluent_uri::encoding::{
///     encoder::{Encoder, Query},
///     table::{self, Table},
///     EString,
/// };
///
/// struct Data;
///
/// impl Encoder for Data {
///     const TABLE: &'static Table = &table::UNRESERVED.enc();
/// }
///
/// let pairs = [("name", "张三"), ("speech", "¡Olé!")];
/// let mut buf = EString::<Query>::new();
/// for (k, v) in pairs {
///     if !buf.is_empty() {
///         buf.push_byte(b'&');
///     }
///     buf.encode::<Data>(k);
///     buf.push_byte(b'=');
///     buf.encode::<Data>(v);
/// }
///
/// assert_eq!(buf, "name=%E5%BC%A0%E4%B8%89&speech=%C2%A1Ol%C3%A9%21");
/// ```
#[derive(Clone, Default)]
pub struct EString<E: Encoder> {
    pub(crate) buf: String,
    encoder: PhantomData<E>,
}

impl<E: Encoder> Deref for EString<E> {
    type Target = EStr<E>;

    #[inline]
    fn deref(&self) -> &EStr<E> {
        EStr::new_validated(&self.buf)
    }
}

impl<E: Encoder> EString<E> {
    #[inline]
    pub(crate) const fn new_validated(buf: String) -> Self {
        EString {
            buf,
            encoder: PhantomData,
        }
    }

    /// Creates a new empty `EString`.
    #[inline]
    pub const fn new() -> Self {
        Self::new_validated(String::new())
    }

    /// Creates a new empty `EString` with a particular capacity.
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self::new_validated(String::with_capacity(capacity))
    }

    /// Consumes this `EString` and yields the underlying `String` storage.
    #[inline]
    pub fn into_string(self) -> String {
        self.buf
    }

    /// Coerces to an `EStr` slice.
    #[inline]
    pub fn as_estr(&self) -> &EStr<E> {
        self
    }

    /// Encodes a byte sequence with a sub-encoder and appends the result onto the end of this `EString`.
    ///
    /// # Panics
    ///
    /// Panics at compile time if `SubE` is not a [sub-encoder](Encoder#sub-encoder) of `E`,
    /// or if `SubE::TABLE` does not [allow percent-encoding].
    ///
    /// [allow percent-encoding]: super::table::Table::allows_enc
    #[inline]
    pub fn encode<SubE: Encoder>(&mut self, s: &(impl AsRef<[u8]> + ?Sized)) {
        let _ = Assert::<SubE, E>::LEFT_IS_SUB_ENCODER_OF_RIGHT;
        let _ = EStr::<SubE>::ASSERT_ALLOWS_ENC;

        for &x in s.as_ref() {
            SubE::TABLE.encode(x, &mut self.buf)
        }
    }

    /// Appends an unencoded byte onto the end of this `EString`.
    ///
    /// # Panics
    ///
    /// Panics if `E::TABLE` does not [allow] the byte.
    ///
    /// [allow]: super::table::Table::allows
    #[inline]
    pub fn push_byte(&mut self, x: u8) {
        assert!(E::TABLE.allows(x), "table does not allow the byte");
        self.buf.push(x as char);
    }

    /// Appends an `EStr` slice onto the end of this `EString`.
    ///
    /// # Panics
    ///
    /// Panics at compile time if `SubE` is not a [sub-encoder](Encoder#sub-encoder) of `E`.
    #[inline]
    pub fn push_estr<SubE: Encoder>(&mut self, s: &EStr<SubE>) {
        let _ = Assert::<SubE, E>::LEFT_IS_SUB_ENCODER_OF_RIGHT;
        self.buf.push_str(s.as_str())
    }

    /// Invokes [`capacity`] on the underlying `String`.
    ///
    /// [`capacity`]: String::capacity
    #[inline]
    pub fn capacity(&self) -> usize {
        self.buf.capacity()
    }

    /// Invokes [`reserve`] on the underlying `String`.
    ///
    /// [`reserve`]: String::reserve
    #[inline]
    pub fn reserve(&mut self, additional: usize) {
        self.buf.reserve(additional);
    }

    /// Invokes [`reserve_exact`] on the underlying `String`.
    ///
    /// [`reserve_exact`]: String::reserve_exact
    #[inline]
    pub fn reserve_exact(&mut self, additional: usize) {
        self.buf.reserve_exact(additional);
    }

    /// Truncates this `EString` to zero length and casts to another type, preserving the capacity.
    #[inline]
    pub fn clear<F: Encoder>(mut self) -> EString<F> {
        self.buf.clear();
        EString {
            buf: self.buf,
            encoder: PhantomData,
        }
    }
}

impl<E: Encoder> AsRef<EStr<E>> for EString<E> {
    #[inline]
    fn as_ref(&self) -> &EStr<E> {
        self
    }
}

impl<E: Encoder> AsRef<str> for EString<E> {
    #[inline]
    fn as_ref(&self) -> &str {
        &self.buf
    }
}

impl<E: Encoder> Borrow<EStr<E>> for EString<E> {
    #[inline]
    fn borrow(&self) -> &EStr<E> {
        self
    }
}

impl<E: Encoder> From<&EStr<E>> for EString<E> {
    #[inline]
    fn from(value: &EStr<E>) -> Self {
        value.to_owned()
    }
}

impl<E: Encoder, F: Encoder> PartialEq<EString<F>> for EString<E> {
    #[inline]
    fn eq(&self, other: &EString<F>) -> bool {
        self.as_str() == other.as_str()
    }
}

impl<E: Encoder, F: Encoder> PartialEq<EStr<F>> for EString<E> {
    #[inline]
    fn eq(&self, other: &EStr<F>) -> bool {
        self.as_str() == other.as_str()
    }
}

impl<E: Encoder, F: Encoder> PartialEq<EString<E>> for EStr<F> {
    #[inline]
    fn eq(&self, other: &EString<E>) -> bool {
        self.as_str() == other.as_str()
    }
}

impl<E: Encoder, F: Encoder> PartialEq<&EStr<F>> for EString<E> {
    #[inline]
    fn eq(&self, other: &&EStr<F>) -> bool {
        self.as_str() == other.as_str()
    }
}

impl<E: Encoder, F: Encoder> PartialEq<EString<E>> for &EStr<F> {
    #[inline]
    fn eq(&self, other: &EString<E>) -> bool {
        self.as_str() == other.as_str()
    }
}

impl<E: Encoder> PartialEq<str> for EString<E> {
    #[inline]
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl<E: Encoder> PartialEq<EString<E>> for str {
    #[inline]
    fn eq(&self, other: &EString<E>) -> bool {
        self == other.as_str()
    }
}

impl<E: Encoder> PartialEq<&str> for EString<E> {
    #[inline]
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl<E: Encoder> PartialEq<EString<E>> for &str {
    #[inline]
    fn eq(&self, other: &EString<E>) -> bool {
        *self == other.as_str()
    }
}

impl<E: Encoder> Eq for EString<E> {}

impl<E: Encoder> hash::Hash for EString<E> {
    #[inline]
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.buf.hash(state)
    }
}

impl<E: Encoder> PartialOrd for EString<E> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Implements ordering on `EString`s.
///
/// `EString`s are ordered [lexicographically](Ord#lexicographical-comparison) by their byte values.
/// Normalization is **not** performed prior to ordering.
impl<E: Encoder> Ord for EString<E> {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.inner.cmp(&other.inner)
    }
}
