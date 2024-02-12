use super::{encoder::Encoder, EStr};
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
/// struct QueryData;
///
/// impl Encoder for QueryData {
///     const TABLE: &'static Table = &table::QUERY.sub(&Table::gen(b"&=+"));
/// }
///
/// let pairs = [("name", "张三"), ("speech", "¡Olé!")];
/// let mut buf = EString::<Query>::new();
/// for (k, v) in pairs {
///     if !buf.is_empty() {
///         buf.push_byte(b'&');
///     }
///     buf.push_with::<QueryData>(k);
///     buf.push_byte(b'=');
///     buf.push_with::<QueryData>(v);
/// }
///
/// assert_eq!(buf, "name=%E5%BC%A0%E4%B8%89&speech=%C2%A1Ol%C3%A9!");
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
    const ASSERT_ALLOWS_ENC: () = assert!(
        E::TABLE.allows_enc(),
        "table does not allow percent-encoding"
    );

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

    /// Encodes a byte sequence and appends the result onto the end of this `EString`.
    ///
    /// # Panics
    ///
    /// Panics at compile time if the table specified
    /// by `E` does not allow percent-encoding.
    #[inline]
    pub fn push<S: AsRef<[u8]> + ?Sized>(&mut self, s: &S) {
        let _ = Self::ASSERT_ALLOWS_ENC;

        for &x in s.as_ref() {
            E::TABLE.encode(x, &mut self.buf)
        }
    }

    /// Encodes a byte sequence with a sub-encoder and appends the result onto the end of this `EString`.
    ///
    /// A sub-encoder `SubE` of `E` is an encoder such that `SubE::TABLE` is a [subset] of `E::TABLE`.
    ///
    /// [subset]: super::table::Table::is_subset
    ///
    /// # Panics
    ///
    /// Panics at compile time if `SubE` is not a sub-encoder of `E`, or
    /// if the table specified by `SubE` does not allow percent-encoding.
    #[inline]
    pub fn push_with<SubE: Encoder>(&mut self, s: &(impl AsRef<[u8]> + ?Sized)) {
        struct Assert<SubE: Encoder, E: Encoder> {
            _marker: PhantomData<(SubE, E)>,
        }
        impl<SubE: Encoder, E: Encoder> Assert<SubE, E> {
            const IS_SUB_ENCODER: () = assert!(
                SubE::TABLE.is_subset(E::TABLE),
                "pushing with non-sub-encoder"
            );
        }
        let _ = Assert::<SubE, E>::IS_SUB_ENCODER;
        let _ = EString::<SubE>::ASSERT_ALLOWS_ENC;

        for &x in s.as_ref() {
            SubE::TABLE.encode(x, &mut self.buf)
        }
    }

    /// Encodes a byte and appends the result onto the end of this `EString`.
    ///
    /// # Panics
    ///
    /// Panics at compile time if the table specified
    /// by `E` does not allow percent-encoding.
    #[inline]
    pub fn push_byte(&mut self, x: u8) {
        E::TABLE.encode(x, &mut self.buf)
    }

    /// Appends an `EStr` slice onto the end of this `EString`.
    #[inline]
    pub fn push_encoded(&mut self, s: &EStr<E>) {
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

    /// Invokes [`shrink_to_fit`] on the underlying `String`.
    ///
    /// [`shrink_to_fit`]: String::shrink_to_fit
    #[inline]
    pub fn shrink_to_fit(&mut self) {
        self.buf.shrink_to_fit()
    }

    /// Invokes [`shrink_to`] on the underlying `String`.
    ///
    /// [`shrink_to`]: String::shrink_to
    #[inline]
    pub fn shrink_to(&mut self, min_capacity: usize) {
        self.buf.shrink_to(min_capacity)
    }

    /// Invokes [`len`] on the underlying `String`.
    ///
    /// [`len`]: String::len
    #[inline]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Invokes [`is_empty`] on the underlying `String`.
    ///
    /// [`is_empty`]: String::is_empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Invokes [`clear`] on the underlying `String`.
    ///
    /// [`clear`]: String::clear
    #[inline]
    pub fn clear(&mut self) {
        self.buf.clear()
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

impl<E: Encoder> AsRef<[u8]> for EString<E> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.buf.as_bytes()
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
