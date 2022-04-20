use std::{borrow::Borrow, fmt, hash, marker::PhantomData, ops::Deref};

use crate::{Result, SyntaxError};

use super::{
    table::{self, Table},
    EStr, HEX_TABLE,
};

/// A trait used by [`EString`] to specify the table used for encoding.
pub trait Encoder {
    /// The table used for encoding.
    const TABLE: &'static Table;
}

/// A percent-encoded, growable string.
///
/// # Panics
///
/// This struct triggers a compile-time panic if the table specified
/// by `E` is not for encoding.
pub struct EString<E: Encoder> {
    string: String,
    _marker: PhantomData<E>,
}

impl<E: Encoder> EString<E> {
    const ASSERT: () = assert!(E::TABLE.allows_enc(), "table not for encoding");

    /// Creates a new empty `EString`.
    #[inline]
    pub fn new() -> Self {
        EString {
            string: String::new(),
            _marker: PhantomData,
        }
    }

    /// Creates a new empty `EString` with a particular capacity.
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        EString {
            string: String::with_capacity(capacity),
            _marker: PhantomData,
        }
    }

    #[inline]
    unsafe fn from_string_unchecked(string: String) -> Self {
        EString {
            string,
            _marker: PhantomData,
        }
    }

    /// Consumes this `EString` and yields the underlying `String` storage.
    #[inline]
    pub fn into_string(self) -> String {
        self.string
    }

    /// Coerces to an `EStr` slice.
    #[inline]
    pub fn as_estr(&self) -> &EStr {
        // SAFETY: EString guarantees that it is properly encoded.
        unsafe { EStr::new_unchecked(self.as_str()) }
    }

    /// Encodes a byte sequence and appends the result onto the end of this `EString`.
    #[inline]
    pub fn push<S: AsRef<[u8]> + ?Sized>(&mut self, s: &S) {
        super::encode_to(s, E::TABLE, &mut self.string);
    }

    /// Encodes a byte sequence with a sub-encoder and appends the result onto the end of this `EString`.
    ///
    /// A sub-encoder `SubE` of `E` is an encoder such that `SubE::TABLE` is a [subset] of `E::TABLE`.
    ///
    /// [subset]: Table::is_subset
    ///
    /// # Panics
    ///
    /// This function triggers a compile-time panic if `SubE` is not a sub-encoder of `E`, or
    /// if the table specified by `SubE` is not for encoding.
    #[inline]
    #[allow(unused_variables)]
    pub fn push_with<S: AsRef<[u8]> + ?Sized, SubE: Encoder>(&mut self, s: &S, sub_encoder: SubE) {
        struct Assert<SubE: Encoder, E: Encoder> {
            _marker: PhantomData<(SubE, E)>,
        }
        impl<SubE: Encoder, E: Encoder> Assert<SubE, E> {
            const IS_SUB_ENCODER: () = assert!(
                SubE::TABLE.is_subset(E::TABLE),
                "pushing with non-sub-encoder"
            );
        }
        let _ = (Assert::<SubE, E>::IS_SUB_ENCODER, EString::<SubE>::ASSERT);

        super::encode_to(s, SubE::TABLE, &mut self.string);
    }

    /// Encodes a byte and appends the result onto the end of this `EString`.
    #[inline]
    pub fn push_byte(&mut self, x: u8) {
        // SAFETY: The encoded bytes are valid UTF-8.
        let vec = unsafe { self.string.as_mut_vec() };
        if E::TABLE.allows(x) {
            vec.push(x);
        } else {
            vec.extend_from_slice(&[
                b'%',
                HEX_TABLE[x as usize * 2],
                HEX_TABLE[x as usize * 2 + 1],
            ]);
        }
    }

    /// Invokes [`capacity`] on the underlying `String`.
    ///
    /// [`capacity`]: String::capacity
    #[inline]
    pub fn capacity(&self) -> usize {
        self.string.capacity()
    }

    /// Invokes [`reserve`] on the underlying `String`.
    ///
    /// [`reserve`]: String::reserve
    #[inline]
    pub fn reserve(&mut self, additional: usize) {
        self.string.reserve(additional);
    }

    /// Invokes [`reserve_exact`] on the underlying `String`.
    ///
    /// [`reserve_exact`]: String::reserve_exact
    #[inline]
    pub fn reserve_exact(&mut self, additional: usize) {
        self.string.reserve_exact(additional);
    }

    /// Invokes [`shrink_to_fit`] on the underlying `String`.
    ///
    /// [`shrink_to_fit`]: String::shrink_to_fit
    #[inline]
    pub fn shrink_to_fit(&mut self) {
        self.string.shrink_to_fit()
    }

    /// Invokes [`shrink_to`] on the underlying `String`.
    ///
    /// [`shrink_to`]: String::shrink_to
    #[inline]
    pub fn shrink_to(&mut self, min_capacity: usize) {
        self.string.shrink_to(min_capacity)
    }

    /// Invokes [`len`] on the underlying `String`.
    ///
    /// [`len`]: String::len
    #[inline]
    pub fn len(&self) -> usize {
        self.string.len()
    }

    /// Invokes [`is_empty`] on the underlying `String`.
    ///
    /// [`is_empty`]: String::is_empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.string.is_empty()
    }

    /// Invokes [`clear`] on the underlying `String`.
    ///
    /// [`clear`]: String::clear
    #[inline]
    pub fn clear(&mut self) {
        self.string.clear()
    }
}

impl<E: Encoder> TryFrom<String> for EString<E> {
    type Error = SyntaxError;

    #[inline]
    fn try_from(string: String) -> Result<Self> {
        super::validate(&string, E::TABLE)?;
        // SAFETY: We have done the validation.
        Ok(unsafe { EString::from_string_unchecked(string) })
    }
}

impl<E: Encoder> TryFrom<Vec<u8>> for EString<E> {
    type Error = SyntaxError;

    #[inline]
    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        super::validate(&bytes, E::TABLE)?;
        // SAFETY: We have done the validation.
        unsafe {
            let string = String::from_utf8_unchecked(bytes);
            Ok(EString::from_string_unchecked(string))
        }
    }
}

impl<E: Encoder> Deref for EString<E> {
    type Target = EStr;

    #[inline]
    fn deref(&self) -> &EStr {
        self.as_estr()
    }
}

impl<E: Encoder> AsRef<EStr> for EString<E> {
    #[inline]
    fn as_ref(&self) -> &EStr {
        self.as_estr()
    }
}

impl<E: Encoder> AsRef<str> for EString<E> {
    #[inline]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl<E: Encoder> Borrow<str> for EString<E> {
    #[inline]
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl<E: Encoder, F: Encoder> PartialEq<EString<F>> for EString<E> {
    #[inline]
    fn eq(&self, other: &EString<F>) -> bool {
        self.as_str() == other.as_str()
    }
}

impl<E: Encoder> PartialEq<&EStr> for EString<E> {
    #[inline]
    fn eq(&self, other: &&EStr) -> bool {
        self.as_str() == other.as_str()
    }
}

impl<E: Encoder> PartialEq<EStr> for EString<E> {
    #[inline]
    fn eq(&self, other: &EStr) -> bool {
        self.as_str() == other.as_str()
    }
}

impl<E: Encoder> PartialEq<EString<E>> for EStr {
    #[inline]
    fn eq(&self, other: &EString<E>) -> bool {
        self.as_str() == other.as_str()
    }
}

impl<E: Encoder> PartialEq<&str> for EString<E> {
    #[inline]
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
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

impl<E: Encoder> Eq for EString<E> {}

impl<E: Encoder> Clone for EString<E> {
    #[inline]
    fn clone(&self) -> Self {
        EString {
            string: self.string.clone(),
            _marker: PhantomData,
        }
    }

    #[inline]
    fn clone_from(&mut self, source: &Self) {
        self.string.clone_from(&source.string)
    }
}

impl<E: Encoder> fmt::Debug for EString<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EString")
            .field("encoder", &std::any::type_name::<E>())
            .field("contents", &self.string)
            .finish()
    }
}

impl<E: Encoder> fmt::Display for EString<E> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.string, f)
    }
}

impl<E: Encoder> Default for EString<E> {
    #[inline]
    fn default() -> Self {
        EString::new()
    }
}

impl<E: Encoder> hash::Hash for EString<E> {
    #[inline]
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.string.hash(state)
    }
}

/// An encoder for the path component.
#[derive(Clone, Copy, Debug)]
pub struct PathEncoder;

/// An encoder for the query or fragment component.
#[derive(Clone, Copy, Debug)]
pub struct QueryFragmentEncoder;

impl Encoder for PathEncoder {
    const TABLE: &'static Table = table::PATH;
}

impl Encoder for QueryFragmentEncoder {
    const TABLE: &'static Table = table::QUERY_FRAGMENT;
}
