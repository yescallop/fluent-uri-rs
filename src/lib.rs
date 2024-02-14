#![allow(clippy::let_unit_value)]
#![warn(missing_debug_implementations, missing_docs, rust_2018_idioms)]
#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

//! An [RFC 3986] compliant generic URI parser and builder.
//!
//! [RFC 3986]: https://datatracker.ietf.org/doc/html/rfc3986/
//!
//! See the documentation of [`Uri`] for usage.
//!
//! # Crate-specific syntax extension
//!
//! This crate incorporates the IPv6 scoped address format of [RFC 4007]
//! to allow parsing and building URIs such as `http://[fe80::1%eth0]`.
//! The syntax extension and a way to opt out are documented at [`Uri::parse`].
//!
//! [RFC 4007]: https://datatracker.ietf.org/doc/html/rfc4007/
//!
//! # Crate features
//!
//! - `net` (default, requires `std`): Enables [`std::net`] support.
//!   Includes [`Authority::to_socket_addrs`], [`Builder::host_port_from_socket_addr`],
//!   and several fields in [`Host`].
//!   Disabling this will not affect the behavior of [`Uri::parse`].
//!
//! - `std` (default): Enables [`std`] support. Includes [`Error`] implementations.
//!
//! [`Error`]: std::error::Error
//! [`Host`]: component::Host

mod builder;
pub mod component;
pub mod encoding;
mod error;
mod fmt;
mod internal;
mod parser;

pub use builder::Builder;
pub use error::ParseError;

extern crate alloc;

use alloc::{borrow::ToOwned, string::String};
use component::{Authority, Scheme};
use core::{
    borrow::Borrow,
    cmp::Ordering,
    hash,
    str::{self, FromStr},
};
use encoding::{
    encoder::{Encoder, Fragment, Path, Query},
    EStr,
};
use internal::{AuthMeta, HostMeta, Meta, Storage, StorageHelper, ToUri};

/// A [URI reference] defined in RFC 3986.
///
/// [URI reference]: https://datatracker.ietf.org/doc/html/rfc3986/#section-4.1
///
/// # Variants
///
/// Two variants of `Uri` are available: `Uri<String>` (owned) and `Uri<&str>` (borrowed).
///
/// `Uri<&'a str>` outputs references with lifetime `'a` where possible:
///
/// ```
/// use fluent_uri::Uri;
///
/// // Drop a temporary `Uri` while keeping the reference to the path.
/// let path = Uri::parse("foo:bar")?.path();
/// assert_eq!(path, "bar");
/// # Ok::<_, fluent_uri::ParseError>(())
/// ```
///
/// # Examples
///
/// Parse into and convert between `Uri<&str>` and `Uri<String>`:
///
/// ```
/// use fluent_uri::Uri;
///
/// let s = "foo:bar";
///
/// // Parse into a `Uri<&str>` from a string slice.
/// let uri: Uri<&str> = Uri::parse(s)?;
///
/// // Parse into a `Uri<String>` from an owned string.
/// let uri_owned: Uri<String> = Uri::parse(s.to_owned()).map_err(|e| e.plain())?;
///
/// // When referencing a `Uri`, use `Uri<&str>`.
/// fn foo(uri: Uri<&str>) {
///     // Convert a `Uri<&str>` to `Uri<String>`.
///     let uri_owned: Uri<String> = uri.to_owned();
/// }
///
/// foo(uri);
/// // Borrow a `Uri<String>` as `Uri<&str>`.
/// foo(uri_owned.borrow());
/// # Ok::<_, fluent_uri::ParseError>(())
/// ```
///
/// See the documentation of [`Builder`] for examples of building a `Uri` from its components.
#[derive(Clone, Copy, Default)]
pub struct Uri<T: Storage> {
    /// Stores the URI reference. Guaranteed to contain only ASCII bytes.
    storage: T,
    /// Metadata of the URI reference.
    /// Guaranteed identical to parser output with `storage` as input.
    meta: Meta,
}

impl<T: Storage> Uri<T> {
    /// Parses a URI reference from a string into a `Uri`.
    ///
    /// The return type is
    ///
    /// - `Result<Uri<String>, ParseError<String>>` for `I = String`.
    /// - `Result<Uri<&str>, ParseError>` for `I = &S` where `S: AsRef<str> + ?Sized`.
    ///
    /// You may recover an input [`String`] by calling [`ParseError::into_input`].
    ///
    /// # Behavior
    ///
    /// This function validates the input according to [RFC 3986],
    /// with the only exception that a non-empty case-sensitive IPv6 zone identifier
    /// containing only [unreserved] characters is accepted,
    /// such as `eth0` in `http://[fe80::1%eth0]`.
    /// If this is not desirable, consider rejecting an output `Uri`
    /// with [`is_strictly_rfc3986_compliant`] returning `false`.
    ///
    /// [RFC 3986]: https://datatracker.ietf.org/doc/html/rfc3986/
    /// [unreserved]: https://datatracker.ietf.org/doc/html/rfc3986/#section-2.3
    /// [`is_strictly_rfc3986_compliant`]: Self::is_strictly_rfc3986_compliant
    ///
    /// # Panics
    ///
    /// Panics if the input length is greater than [`u32::MAX`].
    #[inline]
    pub fn parse<I>(input: I) -> Result<Uri<I::Storage>, I::Err>
    where
        I: ToUri<Storage = T>,
    {
        input.to_uri()
    }
}

impl Uri<String> {
    /// Creates a new builder for URI reference.
    #[inline]
    pub fn builder() -> Builder {
        Builder::new()
    }

    /// Borrows this `Uri<String>` as `Uri<&str>`.
    #[allow(clippy::should_implement_trait)]
    #[inline]
    pub fn borrow(&self) -> Uri<&str> {
        Uri {
            storage: &self.storage,
            meta: self.meta,
        }
    }

    /// Consumes this `Uri<String>` and yields the underlying [`String`] storage.
    #[inline]
    pub fn into_string(self) -> String {
        self.storage
    }
}

impl<T: Storage> Uri<T> {
    #[inline]
    fn len(&self) -> u32 {
        self.as_str().len() as _
    }
}

impl Uri<&str> {
    /// Creates a new `Uri<String>` by cloning the contents of this `Uri<&str>`.
    #[inline]
    pub fn to_owned(&self) -> Uri<String> {
        Uri {
            storage: self.storage.to_owned(),
            meta: self.meta,
        }
    }
}

impl<'i, 'o, T: StorageHelper<'i, 'o>> Uri<T> {
    /// Returns the URI reference as a string slice.
    #[inline]
    pub fn as_str(&'i self) -> &'o str {
        self.storage.as_str()
    }

    /// Returns a string slice of the `Uri` between the given indexes.
    #[inline]
    fn slice(&'i self, start: u32, end: u32) -> &'o str {
        &self.as_str()[start as usize..end as usize]
    }

    /// Returns an `EStr` slice of the `Uri` between the given indexes.
    #[inline]
    fn eslice<E: Encoder>(&'i self, start: u32, end: u32) -> &'o EStr<E> {
        EStr::new_validated(self.slice(start, end))
    }

    /// Returns the [scheme] component.
    ///
    /// [scheme]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.1
    #[inline]
    pub fn scheme(&'i self) -> Option<&'o Scheme> {
        self.scheme_end
            .map(|i| Scheme::new_validated(self.slice(0, i.get())))
    }

    /// Returns the [authority] component.
    ///
    /// [authority]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2
    #[inline]
    pub fn authority(&self) -> Option<&Authority<T>> {
        if self.auth_meta.is_some() {
            Some(Authority::new(self))
        } else {
            None
        }
    }

    /// Returns the [path] component.
    ///
    /// The returned [`EStr`] slice has [extension methods] for the path component.
    ///
    /// [path]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.3
    /// [extension methods]: EStr#impl-EStr<Path>
    #[inline]
    pub fn path(&'i self) -> &'o EStr<Path> {
        self.eslice(self.path_bounds.0, self.path_bounds.1)
    }

    /// Returns the [query] component.
    ///
    /// [query]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.4
    #[inline]
    pub fn query(&'i self) -> Option<&'o EStr<Query>> {
        self.query_end
            .map(|i| self.eslice(self.path_bounds.1 + 1, i.get()))
    }

    #[inline]
    fn fragment_start(&self) -> Option<u32> {
        let query_or_path_end = self
            .query_end
            .map(|i| i.get())
            .unwrap_or(self.path_bounds.1);
        (query_or_path_end != self.len()).then_some(query_or_path_end + 1)
    }

    /// Returns the [fragment] component.
    ///
    /// [fragment]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.5
    #[inline]
    pub fn fragment(&'i self) -> Option<&'o EStr<Fragment>> {
        self.fragment_start().map(|i| self.eslice(i, self.len()))
    }

    /// Returns `true` if the URI reference is [relative], i.e., without a scheme.
    ///
    /// Note that this method is not the opposite of [`is_absolute`].
    ///
    /// [relative]: https://datatracker.ietf.org/doc/html/rfc3986/#section-4.2
    /// [`is_absolute`]: Self::is_absolute
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let uri = Uri::parse("/path/to/file")?;
    /// assert!(uri.is_relative());
    /// let uri = Uri::parse("http://example.com/")?;
    /// assert!(!uri.is_relative());
    /// # Ok::<_, fluent_uri::ParseError>(())
    /// ```
    #[inline]
    pub fn is_relative(&self) -> bool {
        self.scheme_end.is_none()
    }

    /// Returns `true` if the URI reference is [absolute], i.e., with a scheme and without a fragment.
    ///
    /// Note that this method is not the opposite of [`is_relative`].
    ///
    /// [absolute]: https://datatracker.ietf.org/doc/html/rfc3986/#section-4.3
    /// [`is_relative`]: Self::is_relative
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let uri = Uri::parse("http://example.com/")?;
    /// assert!(uri.is_absolute());
    /// let uri = Uri::parse("http://example.com/#title1")?;
    /// assert!(!uri.is_absolute());
    /// let uri = Uri::parse("/path/to/file")?;
    /// assert!(!uri.is_absolute());
    /// # Ok::<_, fluent_uri::ParseError>(())
    /// ```
    #[inline]
    pub fn is_absolute(&self) -> bool {
        self.scheme_end.is_some() && self.fragment_start().is_none()
    }

    /// Returns `true` if the URI reference is strictly RFC 3986 compliant,
    /// i.e., it does not contain an IPv6 zone identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let uri = Uri::parse("http://[fe80::1]/")?;
    /// assert!(uri.is_strictly_rfc3986_compliant());
    ///
    /// let uri = Uri::parse("http://[fe80::1%eth0]/")?;
    /// assert!(!uri.is_strictly_rfc3986_compliant());
    /// # Ok::<_, fluent_uri::ParseError>(())
    /// ```
    pub fn is_strictly_rfc3986_compliant(&self) -> bool {
        !matches!(
            self.auth_meta,
            Some(AuthMeta {
                host_meta: HostMeta::Ipv6Zoned(..),
                ..
            })
        )
    }
}

impl<T: Storage, U: Storage> PartialEq<Uri<U>> for Uri<T> {
    #[inline]
    fn eq(&self, other: &Uri<U>) -> bool {
        self.as_str() == other.as_str()
    }
}

impl<T: Storage> Eq for Uri<T> {}

impl<T: Storage> hash::Hash for Uri<T> {
    #[inline]
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.as_str().hash(state)
    }
}

impl<T: Storage> PartialOrd for Uri<T> {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.as_str().cmp(other.as_str()))
    }
}

/// Implements ordering of `Uri`s.
///
/// `Uri`s are ordered [lexicographically](Ord#lexicographical-comparison) by their byte values.
/// Normalization is **not** performed prior to ordering.
impl<T: Storage> Ord for Uri<T> {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl<T: Storage> AsRef<str> for Uri<T> {
    #[inline]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl<T: Storage> Borrow<str> for Uri<T> {
    #[inline]
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl From<Uri<&str>> for Uri<String> {
    #[inline]
    fn from(value: Uri<&str>) -> Self {
        value.to_owned()
    }
}

impl FromStr for Uri<String> {
    type Err = ParseError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uri::parse(s).map(|uri| uri.to_owned())
    }
}
