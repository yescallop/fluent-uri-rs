#![allow(clippy::let_unit_value)]
#![warn(missing_debug_implementations, missing_docs, rust_2018_idioms)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![no_std]

//! A fast, easy generic URI parser and builder compliant with [RFC 3986].
//!
//! [RFC 3986]: https://datatracker.ietf.org/doc/html/rfc3986/
//!
//! **Examples:** [Parsing](Uri#examples). [Building](Builder#examples).
//! [Reference resolution](Uri::resolve). [Normalization](Uri::normalize).
//!
//! # Crate features
//!
//! - `net` (default): Enables [`std::net`] support.
//!   Includes IP address fields in [`Host`] and [`Authority::to_socket_addrs`].
//!   Disabling this will not affect the behavior of [`Uri::parse`].
//!
//! - `std` (default): Enables [`std`] support. Includes [`Error`] implementations
//!   and [`Authority::to_socket_addrs`]. Disabling this while enabling `net`
//!   requires [`core::net`] and a minimum Rust version of `1.77`.
//!
//! [`Error`]: std::error::Error
//! [`Host`]: component::Host

mod builder;
pub mod component;
pub mod encoding;
pub mod error;
mod fmt;
mod internal;
mod normalizer;
mod parser;
mod resolver;

pub use builder::Builder;

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;

#[cfg(all(feature = "net", feature = "std"))]
use std::net;

#[cfg(all(feature = "net", not(feature = "std")))]
use core::net;

use alloc::{borrow::ToOwned, string::String};
use borrow_or_share::{BorrowOrShare, Bos};
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
use error::{ParseError, ResolveError};
use internal::{Meta, ToUri, Val};

/// A [URI reference] defined in RFC 3986.
///
/// [URI reference]: https://datatracker.ietf.org/doc/html/rfc3986/#section-4.1
///
/// # Variants
///
/// Two variants of `Uri` are available: `Uri<&str>` (borrowed) and `Uri<String>` (owned).
///
/// `Uri<&'a str>` outputs references with lifetime `'a` where possible
/// (thanks to [`borrow-or-share`](borrow_or_share)):
///
/// ```
/// use fluent_uri::Uri;
///
/// // Keep a reference to the path after dropping the `Uri`.
/// let path = Uri::parse("foo:bar")?.path();
/// assert_eq!(path, "bar");
/// # Ok::<_, fluent_uri::error::ParseError>(())
/// ```
///
/// # Comparison
///
/// `Uri`s are compared [lexicographically](Ord#lexicographical-comparison)
/// by their byte values. Normalization is **not** performed prior to comparison.
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
/// # Ok::<_, fluent_uri::error::ParseError>(())
/// ```
#[derive(Clone, Copy)]
pub struct Uri<T> {
    /// Value of the URI reference.
    val: T,
    /// Metadata of the URI reference.
    /// Should be identical to parser output with `val` as input.
    meta: Meta,
}

impl<T> Uri<T> {
    /// Parses a URI reference from a string into a `Uri`.
    ///
    /// The return type is
    ///
    /// - `Result<Uri<&str>, ParseError>` for `I = &str`;
    /// - `Result<Uri<String>, ParseError<String>>` for `I = String`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the string does not match
    /// the [`URI-reference`] ABNF rule from RFC 3986 or
    /// if the input length is greater than [`u32::MAX`].
    ///
    /// You may recover an input [`String`] by calling [`ParseError::into_input`].
    ///
    /// [`URI-reference`]: https://datatracker.ietf.org/doc/html/rfc3986/#section-4.1
    pub fn parse<I>(input: I) -> Result<Self, I::Err>
    where
        I: ToUri<Val = T>,
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
            val: &self.val,
            meta: self.meta,
        }
    }

    /// Consumes this `Uri<String>` and yields the underlying [`String`].
    #[inline]
    pub fn into_string(self) -> String {
        self.val
    }
}

impl Uri<&str> {
    /// Creates a new `Uri<String>` by cloning the contents of this `Uri<&str>`.
    #[inline]
    pub fn to_owned(&self) -> Uri<String> {
        Uri {
            val: self.val.to_owned(),
            meta: self.meta,
        }
    }
}

impl<T: Bos<str>> Uri<T> {
    fn len(&self) -> u32 {
        self.as_str().len() as _
    }
}

impl<'i, 'o, T: BorrowOrShare<'i, 'o, str>> Uri<T> {
    /// Returns the URI reference as a string slice.
    pub fn as_str(&'i self) -> &'o str {
        self.val.borrow_or_share()
    }

    /// Returns a string slice of the `Uri` between the given indexes.
    fn slice(&'i self, start: u32, end: u32) -> &'o str {
        &self.as_str()[start as usize..end as usize]
    }

    /// Returns an `EStr` slice of the `Uri` between the given indexes.
    fn eslice<E: Encoder>(&'i self, start: u32, end: u32) -> &'o EStr<E> {
        EStr::new_validated(self.slice(start, end))
    }

    /// Returns the [scheme] component.
    ///
    /// [scheme]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.1
    pub fn scheme(&'i self) -> Option<&'o Scheme> {
        self.scheme_end
            .map(|i| Scheme::new_validated(self.slice(0, i.get())))
    }

    /// Returns the [authority] component.
    ///
    /// [authority]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2
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
    pub fn path(&'i self) -> &'o EStr<Path> {
        self.eslice(self.path_bounds.0, self.path_bounds.1)
    }

    /// Returns the [query] component.
    ///
    /// [query]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.4
    pub fn query(&'i self) -> Option<&'o EStr<Query>> {
        self.query_end
            .map(|i| self.eslice(self.path_bounds.1 + 1, i.get()))
    }

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
    pub fn fragment(&'i self) -> Option<&'o EStr<Fragment>> {
        self.fragment_start().map(|i| self.eslice(i, self.len()))
    }

    /// Checks whether the URI reference is a [relative reference],
    /// i.e., without a scheme.
    ///
    /// Note that this method is not the opposite of [`is_absolute_uri`].
    ///
    /// [relative reference]: https://datatracker.ietf.org/doc/html/rfc3986/#section-4.2
    /// [`is_absolute_uri`]: Self::is_absolute_uri
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let uri = Uri::parse("/path/to/file")?;
    /// assert!(uri.is_relative_reference());
    /// let uri = Uri::parse("http://example.com/")?;
    /// assert!(!uri.is_relative_reference());
    /// # Ok::<_, fluent_uri::error::ParseError>(())
    /// ```
    pub fn is_relative_reference(&self) -> bool {
        self.scheme_end.is_none()
    }

    /// Checks whether the URI reference is an [absolute URI], i.e.,
    /// with a scheme and without a fragment.
    ///
    /// Note that this method is not the opposite of [`is_relative_reference`].
    ///
    /// [absolute URI]: https://datatracker.ietf.org/doc/html/rfc3986/#section-4.3
    /// [`is_relative_reference`]: Self::is_relative_reference
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let uri = Uri::parse("http://example.com/")?;
    /// assert!(uri.is_absolute_uri());
    /// let uri = Uri::parse("http://example.com/#title1")?;
    /// assert!(!uri.is_absolute_uri());
    /// let uri = Uri::parse("/path/to/file")?;
    /// assert!(!uri.is_absolute_uri());
    /// # Ok::<_, fluent_uri::error::ParseError>(())
    /// ```
    pub fn is_absolute_uri(&self) -> bool {
        self.scheme_end.is_some() && self.fragment_start().is_none()
    }

    /// Resolves the URI reference against the given base URI
    /// and returns the target URI.
    ///
    /// The base URI **must** be an [absolute URI] in the first place.
    ///
    /// This method applies the reference resolution algorithm defined in
    /// [Section 5 of RFC 3986](https://datatracker.ietf.org/doc/html/rfc3986/#section-5)
    /// with only two exceptions:
    ///
    /// - If `base` contains no authority component and its path is [rootless], then
    ///   `self` **must** either contain a scheme component, be empty, or start with `'#'`.
    /// - When the target URI contains no authority component and its path would start
    ///   with `"//"`, the string `"/."` is prepended to the path. This is required for
    ///   closing a loophole in the original algorithm so that resolving `.//@@` against
    ///   `foo:/` does not yield `foo://@@` which is not a valid URI.
    ///
    /// No normalization except the removal of *unencoded* dot segments
    /// (`"."` and `".."`, but not their percent-encoded equivalents) will be performed.
    /// Use [`normalize`] if need be.
    ///
    /// [absolute URI]: Self::is_absolute_uri
    /// [rootless]: EStr::<Path>::is_rootless
    /// [`normalize`]: Self::normalize
    ///
    /// # Errors
    ///
    /// Returns `Err` if any of the above two **must**s is violated or
    /// if the output length would be greater than [`u32::MAX`].
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let base = Uri::parse("http://example.com/foo/bar")?;
    ///
    /// assert_eq!(Uri::parse("baz")?.resolve(&base)?, "http://example.com/foo/baz");
    /// assert_eq!(Uri::parse("../baz")?.resolve(&base)?, "http://example.com/baz");
    /// assert_eq!(Uri::parse("?baz")?.resolve(&base)?, "http://example.com/foo/bar?baz");
    ///
    /// // The loophole in the original algorithm is closed.
    /// let base = Uri::parse("foo:/")?;
    /// assert_eq!(Uri::parse(".//@@")?.resolve(&base)?, "foo:/.//@@");
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    pub fn resolve<U: Bos<str>>(&self, base: &Uri<U>) -> Result<Uri<String>, ResolveError> {
        resolver::resolve(base.into(), self.into())
    }

    /// Normalizes the URI reference.
    ///
    /// This method applies the syntax-based normalization described in
    /// [Section 6.2.2 of RFC 3986](https://datatracker.ietf.org/doc/html/rfc3986/#section-6.2.2).
    ///
    /// TODO: Expand the doc.
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let uri = Uri::parse("eXAMPLE://a/./b/../b/%63/%7bfoo%7d")?;
    /// assert_eq!(uri.normalize(), "example://a/b/c/%7Bfoo%7D");
    /// # Ok::<_, Box<fluent_uri::error::ParseError>>(())
    /// ```
    pub fn normalize(&self) -> Uri<String> {
        normalizer::normalize(self.into())
    }
}

impl<T: Val> Default for Uri<T> {
    /// Creates an empty URI reference.
    fn default() -> Self {
        Uri {
            val: T::default(),
            meta: Meta::default(),
        }
    }
}

impl<T: Bos<str>, U: Bos<str>> PartialEq<Uri<U>> for Uri<T> {
    fn eq(&self, other: &Uri<U>) -> bool {
        self.as_str() == other.as_str()
    }
}

impl<T: Bos<str>> PartialEq<str> for Uri<T> {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl<T: Bos<str>> PartialEq<Uri<T>> for str {
    fn eq(&self, other: &Uri<T>) -> bool {
        self == other.as_str()
    }
}

impl<T: Bos<str>> PartialEq<&str> for Uri<T> {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl<T: Bos<str>> PartialEq<Uri<T>> for &str {
    fn eq(&self, other: &Uri<T>) -> bool {
        *self == other.as_str()
    }
}

impl<T: Bos<str>> Eq for Uri<T> {}

impl<T: Bos<str>> hash::Hash for Uri<T> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.as_str().hash(state)
    }
}

impl<T: Bos<str>> PartialOrd for Uri<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: Bos<str>> Ord for Uri<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl<T: Bos<str>> AsRef<str> for Uri<T> {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl<T: Bos<str>> Borrow<str> for Uri<T> {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl From<Uri<&str>> for Uri<String> {
    #[inline]
    fn from(uri: Uri<&str>) -> Self {
        uri.to_owned()
    }
}

impl<'a, T: Bos<str>> From<&'a Uri<T>> for Uri<&'a str> {
    #[inline]
    fn from(uri: &'a Uri<T>) -> Self {
        Uri {
            val: uri.as_str(),
            meta: uri.meta,
        }
    }
}

impl FromStr for Uri<String> {
    type Err = ParseError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uri::parse(s).map(|uri| uri.to_owned())
    }
}
