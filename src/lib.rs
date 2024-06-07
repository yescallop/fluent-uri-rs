#![warn(
    future_incompatible,
    missing_debug_implementations,
    missing_docs,
    nonstandard_style,
    rust_2018_idioms,
    clippy::checked_conversions,
    clippy::if_not_else,
    clippy::ignored_unit_patterns,
    clippy::map_unwrap_or,
    clippy::must_use_candidate,
    clippy::semicolon_if_nothing_returned,
    clippy::single_match_else,
    // clippy::missing_errors_doc,
    // clippy::redundant_closure_for_method_calls,
)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![no_std]

//! A full-featured URI handling library compliant with [RFC 3986].
//!
//! [RFC 3986]: https://datatracker.ietf.org/doc/html/rfc3986/
//!
//! **Examples:** [Parsing](Uri#examples). [Building](Builder#examples).
//! [Reference resolution](Uri::resolve_against). [Normalization](Uri::normalize).
//! [Percent-decoding](crate::encoding::EStr#examples).
//! [Percent-encoding](crate::encoding::EString#examples).
//!
//! # Guidance for crate users
//!
//! Advice for designers of new URI schemes can be found in [RFC 7595].
//! Guidance on the specification of URI substructure in standards
//! can be found in [RFC 8820]. The crate author recommends [RFC 9413]
//! for further reading as the long-term interoperability
//! of URI schemes may be of concern.
//!
//! [RFC 7595]: https://datatracker.ietf.org/doc/html/rfc7595/
//! [RFC 8820]: https://datatracker.ietf.org/doc/html/rfc8820/
//! [RFC 9413]: https://datatracker.ietf.org/doc/html/rfc9413/
//!
//! # Crate features
//!
//! - `net` (default): Enables [`std::net`] support.
//!   Required for IP address fields in [`Host`] and [`Authority::to_socket_addrs`].
//!   Disabling `net` will not affect the behavior of [`Uri::parse`].
//!
//! - `std` (default): Enables [`std`] support. Required for [`Error`] implementations
//!   and [`Authority::to_socket_addrs`]. Disabling `std` while enabling `net`
//!   requires [`core::net`] and a minimum Rust version of `1.77`.
//!
//! - `serde`: Enables [`serde`] support. Required for [`Serialize`] and [`Deserialize`]
//!   implementations on [`Uri`].
//!
//! [`Host`]: component::Host
//! [`Error`]: std::error::Error

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
use builder::BuilderStart;
use component::{Authority, Scheme};
use core::{
    borrow::Borrow,
    cmp::Ordering,
    hash,
    str::{self, FromStr},
};
use encoding::{
    encoder::{Fragment, Path, Query},
    EStr, Encoder,
};
use error::{ParseError, ResolveError};
use internal::{Meta, ToUri, Value};

#[cfg(feature = "serde")]
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

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
/// let s = "http://example.com/";
///
/// // Parse into a `Uri<&str>` from a string slice.
/// let uri: Uri<&str> = Uri::parse(s)?;
///
/// // Parse into a `Uri<String>` from an owned string.
/// let uri_owned: Uri<String> = Uri::parse(s.to_owned()).map_err(|e| e.strip_input())?;
///
/// // Convert a `Uri<&str>` to `Uri<String>`.
/// let uri_owned: Uri<String> = uri.to_owned();
///
/// // Borrow a `Uri<String>` as `Uri<&str>`.
/// let uri: Uri<&str> = uri_owned.borrow();
/// # Ok::<_, fluent_uri::error::ParseError>(())
/// ```
///
/// Parse and extract components from a URI reference:
///
/// ```
/// use fluent_uri::{
///     component::{Host, Scheme},
///     encoding::EStr,
///     Uri,
/// };
///
/// let uri = Uri::parse("http://user@example.com:8042/over/there?name=ferret#nose")?;
///
/// assert_eq!(uri.scheme().unwrap(), Scheme::new_or_panic("http"));
///
/// let auth = uri.authority().unwrap();
/// assert_eq!(auth.as_str(), "user@example.com:8042");
/// assert_eq!(auth.userinfo().unwrap(), "user");
/// assert_eq!(auth.host(), "example.com");
/// assert!(matches!(auth.host_parsed(), Host::RegName(name) if name == "example.com"));
/// assert_eq!(auth.port().unwrap(), "8042");
/// assert_eq!(auth.port_to_u16(), Ok(Some(8042)));
///
/// assert_eq!(uri.path(), "/over/there");
/// assert_eq!(uri.query().unwrap(), "name=ferret");
/// assert_eq!(uri.fragment().unwrap(), "nose");
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
    /// the [`URI-reference`] ABNF rule from RFC 3986.
    ///
    /// From a [`ParseError<String>`], you may recover or strip the input
    /// by calling [`into_input`] or [`strip_input`] on it.
    ///
    /// [`URI-reference`]: https://datatracker.ietf.org/doc/html/rfc3986/#section-4.1
    /// [`into_input`]: ParseError::into_input
    /// [`strip_input`]: ParseError::strip_input
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
    pub fn builder() -> BuilderStart {
        Builder::new()
    }

    /// Borrows this `Uri<String>` as `Uri<&str>`.
    #[allow(clippy::should_implement_trait)]
    #[inline]
    #[must_use]
    pub fn borrow(&self) -> Uri<&str> {
        Uri {
            val: &self.val,
            meta: self.meta,
        }
    }

    /// Consumes this `Uri<String>` and yields the underlying [`String`].
    #[inline]
    #[must_use]
    pub fn into_string(self) -> String {
        self.val
    }
}

impl Uri<&str> {
    /// Creates a new `Uri<String>` by cloning the contents of this `Uri<&str>`.
    #[inline]
    #[must_use]
    pub fn to_owned(&self) -> Uri<String> {
        Uri {
            val: self.val.to_owned(),
            meta: self.meta,
        }
    }
}

impl<T: Bos<str>> Uri<T> {
    fn len(&self) -> usize {
        self.as_str().len()
    }

    fn as_ref(&self) -> Uri<&str> {
        Uri {
            val: self.as_str(),
            meta: self.meta,
        }
    }
}

impl<'i, 'o, T: BorrowOrShare<'i, 'o, str>> Uri<T> {
    /// Returns the URI reference as a string slice.
    #[must_use]
    pub fn as_str(&'i self) -> &'o str {
        self.val.borrow_or_share()
    }

    /// Returns a string slice of the `Uri` between the given indexes.
    fn slice(&'i self, start: usize, end: usize) -> &'o str {
        &self.as_str()[start..end]
    }

    /// Returns an `EStr` slice of the `Uri` between the given indexes.
    fn eslice<E: Encoder>(&'i self, start: usize, end: usize) -> &'o EStr<E> {
        EStr::new_validated(self.slice(start, end))
    }

    /// Returns the optional [scheme] component.
    ///
    /// Note that the scheme component is *case-insensitive*.
    /// See the documentation of [`Scheme`] for more details on comparison.
    ///
    /// [scheme]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.1
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::{component::Scheme, Uri};
    ///
    /// const SCHEME_HTTP: &Scheme = Scheme::new_or_panic("http");
    ///
    /// let uri = Uri::parse("http://example.com/")?;
    /// assert_eq!(uri.scheme(), Some(SCHEME_HTTP));
    ///
    /// let uri = Uri::parse("/path/to/file")?;
    /// assert_eq!(uri.scheme(), None);
    /// # Ok::<_, fluent_uri::error::ParseError>(())
    /// ```
    #[must_use]
    pub fn scheme(&'i self) -> Option<&'o Scheme> {
        self.scheme_end
            .map(|i| Scheme::new_validated(self.slice(0, i.get())))
    }

    /// Returns the optional [authority] component.
    ///
    /// [authority]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let uri = Uri::parse("http://example.com/")?;
    /// assert!(uri.authority().is_some());
    ///
    /// let uri = Uri::parse("mailto:user@example.com")?;
    /// assert!(uri.authority().is_none());
    /// # Ok::<_, fluent_uri::error::ParseError>(())
    /// ```
    #[must_use]
    pub fn authority(&self) -> Option<&Authority<T>> {
        if self.auth_meta.is_some() {
            Some(Authority::new(self))
        } else {
            None
        }
    }

    /// Returns the [path] component.
    ///
    /// The path component is always present, although it may be empty.
    ///
    /// The returned [`EStr`] slice has [extension methods] for the path component.
    ///
    /// [path]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.3
    /// [extension methods]: EStr#impl-EStr<Path>
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let uri = Uri::parse("http://example.com/")?;
    /// assert_eq!(uri.path(), "/");
    ///
    /// let uri = Uri::parse("mailto:user@example.com")?;
    /// assert_eq!(uri.path(), "user@example.com");
    ///
    /// let uri = Uri::parse("?lang=en")?;
    /// assert_eq!(uri.path(), "");
    /// # Ok::<_, fluent_uri::error::ParseError>(())
    /// ```
    #[must_use]
    pub fn path(&'i self) -> &'o EStr<Path> {
        self.eslice(self.path_bounds.0, self.path_bounds.1)
    }

    /// Returns the optional [query] component.
    ///
    /// [query]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.4
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::{encoding::EStr, Uri};
    ///
    /// let uri = Uri::parse("http://example.com/?lang=en")?;
    /// assert_eq!(uri.query(), Some(EStr::new_or_panic("lang=en")));
    ///
    /// let uri = Uri::parse("ftp://192.0.2.1/")?;
    /// assert_eq!(uri.query(), None);
    /// # Ok::<_, fluent_uri::error::ParseError>(())
    /// ```
    #[must_use]
    pub fn query(&'i self) -> Option<&'o EStr<Query>> {
        self.query_end
            .map(|i| self.eslice(self.path_bounds.1 + 1, i.get()))
    }

    fn fragment_start(&self) -> Option<usize> {
        let query_or_path_end = self.query_end.map_or(self.path_bounds.1, |i| i.get());
        (query_or_path_end != self.len()).then_some(query_or_path_end + 1)
    }

    /// Returns the optional [fragment] component.
    ///
    /// [fragment]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.5
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::{encoding::EStr, Uri};
    ///
    /// let uri = Uri::parse("http://example.com/#usage")?;
    /// assert_eq!(uri.fragment(), Some(EStr::new_or_panic("usage")));
    ///
    /// let uri = Uri::parse("ftp://192.0.2.1/")?;
    /// assert_eq!(uri.fragment(), None);
    /// # Ok::<_, fluent_uri::error::ParseError>(())
    /// ```
    #[must_use]
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
    #[must_use]
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
    #[must_use]
    pub fn is_absolute_uri(&self) -> bool {
        self.scheme_end.is_some() && self.fragment_start().is_none()
    }

    /// Resolves the URI reference against the given base URI
    /// and returns the target URI.
    ///
    /// The base URI **must** be an [absolute URI] in the first place.
    ///
    /// This method applies the reference resolution algorithm defined in
    /// [Section 5 of RFC 3986](https://datatracker.ietf.org/doc/html/rfc3986/#section-5),
    /// except for the following deviations:
    ///
    /// - If `base` contains no authority and its path is [rootless], then
    ///   `self` **must** either contain a scheme, be empty, or start with `'#'`.
    /// - When the target URI contains no authority and its path would start
    ///   with `"//"`, the string `"/."` is prepended to the path. This closes a
    ///   loophole in the original algorithm that resolving `".//@@"` against
    ///   `"foo:/"` yields `"foo://@@"` which is not a valid URI.
    /// - Percent-encoded dot segments (e.g. `"%2E"` and `".%2e"`) are also removed.
    ///   This closes a loophole in the original algorithm that resolving `".."`
    ///   against `"foo:/bar/.%2E/"` yields `"foo:/bar/"`, while first
    ///   normalizing the base URI and then resolving `".."` against it yields `"foo:/"`.
    /// - A slash (`'/'`) is appended to the base URI when it ends with a double-dot
    ///   segment. This closes a loophole in the original algorithm that resolving
    ///   `"."` against `"foo:/bar/.."` yields `"foo:/bar/"`, while first
    ///   normalizing the base URI and then resolving `"."` against it yields `"foo:/"`.
    ///
    /// No normalization except the removal of dot segments will be performed.
    /// Use [`normalize`] if need be.
    ///
    /// [absolute URI]: Self::is_absolute_uri
    /// [rootless]: EStr::<Path>::is_rootless
    /// [`normalize`]: Self::normalize
    ///
    /// This method has the property that
    /// `self.resolve_against(base).unwrap().normalize()` equals
    /// `self.normalize().resolve_against(&base.normalize()).unwrap()`
    /// when no panic occurs.
    ///
    /// # Errors
    ///
    /// Returns `Err` if any of the above two **must**s is violated.
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let base = Uri::parse("http://example.com/foo/bar")?;
    ///
    /// assert_eq!(Uri::parse("baz")?.resolve_against(&base)?, "http://example.com/foo/baz");
    /// assert_eq!(Uri::parse("../baz")?.resolve_against(&base)?, "http://example.com/baz");
    /// assert_eq!(Uri::parse("?baz")?.resolve_against(&base)?, "http://example.com/foo/bar?baz");
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    pub fn resolve_against<U: Bos<str>>(&self, base: &Uri<U>) -> Result<Uri<String>, ResolveError> {
        resolver::resolve(base.as_ref(), self.as_ref())
    }

    /// Normalizes the URI reference.
    ///
    /// This method applies the syntax-based normalization described in
    /// [Section 6.2.2 of RFC 3986](https://datatracker.ietf.org/doc/html/rfc3986/#section-6.2.2),
    /// which is effectively equivalent to taking the following steps in order:
    ///
    /// - Decode any percent-encoded octet that corresponds to an unreserved character.
    /// - Uppercase the hexadecimal digits within all percent-encoded octets.
    /// - Lowercase the scheme and the host except the percent-encoded octets.
    /// - Turn any IPv6 literal address into its canonical form as per
    ///   [RFC 5952](https://datatracker.ietf.org/doc/html/rfc5952/).
    /// - If the port is empty, remove its `':'` delimiter.
    /// - If the URI reference contains a scheme and an absolute path,
    ///   apply the [`remove_dot_segments`] algorithm to the path, taking account of
    ///   percent-encoded dot segments as described at [`resolve_against`].
    /// - If the URI reference contains no authority and its path would start with
    ///   `"//"`, prepend `"/."` to the path.
    ///
    /// This method is idempotent: `self.normalize()` equals `self.normalize().normalize()`.
    ///
    /// [`remove_dot_segments`]: https://datatracker.ietf.org/doc/html/rfc3986/#section-5.2.4
    /// [`resolve_against`]: Self::resolve_against
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let uri = Uri::parse("eXAMPLE://a/./b/../b/%63/%7bfoo%7d")?;
    /// assert_eq!(uri.normalize(), "example://a/b/c/%7Bfoo%7D");
    /// # Ok::<_, fluent_uri::error::ParseError>(())
    /// ```
    #[must_use]
    pub fn normalize(&self) -> Uri<String> {
        normalizer::normalize(self.as_ref())
    }
}

impl<T: Value> Default for Uri<T> {
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
        self.as_str().hash(state);
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

impl FromStr for Uri<String> {
    type Err = ParseError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uri::parse(s).map(|uri| uri.to_owned())
    }
}

#[cfg(feature = "serde")]
impl<T: Bos<str>> Serialize for Uri<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Uri<&'de str> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = <&str>::deserialize(deserializer)?;
        Uri::parse(s).map_err(de::Error::custom)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Uri<String> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Uri::parse(s).map_err(de::Error::custom)
    }
}
