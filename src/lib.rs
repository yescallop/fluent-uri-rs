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
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    // clippy::redundant_closure_for_method_calls,
    clippy::semicolon_if_nothing_returned,
    clippy::single_match_else,
)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![no_std]

//! A full-featured URI reference handling library compliant with [RFC 3986].
//!
//! [RFC 3986]: https://datatracker.ietf.org/doc/html/rfc3986/
//!
//! **Examples:** [Parsing](UriRef#examples). [Building](Builder#examples).
//! [Reference resolution](UriRef::resolve_against). [Normalization](UriRef::normalize).
//! [Percent-decoding](EStr#examples).
//! [Percent-encoding](crate::encoding::EString#examples).
//! [Validating URIs](UriRef#terminology).
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
//!   Required for IP address fields in [`Host`] and [`Authority::socket_addrs`].
//!   Disabling `net` will not affect the behavior of [`UriRef::parse`].
//!
//! - `std` (default): Enables [`std`] support. Required for [`Error`] implementations
//!   and [`Authority::socket_addrs`]. Disabling `std` while enabling `net`
//!   requires [`core::net`] and a minimum Rust version of `1.77`.
//!
//! - `serde`: Enables [`serde`] support. Required for [`Serialize`] and [`Deserialize`]
//!   implementations on [`UriRef`].
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
use internal::{Meta, ToUriRef, Value};

#[cfg(feature = "serde")]
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

/// A [URI reference] defined in RFC 3986, i.e., either a [URI] or a [relative reference].
///
/// [URI reference]: https://datatracker.ietf.org/doc/html/rfc3986/#section-4.1
/// [URI]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3
/// [relative reference]: https://datatracker.ietf.org/doc/html/rfc3986/#section-4.2
///
/// # Terminology
///
/// A *URI reference* can either be a *URI* or a *relative reference*.
/// If it contains a scheme (like `http`, `ftp`, etc.), it is a URI.
/// For example, `foo:bar` is a URI. If it does not contain a scheme,
/// it is a relative reference. For example, `baz` is a relative reference.
/// Both URIs and relative references are considered URI references.
/// You can combine [`parse`] and [`is_uri`] to check whether a string
/// is a valid URI, for example:
///
/// [`parse`]: Self::parse
/// [`is_uri`]: Self::is_uri
///
/// ```
/// use fluent_uri::UriRef;
///
/// fn is_valid_uri(s: &str) -> bool {
///     UriRef::parse(s).is_ok_and(|r| r.is_uri())
/// }
///
/// assert!(is_valid_uri("foo:bar"));
/// assert!(!is_valid_uri("baz"));
/// ```
///
/// # Variants
///
/// Two variants of `UriRef` are available: `UriRef<&str>` (borrowed) and `UriRef<String>` (owned).
///
/// `UriRef<&'a str>` outputs references with lifetime `'a` where possible
/// (thanks to [`borrow-or-share`](borrow_or_share)):
///
/// ```
/// use fluent_uri::UriRef;
///
/// // Keep a reference to the path after dropping the `UriRef`.
/// let path = UriRef::parse("foo:bar")?.path();
/// assert_eq!(path, "bar");
/// # Ok::<_, fluent_uri::error::ParseError>(())
/// ```
///
/// # Comparison
///
/// `UriRef`s are compared [lexicographically](Ord#lexicographical-comparison)
/// by their byte values. Normalization is **not** performed prior to comparison.
///
/// # Examples
///
/// Parse and extract components from a URI reference:
///
/// ```
/// use fluent_uri::{
///     component::{Host, Scheme},
///     encoding::EStr,
///     UriRef,
/// };
///
/// const SCHEME_FOO: &Scheme = Scheme::new_or_panic("foo");
///
/// let uri_ref = UriRef::parse("foo://user@example.com:8042/over/there?name=ferret#nose")?;
///
/// assert_eq!(uri_ref.scheme().unwrap(), SCHEME_FOO);
///
/// let auth = uri_ref.authority().unwrap();
/// assert_eq!(auth.as_str(), "user@example.com:8042");
/// assert_eq!(auth.userinfo().unwrap(), "user");
/// assert_eq!(auth.host(), "example.com");
/// assert!(matches!(auth.host_parsed(), Host::RegName(name) if name == "example.com"));
/// assert_eq!(auth.port().unwrap(), "8042");
/// assert_eq!(auth.port_to_u16(), Ok(Some(8042)));
///
/// assert_eq!(uri_ref.path(), "/over/there");
/// assert_eq!(uri_ref.query().unwrap(), "name=ferret");
/// assert_eq!(uri_ref.fragment().unwrap(), "nose");
/// # Ok::<_, fluent_uri::error::ParseError>(())
/// ```
///
/// Parse into and convert between `UriRef<&str>` and `UriRef<String>`:
///
/// ```
/// use fluent_uri::UriRef;
///
/// let s = "http://example.com/";
///
/// // Parse into a `UriRef<&str>` from a string slice.
/// let uri_ref: UriRef<&str> = UriRef::parse(s)?;
///
/// // Parse into a `UriRef<String>` from an owned string.
/// let uri_ref_owned: UriRef<String> = UriRef::parse(s.to_owned()).map_err(|e| e.strip_input())?;
///
/// // Convert a `UriRef<&str>` to `UriRef<String>`.
/// let uri_ref_owned: UriRef<String> = uri_ref.to_owned();
///
/// // Borrow a `UriRef<String>` as `UriRef<&str>`.
/// let uri_ref: UriRef<&str> = uri_ref_owned.borrow();
/// # Ok::<_, fluent_uri::error::ParseError>(())
/// ```
#[derive(Clone, Copy)]
pub struct UriRef<T> {
    /// Value of the URI reference.
    val: T,
    /// Metadata of the URI reference.
    /// Should be identical to parser output with `val` as input.
    meta: Meta,
}

impl<T> UriRef<T> {
    /// Parses a URI reference from a string into a `UriRef`.
    ///
    /// The return type is
    ///
    /// - `Result<UriRef<&str>, ParseError>` for `I = &str`;
    /// - `Result<UriRef<String>, ParseError<String>>` for `I = String`.
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
        I: ToUriRef<Val = T>,
    {
        input.to_uri_ref()
    }
}

impl UriRef<String> {
    /// Creates a new builder for URI reference.
    #[inline]
    pub fn builder() -> BuilderStart {
        Builder::new()
    }

    /// Borrows this `UriRef<String>` as `UriRef<&str>`.
    #[allow(clippy::should_implement_trait)]
    #[inline]
    #[must_use]
    pub fn borrow(&self) -> UriRef<&str> {
        UriRef {
            val: &self.val,
            meta: self.meta,
        }
    }

    /// Consumes this `UriRef<String>` and yields the underlying [`String`].
    #[inline]
    #[must_use]
    pub fn into_string(self) -> String {
        self.val
    }
}

impl UriRef<&str> {
    /// Creates a new `UriRef<String>` by cloning the contents of this `UriRef<&str>`.
    #[inline]
    #[must_use]
    pub fn to_owned(&self) -> UriRef<String> {
        UriRef {
            val: self.val.to_owned(),
            meta: self.meta,
        }
    }
}

impl<T: Bos<str>> UriRef<T> {
    fn len(&self) -> usize {
        self.as_str().len()
    }

    fn as_ref(&self) -> UriRef<&str> {
        UriRef {
            val: self.as_str(),
            meta: self.meta,
        }
    }
}

impl<'i, 'o, T: BorrowOrShare<'i, 'o, str>> UriRef<T> {
    /// Returns the URI reference as a string slice.
    #[must_use]
    pub fn as_str(&'i self) -> &'o str {
        self.val.borrow_or_share()
    }

    /// Returns a string slice of the `UriRef` between the given indexes.
    fn slice(&'i self, start: usize, end: usize) -> &'o str {
        &self.as_str()[start..end]
    }

    /// Returns an `EStr` slice of the `UriRef` between the given indexes.
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
    /// use fluent_uri::{component::Scheme, UriRef};
    ///
    /// const SCHEME_HTTP: &Scheme = Scheme::new_or_panic("http");
    ///
    /// let uri_ref = UriRef::parse("http://example.com/")?;
    /// assert_eq!(uri_ref.scheme(), Some(SCHEME_HTTP));
    ///
    /// let uri_ref = UriRef::parse("/path/to/file")?;
    /// assert_eq!(uri_ref.scheme(), None);
    /// # Ok::<_, fluent_uri::error::ParseError>(())
    /// ```
    #[must_use]
    pub fn scheme(&'i self) -> Option<&'o Scheme> {
        let end = self.meta.scheme_end?.get();
        Some(Scheme::new_validated(self.slice(0, end)))
    }

    /// Returns the optional [authority] component.
    ///
    /// [authority]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::UriRef;
    ///
    /// let uri_ref = UriRef::parse("http://example.com/")?;
    /// assert!(uri_ref.authority().is_some());
    ///
    /// let uri_ref = UriRef::parse("mailto:user@example.com")?;
    /// assert!(uri_ref.authority().is_none());
    /// # Ok::<_, fluent_uri::error::ParseError>(())
    /// ```
    #[must_use]
    pub fn authority(&'i self) -> Option<Authority<'o>> {
        let mut meta = self.meta.auth_meta?;
        let start = match self.meta.scheme_end {
            Some(i) => i.get() + 3,
            None => 2,
        };
        let end = self.meta.path_bounds.0;

        meta.host_bounds.0 -= start;
        meta.host_bounds.1 -= start;

        Some(Authority::new(self.slice(start, end), meta))
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
    /// use fluent_uri::UriRef;
    ///
    /// let uri_ref = UriRef::parse("http://example.com/")?;
    /// assert_eq!(uri_ref.path(), "/");
    ///
    /// let uri_ref = UriRef::parse("mailto:user@example.com")?;
    /// assert_eq!(uri_ref.path(), "user@example.com");
    ///
    /// let uri_ref = UriRef::parse("?lang=en")?;
    /// assert_eq!(uri_ref.path(), "");
    /// # Ok::<_, fluent_uri::error::ParseError>(())
    /// ```
    #[must_use]
    pub fn path(&'i self) -> &'o EStr<Path> {
        self.eslice(self.meta.path_bounds.0, self.meta.path_bounds.1)
    }

    /// Returns the optional [query] component.
    ///
    /// [query]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.4
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::{encoding::EStr, UriRef};
    ///
    /// let uri_ref = UriRef::parse("http://example.com/?lang=en")?;
    /// assert_eq!(uri_ref.query(), Some(EStr::new_or_panic("lang=en")));
    ///
    /// let uri_ref = UriRef::parse("ftp://192.0.2.1/")?;
    /// assert_eq!(uri_ref.query(), None);
    /// # Ok::<_, fluent_uri::error::ParseError>(())
    /// ```
    #[must_use]
    pub fn query(&'i self) -> Option<&'o EStr<Query>> {
        let end = self.meta.query_end?.get();
        Some(self.eslice(self.meta.path_bounds.1 + 1, end))
    }

    fn fragment_start(&self) -> Option<usize> {
        let query_or_path_end = match self.meta.query_end {
            Some(i) => i.get(),
            None => self.meta.path_bounds.1,
        };
        (query_or_path_end != self.len()).then_some(query_or_path_end + 1)
    }

    /// Returns the optional [fragment] component.
    ///
    /// [fragment]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.5
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::{encoding::EStr, UriRef};
    ///
    /// let uri_ref = UriRef::parse("http://example.com/#usage")?;
    /// assert_eq!(uri_ref.fragment(), Some(EStr::new_or_panic("usage")));
    ///
    /// let uri_ref = UriRef::parse("ftp://192.0.2.1/")?;
    /// assert_eq!(uri_ref.fragment(), None);
    /// # Ok::<_, fluent_uri::error::ParseError>(())
    /// ```
    #[must_use]
    pub fn fragment(&'i self) -> Option<&'o EStr<Fragment>> {
        self.fragment_start().map(|i| self.eslice(i, self.len()))
    }

    /// Resolves the URI reference against the given base URI
    /// and returns the target URI.
    ///
    /// The base URI **must** contain a scheme and no fragment, i.e.,
    /// match the [`absolute-URI`] ABNF rule from RFC 3986.
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
    /// Use [`normalize`] if necessary.
    ///
    /// [`absolute-URI`]: https://datatracker.ietf.org/doc/html/rfc3986/#section-4.3
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
    /// use fluent_uri::UriRef;
    ///
    /// let base = UriRef::parse("http://example.com/foo/bar")?;
    ///
    /// assert_eq!(UriRef::parse("baz")?.resolve_against(&base)?, "http://example.com/foo/baz");
    /// assert_eq!(UriRef::parse("../baz")?.resolve_against(&base)?, "http://example.com/baz");
    /// assert_eq!(UriRef::parse("?baz")?.resolve_against(&base)?, "http://example.com/foo/bar?baz");
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    pub fn resolve_against<U: Bos<str>>(
        &self,
        base: &UriRef<U>,
    ) -> Result<UriRef<String>, ResolveError> {
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
    /// use fluent_uri::UriRef;
    ///
    /// let uri_ref = UriRef::parse("eXAMPLE://a/./b/../b/%63/%7bfoo%7d")?;
    /// assert_eq!(uri_ref.normalize(), "example://a/b/c/%7Bfoo%7D");
    /// # Ok::<_, fluent_uri::error::ParseError>(())
    /// ```
    #[must_use]
    pub fn normalize(&self) -> UriRef<String> {
        normalizer::normalize(self.as_ref())
    }

    /// Checks whether the URI reference is a [URI], i.e., contains a scheme.
    ///
    /// This method is equivalent to [`has_scheme`].
    ///
    /// [URI]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3
    /// [`has_scheme`]: Self::has_scheme
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::UriRef;
    ///
    /// assert!(UriRef::parse("http://example.com/")?.is_uri());
    /// assert!(!UriRef::parse("/path/to/file")?.is_uri());
    /// # Ok::<_, fluent_uri::error::ParseError>(())
    /// ```
    #[must_use]
    pub fn is_uri(&self) -> bool {
        self.has_scheme()
    }

    /// Checks whether the URI reference contains a scheme component.
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::UriRef;
    ///
    /// assert!(UriRef::parse("http://example.com/")?.has_scheme());
    /// assert!(!UriRef::parse("/path/to/file")?.has_scheme());
    /// # Ok::<_, fluent_uri::error::ParseError>(())
    /// ```
    #[must_use]
    pub fn has_scheme(&self) -> bool {
        self.meta.scheme_end.is_some()
    }

    /// Checks whether the URI reference contains an authority component.
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::UriRef;
    ///
    /// assert!(UriRef::parse("http://example.com/")?.has_authority());
    /// assert!(!UriRef::parse("mailto:user@example.com")?.has_authority());
    /// # Ok::<_, fluent_uri::error::ParseError>(())
    /// ```
    #[must_use]
    pub fn has_authority(&self) -> bool {
        self.meta.auth_meta.is_some()
    }

    /// Checks whether the URI reference contains a query component.
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::UriRef;
    ///
    /// assert!(UriRef::parse("http://example.com/?lang=en")?.has_query());
    /// assert!(!UriRef::parse("ftp://192.0.2.1/")?.has_query());
    /// # Ok::<_, fluent_uri::error::ParseError>(())
    /// ```
    #[must_use]
    pub fn has_query(&self) -> bool {
        self.meta.query_end.is_some()
    }

    /// Checks whether the URI reference contains a fragment component.
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::UriRef;
    ///
    /// assert!(UriRef::parse("http://example.com/#usage")?.has_fragment());
    /// assert!(!UriRef::parse("ftp://192.0.2.1/")?.has_fragment());
    /// # Ok::<_, fluent_uri::error::ParseError>(())
    /// ```
    #[must_use]
    pub fn has_fragment(&self) -> bool {
        self.fragment_start().is_some()
    }
}

impl<T: Value> Default for UriRef<T> {
    /// Creates an empty URI reference.
    fn default() -> Self {
        UriRef {
            val: T::default(),
            meta: Meta::default(),
        }
    }
}

impl<T: Bos<str>, U: Bos<str>> PartialEq<UriRef<U>> for UriRef<T> {
    fn eq(&self, other: &UriRef<U>) -> bool {
        self.as_str() == other.as_str()
    }
}

impl<T: Bos<str>> PartialEq<str> for UriRef<T> {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl<T: Bos<str>> PartialEq<UriRef<T>> for str {
    fn eq(&self, other: &UriRef<T>) -> bool {
        self == other.as_str()
    }
}

impl<T: Bos<str>> PartialEq<&str> for UriRef<T> {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl<T: Bos<str>> PartialEq<UriRef<T>> for &str {
    fn eq(&self, other: &UriRef<T>) -> bool {
        *self == other.as_str()
    }
}

impl<T: Bos<str>> Eq for UriRef<T> {}

impl<T: Bos<str>> hash::Hash for UriRef<T> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.as_str().hash(state);
    }
}

impl<T: Bos<str>> PartialOrd for UriRef<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: Bos<str>> Ord for UriRef<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl<T: Bos<str>> AsRef<str> for UriRef<T> {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl<T: Bos<str>> Borrow<str> for UriRef<T> {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl From<UriRef<&str>> for UriRef<String> {
    #[inline]
    fn from(uri_ref: UriRef<&str>) -> Self {
        uri_ref.to_owned()
    }
}

impl FromStr for UriRef<String> {
    type Err = ParseError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        UriRef::parse(s).map(|r| r.to_owned())
    }
}

#[cfg(feature = "serde")]
impl<T: Bos<str>> Serialize for UriRef<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for UriRef<&'de str> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = <&str>::deserialize(deserializer)?;
        UriRef::parse(s).map_err(de::Error::custom)
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for UriRef<String> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        UriRef::parse(s).map_err(de::Error::custom)
    }
}
