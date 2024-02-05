#![warn(missing_debug_implementations, missing_docs, rust_2018_idioms)]
#![deny(unsafe_op_in_unsafe_fn)]
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

//! An [RFC 3986] compliant generic URI parser.
//!
//! [RFC 3986]: https://datatracker.ietf.org/doc/html/rfc3986/
//!
//! See the documentation of [`Uri`] for more details.
//!
//! # Feature flags
//!
//! - `std`: Enables `std` support (by default).
//!
//!   This includes [`Error`] implementations, `Ip{v4, v6}Addr` support in [`ParsedHost`],
//!   and [`Authority::to_socket_addrs`].
//!
//! [`Error`]: std::error::Error

/// Percent-encoding utilities.
pub mod encoding;
mod error;
mod fmt;
mod internal;
mod parser;

extern crate alloc;

use alloc::{borrow::ToOwned, string::String};
use core::{
    borrow::Borrow,
    cmp::Ordering,
    hash, iter,
    str::{self, FromStr},
};
use encoding::{EStr, Split};
use internal::{AuthMeta, HostMeta, Meta, Storage, StorageHelper, ToUri};
use ref_cast::{ref_cast_custom, RefCastCustom};

#[cfg(feature = "std")]
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, ToSocketAddrs},
};

pub use error::ParseError;

/// A [URI reference] defined in RFC 3986.
///
/// [URI reference]: https://datatracker.ietf.org/doc/html/rfc3986/#section-4.1
///
/// # Variants
///
/// There are two variants of `Uri` in total:
///
/// - `Uri<&str>`: borrowed; immutable.
/// - `Uri<String>`: owned; immutable.
///
/// `Uri<&'a str>` outputs references with lifetime `'a` where possible.
/// This allows you to drop a temporary `Uri` while keeping the output references:
///
/// ```
/// use fluent_uri::Uri;
///
/// let path = Uri::parse("foo:bar")?.path();
/// assert_eq!(path.as_str(), "bar");
/// # Ok::<_, fluent_uri::ParseError>(())
/// ```
///
/// # Examples
///
/// Create and convert between `Uri<&str>` and `Uri<String>`:
///
/// ```
/// use fluent_uri::Uri;
///
/// let s = "http://example.com/";
///
/// // Create a `Uri<&str>` from a string slice.
/// let uri: Uri<&str> = Uri::parse(s)?;
///
/// // Create a `Uri<String>` from an owned string.
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
    /// - `Result<Uri<&str>, ParseError>` for `I = &S` where `S: AsRef<str> + ?Sized`.
    /// - `Result<Uri<String>, ParseError<String>>` for `I = String`.
    ///
    /// You may recover an input [`String`] by calling [`ParseError::into_input`].
    ///
    /// # Behavior
    ///
    /// This function validates the input strictly as per [RFC 3986],
    /// with the only exception that a case-sensitive IPv6 zone identifier containing
    /// only [unreserved] characters is accepted, as in `http://[fe80::1%eth0]`.
    ///
    /// [RFC 3986]: https://datatracker.ietf.org/doc/html/rfc3986/
    /// [unreserved]: https://datatracker.ietf.org/doc/html/rfc3986/#section-2.3
    ///
    /// # Panics
    ///
    /// Panics if the input length is greater than [`i32::MAX`].
    #[inline]
    pub fn parse<I>(input: I) -> Result<Uri<I::Storage>, I::Err>
    where
        I: ToUri<Storage = T>,
    {
        input.to_uri()
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

impl Uri<String> {
    /// Borrows this `Uri<String>` as `Uri<&str>`.
    #[inline]
    #[allow(clippy::should_implement_trait)]
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
    fn eslice(&'i self, start: u32, end: u32) -> &'o EStr {
        EStr::new_validated(self.slice(start, end))
    }

    /// Returns the [scheme] component.
    ///
    /// [scheme]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.1
    #[inline]
    pub fn scheme(&'i self) -> Option<&'o Scheme> {
        self.scheme_end.map(|i| Scheme::new(self.slice(0, i.get())))
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
    /// [path]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.3
    #[inline]
    pub fn path(&'i self) -> &'o Path {
        Path::new(self.eslice(self.path_bounds.0, self.path_bounds.1))
    }

    /// Returns the [query] component.
    ///
    /// [query]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.4
    #[inline]
    pub fn query(&'i self) -> Option<&'o EStr> {
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
    pub fn fragment(&'i self) -> Option<&'o EStr> {
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

/// Implements comparison operations on `Uri`s.
///
/// `Uri`s are compared [lexicographically](Ord#lexicographical-comparison) by their byte values.
/// Normalization is **not** performed prior to comparison.
impl<T: Storage, U: Storage> PartialOrd<Uri<U>> for Uri<T> {
    #[inline]
    fn partial_cmp(&self, other: &Uri<U>) -> Option<Ordering> {
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

/// The [scheme] component of URI reference.
///
/// [scheme]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.1
#[derive(RefCastCustom)]
#[repr(transparent)]
pub struct Scheme {
    inner: str,
}

const ASCII_CASE_MASK: u8 = 0b010_0000;

impl Scheme {
    #[ref_cast_custom]
    #[inline]
    fn new(scheme: &str) -> &Scheme;

    /// Returns the scheme as a string slice.
    ///
    /// Note that the scheme is case-insensitive. You should typically use
    /// [`eq_lowercase`] for testing if the scheme is a desired one.
    ///
    /// [`eq_lowercase`]: Self::eq_lowercase
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let uri = Uri::parse("HTTP://example.com/")?;
    /// let scheme = uri.scheme().unwrap();
    /// assert_eq!(scheme.as_str(), "HTTP");
    /// # Ok::<_, fluent_uri::ParseError>(())
    /// ```
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.inner
    }

    /// Checks if the scheme equals case-insensitively with a lowercase string.
    ///
    /// This method is slightly faster than [`str::eq_ignore_ascii_case`] but will
    /// always return `false` if there is any uppercase letter in the given string.
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let uri = Uri::parse("HTTP://example.com/")?;
    /// let scheme = uri.scheme().unwrap();
    /// assert!(scheme.eq_lowercase("http"));
    /// // Always return `false` if there's any uppercase letter in the given string.
    /// assert!(!scheme.eq_lowercase("hTTp"));
    /// # Ok::<_, fluent_uri::ParseError>(())
    /// ```
    #[inline]
    pub fn eq_lowercase(&self, other: &str) -> bool {
        let (a, b) = (self.inner.as_bytes(), other.as_bytes());
        // The only characters allowed in a scheme are alphabets, digits, "+", "-" and ".",
        // the ASCII codes of which allow us to simply set the sixth bit and compare.
        a.len() == b.len() && iter::zip(a, b).all(|(a, b)| a | ASCII_CASE_MASK == *b)
    }
}

/// The [authority] component of URI reference.
///
/// [authority]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2
#[derive(RefCastCustom)]
#[repr(transparent)]
pub struct Authority<T: Storage> {
    uri: Uri<T>,
}

impl<'i, 'o, T: StorageHelper<'i, 'o>> Authority<T> {
    /// Converts from `&Uri<T>` to `&Authority<T>`,
    /// assuming that authority is present.
    #[ref_cast_custom]
    #[inline]
    fn new(uri: &Uri<T>) -> &Authority<T>;

    #[inline]
    fn meta(&self) -> &AuthMeta {
        self.uri.auth_meta.as_ref().unwrap()
    }

    #[inline]
    fn start(&self) -> u32 {
        self.meta().start.get()
    }

    #[inline]
    fn end(&self) -> u32 {
        self.uri.path_bounds.0
    }

    #[inline]
    fn host_bounds(&self) -> (u32, u32) {
        self.meta().host_bounds
    }

    /// Returns the authority as a string slice.
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let uri = Uri::parse("ftp://user@[fe80::abcd]:6780/")?;
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.as_str(), "user@[fe80::abcd]:6780");
    /// # Ok::<_, fluent_uri::ParseError>(())
    /// ```
    #[inline]
    pub fn as_str(&'i self) -> &'o str {
        self.uri.slice(self.start(), self.end())
    }

    /// Returns the [userinfo] subcomponent.
    ///
    /// [userinfo]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.1
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let uri = Uri::parse("ftp://user@192.168.1.24/")?;
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.userinfo().unwrap(), "user");
    /// # Ok::<_, fluent_uri::ParseError>(())
    /// ```
    #[inline]
    pub fn userinfo(&'i self) -> Option<&'o EStr> {
        let (start, host_start) = (self.start(), self.host_bounds().0);
        (start != host_start).then(|| self.uri.eslice(start, host_start - 1))
    }

    /// Returns the [host] subcomponent.
    ///
    /// [host]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.2
    #[inline]
    pub fn host(&self) -> &Host<T> {
        Host::new(self)
    }

    /// Returns the [port] subcomponent.
    ///
    /// [port]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.3
    ///
    /// Note that in the generic URI syntax, the port may be empty, with leading zeros, or very large.
    /// It is up to you to decide whether to deny such a port, fallback to the scheme's default if it
    /// is empty, ignore the leading zeros, or use a different addressing mechanism that allows a large port.
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let uri = Uri::parse("ssh://device.local:4673/")?;
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.port(), Some("4673"));
    ///
    /// let uri = Uri::parse("ssh://device.local:/")?;
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.port(), Some(""));
    ///
    /// let uri = Uri::parse("ssh://device.local/")?;
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.port(), None);
    /// # Ok::<_, fluent_uri::ParseError>(())
    /// ```
    #[inline]
    pub fn port(&'i self) -> Option<&'o str> {
        let (host_end, end) = (self.host_bounds().1, self.end());
        (host_end != end).then(|| self.uri.slice(host_end + 1, end))
    }

    /// Converts this authority to an iterator of resolved [`SocketAddr`]s.
    ///
    /// The default port is used if the port component is not present or is empty.
    ///
    /// A registered name is **not** normalized prior to resolution and is resolved
    /// with [`ToSocketAddrs`] as is.
    ///
    /// An IPv6 zone identifier is parsed as a 32-bit unsigned integer
    /// with or without leading zeros, or a network interface name on Unix-like systems.
    #[cfg(feature = "std")]
    pub fn to_socket_addrs(
        &'i self,
        default_port: u16,
    ) -> io::Result<impl Iterator<Item = SocketAddr>> {
        let port = self
            .port()
            .filter(|port| !port.is_empty())
            .map(|port| {
                port.parse::<u16>()
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid port value"))
            })
            .transpose()?
            .unwrap_or(default_port);

        match self.host().parsed() {
            ParsedHost::Ipv4(addr) => Ok(vec![(addr, port).into()].into_iter()),
            ParsedHost::Ipv6 { addr, zone_id } => {
                let scope_id = if let Some(zone_id) = zone_id {
                    if let Ok(scope_id) = zone_id.parse::<u32>() {
                        scope_id
                    } else {
                        #[cfg(not(unix))]
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "invalid zone identifier value",
                        ));
                        #[cfg(unix)]
                        {
                            let if_name = std::ffi::CString::new(zone_id).unwrap();
                            // SAFETY: It is safe to pass a valid C string pointer to `if_nametoindex`.
                            let if_index = unsafe { libc::if_nametoindex(if_name.as_ptr()) };
                            if if_index == 0 {
                                return Err(io::Error::last_os_error());
                            }
                            if_index
                        }
                    }
                } else {
                    0
                };
                Ok(vec![SocketAddrV6::new(addr, port, 0, scope_id).into()].into_iter())
            }
            ParsedHost::IpvFuture => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "address mechanism not supported",
            )),
            ParsedHost::RegName(name) => (name.as_str(), port).to_socket_addrs(),
        }
    }
}

/// The [host] subcomponent of authority.
///
/// [host]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.2
#[derive(RefCastCustom)]
#[repr(transparent)]
pub struct Host<T: Storage> {
    auth: Authority<T>,
}

impl<'i, 'o, T: StorageHelper<'i, 'o>> Host<T> {
    #[ref_cast_custom]
    #[inline]
    fn new(auth: &Authority<T>) -> &Host<T>;

    #[inline]
    fn bounds(&self) -> (u32, u32) {
        self.auth.host_bounds()
    }

    #[inline]
    fn meta(&self) -> &HostMeta {
        &self.auth.meta().host_meta
    }

    /// Returns the host as a string slice.
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let uri = Uri::parse("ftp://user@[::1]/")?;
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.host().as_str(), "[::1]");
    /// # Ok::<_, fluent_uri::ParseError>(())
    /// ```
    #[inline]
    pub fn as_str(&'i self) -> &'o str {
        self.auth.uri.slice(self.bounds().0, self.bounds().1)
    }

    fn zone_id(&'i self) -> &'o str {
        let (start, end) = self.bounds();
        let addr = self.auth.uri.slice(start + 1, end - 1);
        addr.rsplit_once('%').unwrap().1
    }

    /// Returns the parsed host component.
    pub fn parsed(&'i self) -> ParsedHost<'o> {
        #[cfg(feature = "std")]
        match *self.meta() {
            HostMeta::Ipv4(addr) => ParsedHost::Ipv4(addr),
            HostMeta::Ipv6(addr) => ParsedHost::Ipv6 {
                addr,
                zone_id: None,
            },
            HostMeta::Ipv6Zoned(addr) => ParsedHost::Ipv6 {
                addr,
                zone_id: Some(self.zone_id()),
            },
            HostMeta::IpvFuture => ParsedHost::IpvFuture,
            HostMeta::RegName => ParsedHost::RegName(EStr::new_validated(self.as_str())),
        }
        #[cfg(not(feature = "std"))]
        match self.meta() {
            HostMeta::Ipv4() => ParsedHost::Ipv4(),
            HostMeta::Ipv6() => ParsedHost::Ipv6 { zone_id: None },
            HostMeta::Ipv6Zoned() => ParsedHost::Ipv6 {
                zone_id: Some(self.zone_id()),
            },
            HostMeta::IpvFuture => ParsedHost::IpvFuture,
            HostMeta::RegName => ParsedHost::RegName(EStr::new_validated(self.as_str())),
        }
    }
}

/// A parsed host component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParsedHost<'a> {
    /// An IPv4 address.
    #[cfg_attr(not(feature = "std"), non_exhaustive)]
    Ipv4(
        /// The address.
        #[cfg(feature = "std")]
        Ipv4Addr,
    ),
    /// An IPv6 address.
    #[cfg_attr(not(feature = "std"), non_exhaustive)]
    Ipv6 {
        /// The address.
        #[cfg(feature = "std")]
        addr: Ipv6Addr,
        /// An optional zone identifier.
        zone_id: Option<&'a str>,
    },
    /// An IP address of future version.
    IpvFuture,
    /// A registered name.
    RegName(&'a EStr),
}

/// The [path] component of URI reference.
///
/// [path]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.3
#[derive(RefCastCustom)]
#[repr(transparent)]
pub struct Path {
    inner: EStr,
}

impl Path {
    #[ref_cast_custom]
    #[inline]
    fn new(path: &EStr) -> &Path;

    /// Yields the underlying [`EStr`].
    #[inline]
    pub fn as_estr(&self) -> &EStr {
        &self.inner
    }

    /// Returns the path as a string slice.
    #[inline]
    pub fn as_str(&self) -> &str {
        self.inner.as_str()
    }

    /// Returns `true` if the path is absolute, i.e., beginning with "/".
    #[inline]
    pub fn is_absolute(&self) -> bool {
        self.as_str().starts_with('/')
    }

    /// Returns `true` if the path is rootless, i.e., not beginning with "/".
    #[inline]
    pub fn is_rootless(&self) -> bool {
        !self.is_absolute()
    }

    /// Returns an iterator over the path [segments].
    ///
    /// [segments]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.3
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
    /// // Segments are separated by "/".
    /// let uri = Uri::parse("a/b/c")?;
    /// assert!(uri.path().segments().eq(["a", "b", "c"]));
    ///
    /// // The empty string before a preceding "/" is not a segment.
    /// // However, segments can be empty in the other cases.
    /// let uri = Uri::parse("/path/to//dir/")?;
    /// assert!(uri.path().segments().eq(["path", "to", "", "dir", ""]));
    /// # Ok::<_, fluent_uri::ParseError>(())
    /// ```
    #[inline]
    pub fn segments(&self) -> Split<'_> {
        let mut path = self.as_str();
        if let Some(rest) = path.strip_prefix('/') {
            path = rest;
        }
        let path = EStr::new_validated(path);

        let mut split = path.split('/');
        if self.as_str().is_empty() {
            split.next();
        }
        split
    }
}
