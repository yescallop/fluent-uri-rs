#![warn(missing_debug_implementations, missing_docs, rust_2018_idioms)]
#![deny(unsafe_op_in_unsafe_fn)]
#![cfg_attr(not(feature = "std"), no_std)]

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
//!   This includes [`Error`] implementations and `Ip{v4, v6}Addr` support in [`ParsedHost`].
//!
//! [`Error`]: std::error::Error

/// Percent-encoding utilities.
pub mod encoding;
mod error;
mod fmt;
mod internal;
mod parser;

extern crate alloc;

use alloc::string::String;
use core::{
    hash, iter,
    marker::PhantomData,
    slice,
    str::{self, FromStr},
};
use encoding::{EStr, Split};
use internal::{
    AuthorityMeta, Capped, Flags, HostMeta, Meta, Pointer, Storage, StorageHelper, ToUri,
};
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
/// let uri_str = "http://example.com/";
///
/// // Create a `Uri<&str>` from a string slice.
/// let uri_a: Uri<&str> = Uri::parse(uri_str)?;
///
/// // Create a `Uri<String>` from an owned string.
/// let uri_b: Uri<String> = Uri::parse(uri_str.to_owned()).map_err(|e| e.plain())?;
///
/// // Convert a `Uri<&str>` to a `Uri<String>`.
/// let uri_c: Uri<String> = uri_a.to_owned();
///
/// // Borrow a `Uri<String>` as a `Uri<&str>`.
/// let uri_d: &Uri<&str> = uri_b.borrow();
/// # Ok::<_, fluent_uri::ParseError>(())
/// ```
#[derive(Clone, Default)]
#[repr(C)]
pub struct Uri<T: Storage> {
    ptr: T::Ptr,
    meta: Meta,
    _marker: PhantomData<T>,
}

impl<T: Storage> Uri<T> {
    /// Parses a URI reference from a byte sequence into a `Uri`.
    ///
    /// The return type is
    ///
    /// - `Result<Uri<&str>, ParseError>` for `I = &S` where `S: AsRef<[u8]> + ?Sized`.
    /// - `Result<Uri<String>, ParseError<I>>` for `I = String` or `I = Vec<u8>`.
    ///
    /// You may recover the input [`String`] or [`Vec<u8>`] by
    /// calling [`into_input`] on a [`ParseError`].
    ///
    /// [`into_input`]: ParseError::into_input
    ///
    /// # Behavior
    ///
    /// This function validates the input strictly as per [RFC 3986] with only two exceptions:
    ///
    /// - An IPvFuture address is rejected.
    /// - A case-sensitive IPv6 zone identifier containing only [unreserved] characters
    ///   is accepted, as in `http://[fe80::1%eth0]`.
    ///
    /// [RFC 3986]: https://datatracker.ietf.org/doc/html/rfc3986/
    /// [unreserved]: https://datatracker.ietf.org/doc/html/rfc3986/#section-2.3
    ///
    /// # Panics
    ///
    /// Panics if the length or capacity of the input is greater than [`i32::MAX`].
    pub fn parse<I>(input: I) -> Result<Uri<I::Storage>, I::Err>
    where
        I: ToUri<Storage = T>,
    {
        input.to_uri()
    }
}

impl Uri<&str> {
    /// Creates a new `Uri<String>` by cloning the contents of this `Uri<&str>`.
    pub fn to_owned(&self) -> Uri<String> {
        Uri {
            ptr: Capped::new(self.as_str().into()),
            meta: self.meta.clone(),
            _marker: PhantomData,
        }
    }
}

impl Uri<String> {
    /// Borrows this `Uri<String>` as a reference to `Uri<&str>`.
    #[inline]
    // We can't impl `Borrow` due to the limitation of lifetimes.
    #[allow(clippy::should_implement_trait)]
    pub fn borrow(&self) -> &Uri<&str> {
        // SAFETY: `Uri<String>` has the same layout as `Uri<&str>`.
        unsafe { &*(self as *const Uri<String> as *const Uri<&str>) }
    }

    /// Consumes this `Uri<String>` and yields the underlying [`String`] storage.
    #[inline]
    pub fn into_string(self) -> String {
        // SAFETY: The validation is done.
        unsafe { String::from_utf8_unchecked(self.ptr.into_bytes()) }
    }
}

impl<'i, 'o, T: StorageHelper<'i, 'o>> Uri<T> {
    #[inline]
    fn len(&self) -> u32 {
        self.ptr.len()
    }

    #[inline]
    unsafe fn slice(&'i self, start: u32, end: u32) -> &'o str {
        debug_assert!(start <= end && end <= self.len());
        // SAFETY: The caller must ensure that the indexes are within bounds.
        let bytes = unsafe {
            slice::from_raw_parts(self.ptr.get().add(start as usize), (end - start) as usize)
        };
        // SAFETY: The parser guarantees that the bytes are valid UTF-8.
        unsafe { str::from_utf8_unchecked(bytes) }
    }

    #[inline]
    unsafe fn eslice(&'i self, start: u32, end: u32) -> &'o EStr {
        // SAFETY: The caller must ensure that the indexes are within bounds.
        let s = unsafe { self.slice(start, end) };
        // SAFETY: The caller must ensure that the subslice is properly encoded.
        unsafe { EStr::new_unchecked(s.as_bytes()) }
    }

    /// Returns the URI reference as a string slice.
    #[inline]
    pub fn as_str(&'i self) -> &'o str {
        unsafe { self.slice(0, self.len()) }
    }

    /// Returns the [scheme] component.
    ///
    /// [scheme]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.1
    #[inline]
    pub fn scheme(&'i self) -> Option<&'o Scheme> {
        // SAFETY: The indexes are within bounds.
        self.scheme_end
            .map(|i| Scheme::new(unsafe { self.slice(0, i.get()) }))
    }

    /// Returns the [authority] component.
    ///
    /// [authority]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2
    #[inline]
    pub fn authority(&self) -> Option<&Authority<T>> {
        if self.authority_meta.is_some() {
            // SAFETY: The authority is present.
            Some(unsafe { Authority::new(self) })
        } else {
            None
        }
    }

    /// Returns the [path] component.
    ///
    /// [path]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.3
    #[inline]
    pub fn path(&'i self) -> &'o Path {
        // SAFETY: The indexes are within bounds and the validation is done.
        Path::new(unsafe { self.eslice(self.path_bounds.0, self.path_bounds.1) })
    }

    /// Returns the [query] component.
    ///
    /// [query]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.4
    #[inline]
    pub fn query(&'i self) -> Option<&'o EStr> {
        // SAFETY: The indexes are within bounds and the validation is done.
        self.query_end
            .map(|i| unsafe { self.eslice(self.path_bounds.1 + 1, i.get()) })
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
        // SAFETY: The indexes are within bounds and the validation is done.
        self.fragment_start()
            .map(|i| unsafe { self.eslice(i, self.len()) })
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

/// Implements equality comparisons on `Uri`s.
///
/// `Uri`s are compared by their byte values.
/// Normalization is **not** performed prior to comparison.
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

// SAFETY: Both `&str` and `String` are Send and Sync.
unsafe impl<T: Storage> Send for Uri<T> {}
unsafe impl<T: Storage> Sync for Uri<T> {}

impl FromStr for Uri<String> {
    type Err = ParseError;

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
    #[ref_cast_custom]
    #[inline]
    unsafe fn new(uri: &Uri<T>) -> &Authority<T>;

    #[inline]
    fn meta(&self) -> &AuthorityMeta {
        // SAFETY: When authority is present, `authority_meta` must be `Some`.
        unsafe { self.uri.authority_meta.as_ref().unwrap_unchecked() }
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
        // SAFETY: The indexes are within bounds and the validation is done.
        unsafe { self.uri.slice(self.start(), self.end()) }
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
        // SAFETY: The indexes are within bounds and the validation is done.
        (start != host_start).then(|| unsafe { self.uri.eslice(start, host_start - 1) })
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
        // SAFETY: The indexes are within bounds and the validation is done.
        (host_end != end).then(|| unsafe { self.uri.slice(host_end + 1, end) })
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
        // SAFETY: The indexes are within bounds.
        unsafe { self.auth.uri.slice(self.bounds().0, self.bounds().1) }
    }

    /// Returns the parsed host component.
    pub fn parsed(&'i self) -> ParsedHost<'o> {
        let _meta = self.meta();
        let flags = self.auth.uri.flags;
        // SAFETY: We only access the union after checking the flags.
        unsafe {
            if flags.contains(Flags::HOST_REG_NAME) {
                // SAFETY: The validation is done.
                return ParsedHost::RegName(EStr::new_unchecked(self.as_str().as_bytes()));
            } else if flags.contains(Flags::HOST_IPV4) {
                return ParsedHost::Ipv4(
                    #[cfg(feature = "std")]
                    _meta.ipv4_addr,
                );
            }
            ParsedHost::Ipv6 {
                #[cfg(feature = "std")]
                addr: _meta.ipv6_addr,
                // SAFETY: The indexes are within bounds.
                zone_id: flags.contains(Flags::HAS_ZONE_ID).then(|| {
                    self.auth
                        .uri
                        .slice(self.bounds().0 + 1, self.bounds().1 - 1)
                        .rsplit_once('%')
                        .unwrap()
                        .1
                }),
            }
        }
    }
}

/// A parsed host component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParsedHost<'a> {
    /// An IPv4 address.
    #[cfg_attr(not(feature = "std"), non_exhaustive)]
    Ipv4(#[cfg(feature = "std")] Ipv4Addr),
    /// An IPv6 address.
    #[cfg_attr(not(feature = "std"), non_exhaustive)]
    Ipv6 {
        /// The address.
        #[cfg(feature = "std")]
        addr: Ipv6Addr,
        /// An optional zone identifier.
        zone_id: Option<&'a str>,
    },
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
    pub fn segments(&self) -> Split<'_> {
        let mut path = self.inner.as_str();
        if self.is_absolute() {
            // SAFETY: Skipping "/" is fine.
            path = unsafe { path.get_unchecked(1..) };
        }
        // SAFETY: The validation is done.
        let path = unsafe { EStr::new_unchecked(path.as_bytes()) };

        let mut split = path.split('/');
        split.finished = self.as_str().is_empty();
        split
    }
}
