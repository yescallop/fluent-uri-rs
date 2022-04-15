mod path;
pub use path::*;

mod parser;

use crate::encoding::EStr;
use std::{
    fmt,
    marker::PhantomData,
    net::{Ipv4Addr, Ipv6Addr},
    num::NonZeroU32,
    slice, str,
};

/// Detailed cause of a [`SyntaxError`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyntaxErrorKind {
    /// Invalid percent-encoded octet that is either non-hexadecimal or incomplete.
    ///
    /// The error index points to the percent character "%" of the octet.
    InvalidOctet,
    /// Unexpected character that is not allowed by the URI syntax.
    ///
    /// The error index points to the character.
    UnexpectedChar,
    /// Invalid IP literal.
    ///
    /// The error index points to the preceding left square bracket "[".
    InvalidIpLiteral,
}

/// A syntax error occurred when parsing, decoding or validating strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyntaxError {
    pub(crate) index: usize,
    pub(crate) kind: SyntaxErrorKind,
}

impl SyntaxError {
    /// Returns the index where the error occurred in the input string.
    #[inline]
    pub fn index(self) -> usize {
        self.index
    }

    /// Returns the detailed cause of the error.
    #[inline]
    pub fn kind(self) -> SyntaxErrorKind {
        self.kind
    }
}

impl std::error::Error for SyntaxError {}

impl fmt::Display for SyntaxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self.kind {
            SyntaxErrorKind::InvalidOctet => "invalid percent-encoded octet at index ",
            SyntaxErrorKind::UnexpectedChar => "unexpected character at index ",
            SyntaxErrorKind::InvalidIpLiteral => "invalid IP literal at index ",
        };
        write!(f, "{}{}", msg, self.index)
    }
}

pub(crate) type Result<T, E = SyntaxError> = std::result::Result<T, E>;

/// A URI reference defined in [RFC 3986].
///
/// [RFC 3986]: https://datatracker.ietf.org/doc/html/rfc3986/
#[derive(Clone)]
pub struct Uri<'a> {
    ptr: *const u8,
    len: u32,
    // One byte past the trailing ':'.
    // This encoding is chosen so that no extra branch is introduced
    // when indexing the start of the authority.
    scheme_end: Option<NonZeroU32>,
    host: Option<(NonZeroU32, u32, HostInternal)>,
    path: (u32, u32),
    // One byte past the last byte of query.
    query_end: Option<NonZeroU32>,
    // One byte past the preceding '#'.
    fragment_start: Option<NonZeroU32>,
    _marker: PhantomData<&'a [u8]>,
}

impl<'a> Uri<'a> {
    /// Parses a URI reference from a byte sequence into a `Uri`.
    ///
    /// This function validates the input strictly except that UTF-8 validation is not
    /// performed on a percent-encoded registered name (see [Section 3.2.2, RFC 3986][1]).
    /// Care should be taken when dealing with such cases.
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.2
    ///
    /// # Panics
    ///
    /// Panics if the input length is greater than `i32::MAX`.
    #[inline]
    pub fn parse<S: AsRef<[u8]> + ?Sized>(s: &S) -> Result<Uri<'_>> {
        parser::parse(s.as_ref())
    }

    #[inline]
    unsafe fn slice(&self, start: u32, end: u32) -> &'a str {
        // SAFETY: The caller must ensure that the indexes are within bounds.
        let bytes =
            unsafe { slice::from_raw_parts(self.ptr.add(start as usize), (end - start) as usize) };
        // SAFETY: The parser guarantees that the bytes are valid UTF-8.
        unsafe { str::from_utf8_unchecked(bytes) }
    }

    #[inline]
    unsafe fn eslice(&self, start: u32, end: u32) -> &'a EStr {
        // SAFETY: The caller must ensure that the indexes are within bounds.
        let s = unsafe { self.slice(start, end) };
        // SAFETY: The caller must ensure that the subslice is properly encoded.
        unsafe { EStr::new_unchecked(s) }
    }

    #[inline]
    /// Returns the URI reference as a string slice.
    pub fn as_str(&self) -> &'a str {
        // SAFETY: The indexes are within bounds.
        unsafe { self.slice(0, self.len) }
    }

    /// Returns the [scheme] component.
    ///
    /// [scheme]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.1
    #[inline]
    pub fn scheme(&self) -> Option<Scheme<'a>> {
        // SAFETY: The indexes are within bounds.
        self.scheme_end
            .map(|i| Scheme(unsafe { self.slice(0, i.get() - 1) }))
    }

    /// Returns the [authority] component.
    ///
    /// [authority]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2
    #[inline]
    pub fn authority(&self) -> Option<Authority<'a, '_>> {
        if self.host.is_some() {
            Some(Authority(self))
        } else {
            None
        }
    }

    /// Returns the [path] component.
    ///
    /// [path]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.3
    #[inline]
    pub fn path(&self) -> Path<'a> {
        // SAFETY: The indexes are within bounds.
        Path(unsafe { self.slice(self.path.0, self.path.1) })
    }

    /// Returns the [query] component.
    ///
    /// [query]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.4
    #[inline]
    pub fn query(&self) -> Option<&'a EStr> {
        // SAFETY: The indexes are within bounds and we have done the validation.
        self.query_end
            .map(|i| unsafe { self.eslice(self.path.1 + 1, i.get()) })
    }

    /// Returns the [fragment] component.
    ///
    /// [fragment]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.5
    #[inline]
    pub fn fragment(&self) -> Option<&'a EStr> {
        // SAFETY: The indexes are within bounds and we have done the validation.
        self.fragment_start
            .map(|i| unsafe { self.eslice(i.get(), self.len) })
    }

    /// Returns `true` if the URI reference is [relative], i.e., without a scheme.
    ///
    /// Note that this function is not the opposite of [`is_absolute`].
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
    /// # Ok::<_, fluent_uri::SyntaxError>(())
    /// ```
    #[inline]
    pub fn is_relative(&self) -> bool {
        self.scheme_end.is_none()
    }

    /// Returns `true` if the URI reference is [absolute], i.e., with a scheme and without a fragment.
    ///
    /// Note that this function is not the opposite of [`is_relative`].
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
    /// # Ok::<_, fluent_uri::SyntaxError>(())
    /// ```
    #[inline]
    pub fn is_absolute(&self) -> bool {
        self.scheme_end.is_some() && self.fragment_start.is_none()
    }
}

impl<'a> fmt::Display for Uri<'a> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.as_str(), f)
    }
}

impl<'a> fmt::Debug for Uri<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Uri")
            .field("scheme", &self.scheme().map(|s| s.as_str()))
            .field("authority", &self.authority())
            .field("path", &self.path().as_str())
            .field("query", &self.query())
            .field("fragment", &self.fragment())
            .finish()
    }
}

/// The [scheme] component of URI reference.
///
/// [scheme]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.1
#[derive(Debug, Clone, Copy)]
pub struct Scheme<'a>(&'a str);

impl<'a> Scheme<'a> {
    /// Returns the scheme as a string slice in the raw form.
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let uri = Uri::parse("Http://Example.Com/")?;
    /// let scheme = uri.scheme().unwrap();
    /// assert_eq!(scheme.as_str(), "Http");
    /// # Ok::<_, fluent_uri::SyntaxError>(())
    /// ```
    #[inline]
    pub fn as_str(self) -> &'a str {
        self.0
    }

    /// Returns the scheme as a string in the normalized (lowercase) form.
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let uri = Uri::parse("Http://Example.Com/")?;
    /// let scheme = uri.scheme().unwrap();
    /// assert_eq!(scheme.normalize(), "http");
    /// # Ok::<_, fluent_uri::SyntaxError>(())
    /// ```
    #[inline]
    pub fn normalize(self) -> String {
        self.0.to_ascii_lowercase()
    }

    /// Checks if the scheme equals case-insensitively with a lowercase string.
    ///
    /// This function is faster than [`str::eq_ignore_ascii_case`] but will
    /// always return `false` if there is any uppercase letter in the given string.
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let uri = Uri::parse("Http://Example.Com/")?;
    /// let scheme = uri.scheme().unwrap();
    /// assert!(scheme.eq_lowercase("http"));
    /// // Always return `false` if there's any uppercase letter in the given string.
    /// assert!(!scheme.eq_lowercase("hTTp"));
    /// # Ok::<_, fluent_uri::SyntaxError>(())
    /// ```
    #[inline]
    pub fn eq_lowercase(self, other: &str) -> bool {
        // The only characters allowed in a scheme are alphabets, digits, "+", "-" and ".",
        // the ASCII codes of which allow us to simply set the sixth bit and compare.
        const ASCII_CASE_MASK: u8 = 0b010_0000;
        self.0.len() == other.len()
            && self
                .0
                .bytes()
                .zip(other.bytes())
                .all(|(a, b)| a | ASCII_CASE_MASK == b)
    }
}

impl<'a> fmt::Display for Scheme<'a> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.as_str(), f)
    }
}

/// The [authority] component of URI reference.
///
/// [authority]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2
#[derive(Clone, Copy)]
pub struct Authority<'a, 'b>(&'b Uri<'a>);

impl<'a, 'b> Authority<'a, 'b> {
    #[inline]
    fn start(self) -> u32 {
        self.0.scheme_end.map(|x| x.get()).unwrap_or(0) + 2
    }

    #[inline]
    fn host_bounds(self) -> (u32, u32) {
        // SAFETY: When authority is present, `host` must be `Some`.
        let host = unsafe { self.0.host.as_ref().unwrap_unchecked() };
        (host.0.get(), host.1)
    }

    /// Returns the raw authority component as a string slice.
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let uri = Uri::parse("ftp://user@[fe80::abcd]:6780/")?;
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.as_str(), "user@[fe80::abcd]:6780");
    /// # Ok::<_, fluent_uri::SyntaxError>(())
    /// ```
    #[inline]
    pub fn as_str(self) -> &'a str {
        // SAFETY: The indexes are within bounds.
        unsafe { self.0.slice(self.start(), self.0.path.0) }
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
    /// # Ok::<_, fluent_uri::SyntaxError>(())
    /// ```
    #[inline]
    pub fn userinfo(self) -> Option<&'a EStr> {
        let start = self.start();
        let host_start = self.host_bounds().0;
        // SAFETY: The indexes are within bounds and we have done the validation.
        (start != host_start).then(|| unsafe { self.0.eslice(start, host_start - 1) })
    }

    /// Returns the raw [host] subcomponent as a string slice.
    ///
    /// [host]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.2
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let uri = Uri::parse("ftp://user@[::1]/")?;
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.host_raw(), "[::1]");
    /// # Ok::<_, fluent_uri::SyntaxError>(())
    /// ```
    #[inline]
    pub fn host_raw(self) -> &'a str {
        let bounds = self.host_bounds();
        // SAFETY: The indexes are within bounds.
        unsafe { self.0.slice(bounds.0, bounds.1) }
    }

    /// Returns the parsed [host] subcomponent.
    ///
    /// [host]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.2
    pub fn host(self) -> Host<'a> {
        // SAFETY: When authority is present, `host` must be `Some`.
        let host = unsafe { self.0.host.as_ref().unwrap_unchecked() };
        Host::from_internal(self, &host.2)
    }

    /// Returns the raw [port] subcomponent as a string slice.
    ///
    /// [port]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.3
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let uri = Uri::parse("ssh://device.local:4673/")?;
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.port_raw(), Some("4673"));
    ///
    /// let uri = Uri::parse("ssh://device.local:/")?;
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.port_raw(), Some(""));
    ///
    /// let uri = Uri::parse("ssh://device.local/")?;
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.port_raw(), None);
    /// # Ok::<_, fluent_uri::SyntaxError>(())
    /// ```
    #[inline]
    pub fn port_raw(self) -> Option<&'a str> {
        let host_end = self.host_bounds().1;
        // SAFETY: The indexes are within bounds.
        (host_end != self.0.path.0).then(|| unsafe { self.0.slice(host_end + 1, self.0.path.0) })
    }

    /// Parses the [port] subcomponent as `u16`.
    ///
    /// An empty port is interpreted as `None`.
    ///
    /// If the raw port overflows a `u16`, a `Some(Err)` containing the raw port will be returned.
    ///
    /// [port]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.3
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let uri = Uri::parse("ssh://device.local:4673/")?;
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.port(), Some(Ok(4673)));
    ///
    /// let uri = Uri::parse("ssh://device.local:/")?;
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.port(), None);
    ///
    /// let uri = Uri::parse("ssh://device.local/")?;
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.port(), None);
    ///
    /// let uri = Uri::parse("example://device.local:31415926/")?;
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.port(), Some(Err("31415926")));
    /// # Ok::<_, fluent_uri::SyntaxError>(())
    /// ```
    #[inline]
    pub fn port(self) -> Option<Result<u16, &'a str>> {
        self.port_raw()
            .filter(|s| !s.is_empty())
            .map(|s| s.parse().map_err(|_| s))
    }
}

impl<'a, 'b> fmt::Debug for Authority<'a, 'b> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Authority")
            .field("userinfo", &self.userinfo())
            .field("host", &self.host_raw())
            .field("port", &self.port_raw())
            .finish()
    }
}

impl<'a, 'b> fmt::Display for Authority<'a, 'b> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.as_str(), f)
    }
}

#[derive(Clone)]
enum HostInternal {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    #[cfg(feature = "ipv_future")]
    IpvFuture {
        dot_i: u32,
    },
    RegName,
}

/// The [host] subcomponent of authority.
///
/// [host]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.2
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Host<'a> {
    /// An IPv4 address.
    Ipv4(Ipv4Addr),
    /// An IPv6 address.
    ///
    /// In the future an optional zone identifier may be supported.
    Ipv6 {
        /// The address.
        addr: Ipv6Addr,
        // /// The zone identifier.
        // zone_id: Option<&'a EStr>,
    },
    /// An IP address of future version.
    ///
    /// This is supported on **crate feature `ipv_future`** only.
    #[cfg(feature = "ipv_future")]
    IpvFuture {
        /// The version.
        ver: &'a str,
        /// The address.
        addr: &'a str,
    },
    /// A registered name.
    RegName(&'a EStr),
}

impl<'a> Host<'a> {
    fn from_internal<'b>(auth: Authority<'a, 'b>, internal: &'b HostInternal) -> Host<'a> {
        match *internal {
            HostInternal::Ipv4(addr) => Host::Ipv4(addr),
            HostInternal::Ipv6(addr) => Host::Ipv6 { addr },
            #[cfg(feature = "ipv_future")]
            HostInternal::IpvFuture { dot_i } => unsafe {
                let bounds = auth.host_bounds();
                // SAFETY: The indexes are within bounds.
                Host::IpvFuture {
                    ver: auth.0.slice(bounds.0 + 2, dot_i),
                    addr: auth.0.slice(dot_i + 1, bounds.1 - 1),
                }
            },
            // SAFETY: We have done the validation.
            HostInternal::RegName => Host::RegName(unsafe { EStr::new_unchecked(auth.host_raw()) }),
        }
    }
}

impl<'a> fmt::Display for Host<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Host::Ipv4(addr) => write!(f, "{addr}"),
            Host::Ipv6 { addr } => write!(f, "[{addr}]"),
            Host::RegName(reg_name) => write!(f, "{reg_name}"),
            #[cfg(feature = "ipv_future")]
            Host::IpvFuture { ver, addr } => write!(f, "[v{ver}.{addr}]"),
        }
    }
}
