mod path;
pub use path::*;

mod parser;

use crate::encoding::EStr;
use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uri<'a> {
    scheme: Option<&'a str>,
    authority: Option<Authority<'a>>,
    path: &'a str,
    query: Option<&'a str>,
    fragment: Option<&'a str>,
}

impl<'a> Uri<'a> {
    /// An empty URI reference ("").
    pub const EMPTY: Uri<'static> = Uri {
        scheme: None,
        authority: None,
        path: "",
        query: None,
        fragment: None,
    };

    /// Parses a URI reference from a byte sequence into a `Uri`.
    ///
    /// This function validates the input strictly except that UTF-8 validation is not
    /// performed on a percent-encoded registered name (see [Section 3.2.2, RFC 3986][1]).
    /// Care should be taken when dealing with such cases.
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.2
    #[inline]
    pub fn parse<S: AsRef<[u8]> + ?Sized>(s: &S) -> Result<Uri<'_>> {
        parser::parse(s.as_ref())
    }

    /// Returns the [scheme] component.
    ///
    /// [scheme]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.1
    #[inline]
    pub fn scheme(&self) -> Option<Scheme<'_>> {
        self.scheme.map(Scheme)
    }

    /// Returns the [authority] component.
    ///
    /// [authority]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2
    #[inline]
    pub fn authority(&self) -> Option<&Authority<'_>> {
        self.authority.as_ref()
    }

    /// Returns the [path] component.
    ///
    /// [path]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.3
    #[inline]
    pub fn path(&self) -> Path<'_> {
        Path(self.path)
    }

    /// Returns the [query] component.
    ///
    /// [query]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.4
    #[inline]
    pub fn query(&self) -> Option<&EStr> {
        // SAFETY: We have done the validation.
        self.query.map(|s| unsafe { EStr::new_unchecked(s) })
    }

    /// Returns the [fragment] component.
    ///
    /// [fragment]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.5
    #[inline]
    pub fn fragment(&self) -> Option<&EStr> {
        // SAFETY: We have done the validation.
        self.fragment.map(|s| unsafe { EStr::new_unchecked(s) })
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
    /// let uri = Uri::parse("/path/to/file").unwrap();
    /// assert!(uri.is_relative());
    /// let uri = Uri::parse("http://example.com/").unwrap();
    /// assert!(!uri.is_relative());
    /// ```
    #[inline]
    pub fn is_relative(&self) -> bool {
        self.scheme.is_none()
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
    /// let uri = Uri::parse("http://example.com/").unwrap();
    /// assert!(uri.is_absolute());
    /// let uri = Uri::parse("http://example.com/#title1").unwrap();
    /// assert!(!uri.is_absolute());
    /// let uri = Uri::parse("/path/to/file").unwrap();
    /// assert!(!uri.is_absolute());
    /// ```
    #[inline]
    pub fn is_absolute(&self) -> bool {
        self.scheme.is_some() && self.fragment.is_none()
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
    /// let uri = Uri::parse("Http://Example.Com/").unwrap();
    /// let scheme = uri.scheme().unwrap();
    /// assert_eq!(scheme.as_str(), "Http");
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
    /// let uri = Uri::parse("Http://Example.Com/").unwrap();
    /// let scheme = uri.scheme().unwrap();
    /// assert_eq!(scheme.normalize(), "http");
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
    /// let uri = Uri::parse("Http://Example.Com/").unwrap();
    /// let scheme = uri.scheme().unwrap();
    /// assert!(scheme.eq_lowercase("http"));
    /// // Always return `false` if there's any uppercase letter in the given string.
    /// assert!(!scheme.eq_lowercase("hTTp"));
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authority<'a> {
    raw: &'a str,
    userinfo: Option<&'a str>,
    host_raw: &'a str,
    host: Host<'a>,
    port: Option<&'a str>,
}

impl<'a> Authority<'a> {
    /// An empty authority component.
    pub const EMPTY: Authority<'static> = Authority {
        raw: "",
        userinfo: None,
        host_raw: "",
        host: Host::EMPTY,
        port: None,
    };

    /// Returns the raw authority component as a string slice.
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let uri = Uri::parse("ftp://user@[fe80::abcd]:6780/").unwrap();
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.as_str(), "user@[fe80::abcd]:6780");
    /// ```
    #[inline]
    pub fn as_str(&self) -> &str {
        self.raw
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
    /// let uri = Uri::parse("ftp://user@192.168.1.24/").unwrap();
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.userinfo().unwrap(), "user");
    /// ```
    #[inline]
    pub fn userinfo(&self) -> Option<&EStr> {
        // SAFETY: We have done the validation.
        self.userinfo.map(|s| unsafe { EStr::new_unchecked(s) })
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
    /// let uri = Uri::parse("ftp://user@[::1]/").unwrap();
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.host_raw(), "[::1]");
    /// ```
    #[inline]
    pub fn host_raw(&self) -> &str {
        self.host_raw
    }

    /// Returns the parsed [host] subcomponent.
    ///
    /// [host]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.2
    #[inline]
    pub fn host(&self) -> &Host<'_> {
        &self.host
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
    /// let uri = Uri::parse("ssh://device.local:4673/").unwrap();
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.port_raw(), Some("4673"));
    ///
    /// let uri = Uri::parse("ssh://device.local:/").unwrap();
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.port_raw(), Some(""));
    ///
    /// let uri = Uri::parse("ssh://device.local/").unwrap();
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.port_raw(), None);
    /// ```
    #[inline]
    pub fn port_raw(&self) -> Option<&str> {
        self.port
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
    /// let uri = Uri::parse("ssh://device.local:4673/").unwrap();
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.port(), Some(Ok(4673)));
    ///
    /// let uri = Uri::parse("ssh://device.local:/").unwrap();
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.port(), None);
    ///
    /// let uri = Uri::parse("ssh://device.local/").unwrap();
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.port(), None);
    ///
    /// let uri = Uri::parse("example://device.local:31415926/").unwrap();
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.port(), Some(Err("31415926")));
    /// ```
    #[inline]
    pub fn port(&self) -> Option<Result<u16, &str>> {
        self.port
            .filter(|s| !s.is_empty())
            .map(|s| s.parse().map_err(|_| s))
    }
}

impl<'a> fmt::Display for Authority<'a> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.raw, f)
    }
}

/// The [host] subcomponent of authority.
///
/// [host]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.2
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Host<'a> {
    /// An IPv4 address.
    Ipv4(Ipv4Addr),
    /// An IPv6 address.
    ///
    /// In the future an optional zone identifier may be supported.
    #[non_exhaustive]
    Ipv6 {
        /// The address.
        addr: Ipv6Addr,
        // /// The zone identifier.
        // zone_id: Option<&'a EStr>,
    },
    /// An IP address of future version.
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
    /// An empty host subcomponent.
    pub const EMPTY: Host<'static> = Host::RegName(EStr::EMPTY);
}

impl<'a> fmt::Display for Host<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Host::Ipv4(addr) => write!(f, "{addr}"),
            Host::Ipv6 { addr } => write!(f, "[{addr}]"),
            Host::RegName(reg_name) => write!(f, "{reg_name}"),
            #[cfg(feature = "ipv_future")]
            Host::IpvFuture { ver, addr } => write!(f, "[v{ver}.{addr}]"),
        }
    }
}

#[cfg(test)]
mod tests;
