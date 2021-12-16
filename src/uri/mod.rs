/// Path utilities.
pub mod path;

mod parsing;

use crate::encoding::EStr;
use path::Path;
use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
};

/// An error occurred when parsing strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseError(pub(crate) usize);

impl ParseError {
    /// Creates a `ParseError` from a raw pointer.
    ///
    /// The pointer must be within the given string,
    /// otherwise the result would be invalid.
    pub(crate) fn from_raw(ptr: *const u8, s: &str) -> ParseError {
        let offset = (ptr as usize).wrapping_sub(s.as_ptr() as usize);
        debug_assert!(offset <= s.len());
        ParseError(offset)
    }

    /// Returns the index where the error occurred in the input string.
    #[inline]
    pub fn index(self) -> usize {
        self.0
    }
}

impl std::error::Error for ParseError {}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid character at index {}", self.0)
    }
}

/// A URI reference defined in [RFC 3986].
///
/// [RFC 3986]: https://datatracker.ietf.org/doc/html/rfc3986/
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UriRef<'a> {
    scheme: Option<&'a str>,
    authority: Option<Authority<'a>>,
    path: &'a str,
    query: Option<&'a str>,
    fragment: Option<&'a str>,
}

impl<'a> UriRef<'a> {
    /// Parses a URI reference from a string into a `UriRef`.
    #[inline]
    pub fn parse(s: &str) -> Result<UriRef<'_>, ParseError> {
        parsing::parse(s.as_bytes()).map_err(|ptr| ParseError::from_raw(ptr, s))
    }

    /// An empty URI reference ("").
    pub const EMPTY: UriRef<'static> = UriRef {
        scheme: None,
        authority: None,
        path: "",
        query: None,
        fragment: None,
    };

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
        self.query.map(|s| unsafe { EStr::new_unchecked(s) })
    }

    /// Returns the [fragment] component.
    ///
    /// [fragment]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.5
    #[inline]
    pub fn fragment(&self) -> Option<&EStr> {
        self.fragment.map(|s| unsafe { EStr::new_unchecked(s) })
    }

    /// Returns `true` if the URI reference is [relative], i.e., without a scheme.
    ///
    /// Note that this function is not the opposite of [`is_absolute`].
    ///
    /// [relative]: https://datatracker.ietf.org/doc/html/rfc3986/#section-4.2
    /// [`is_absolute`]: Self::is_absolute
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
    #[inline]
    pub fn is_absolute(&self) -> bool {
        self.scheme.is_some() && self.fragment.is_none()
    }
}

/// The [scheme] element of URI reference.
///
/// [scheme]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.1
#[derive(Debug, Clone, Copy)]
pub struct Scheme<'a>(&'a str);

impl<'a> Scheme<'a> {
    /// Returns the scheme as string in the raw form.
    #[inline]
    pub fn as_str(self) -> &'a str {
        self.0
    }

    /// Returns the scheme as string in the normalized (lowercase) form.
    #[inline]
    pub fn normalize(self) -> String {
        self.0.to_ascii_lowercase()
    }

    /// Checks if the scheme equals case-insensitively with a lowercase string.
    ///
    /// This function will always return `false` if there's any uppercase letter in the given string.
    #[inline]
    pub fn eq_lowercase(self, s: &str) -> bool {
        self.0.len() == s.len()
            && self
                .0
                .bytes()
                .zip(s.bytes())
                .all(|(a, b)| a.to_ascii_lowercase() == b)
    }
}

/// The [authority] element of URI reference.
///
/// [authority]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authority<'a> {
    userinfo: Option<&'a str>,
    host: Host<'a>,
    port: Option<&'a str>,
}

impl<'a> Authority<'a> {
    /// An empty authority element.
    pub const EMPTY: Authority<'static> = Authority {
        userinfo: None,
        host: Host::EMPTY,
        port: None,
    };

    /// Returns the [userinfo] subcomponent.
    ///
    /// [userinfo]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.1
    #[inline]
    pub fn userinfo(&self) -> Option<&EStr> {
        self.userinfo.map(|s| unsafe { EStr::new_unchecked(s) })
    }

    /// Returns the [host] subcomponent.
    ///
    /// [host]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.2
    #[inline]
    pub fn host(&self) -> &Host<'_> {
        &self.host
    }

    /// Returns the raw [port] subcomponent.
    ///
    /// [port]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.3
    #[inline]
    pub fn port_raw(&self) -> Option<&str> {
        self.port
    }

    /// Returns the [port] subcomponent as `u16`.
    ///
    /// An empty port is interpreted as `None`.
    ///
    /// If the raw port overflows a `u16`, an `Err` containing the raw port will be returned.
    ///
    /// [port]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.3
    #[inline]
    pub fn port(&self) -> Option<Result<u16, &str>> {
        self.port
            .filter(|s| !s.is_empty())
            .map(|s| s.parse().map_err(|_| s))
    }
}

/// The [host] subcomponent of authority.
///
/// [host]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.2
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Host<'a> {
    /// An IPv4 address.
    Ipv4(Ipv4Addr),
    /// An IPv6 address with optional zone ID.
    Ipv6 {
        /// The address.
        addr: Ipv6Addr,
        /// The zone ID.
        zone_id: Option<&'a str>,
    },
    /// An IP address of future version.
    IpvFuture {
        /// The version.
        ver: &'a str,
        /// The address.
        addr: &'a str,
    },
    /// A registered name.
    RegName(&'a str),
}

impl<'a> Host<'a> {
    /// An empty host subcomponent.
    pub const EMPTY: Host<'static> = Host::RegName("");
}

#[cfg(test)]
mod tests;
