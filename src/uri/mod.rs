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
    /// Returns the scheme as a string slice in the raw form.
    #[inline]
    pub fn as_str(self) -> &'a str {
        self.0
    }

    /// Returns the scheme as a string in the normalized (lowercase) form.
    #[inline]
    pub fn normalize(self) -> String {
        self.0.to_ascii_lowercase()
    }

    /// Checks if the scheme equals case-insensitively with a lowercase string.
    ///
    /// This function is faster than [`str::eq_ignore_ascii_case`] but will
    /// always return `false` if there is any uppercase letter in the given string.
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
        // SAFETY: We have done the validation.
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

    /// Parses the [port] subcomponent as `u16`.
    ///
    /// An empty port is interpreted as `None`.
    ///
    /// If the raw port overflows a `u16`, a `Some(Err)` containing the raw port will be returned.
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
        zone_id: Option<&'a EStr>,
    },
    /// An IP address of future version.
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

#[cfg(test)]
mod tests;
