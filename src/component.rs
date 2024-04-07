//! Components of URI reference.

use crate::{
    encoding::{
        encoder::{RegName, Userinfo},
        table, EStr, EString,
    },
    internal::{AuthMeta, HostMeta},
    Uri,
};
use borrow_or_share::BorrowOrShare;
use core::num::ParseIntError;
use ref_cast::{ref_cast_custom, RefCastCustom};

#[cfg(feature = "net")]
use crate::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[cfg(all(feature = "net", feature = "std"))]
use std::{
    io,
    net::{SocketAddr, ToSocketAddrs},
};

/// The [scheme] component of URI reference.
///
/// [scheme]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.1
#[derive(RefCastCustom)]
#[repr(transparent)]
pub struct Scheme {
    inner: str,
}

impl Scheme {
    #[ref_cast_custom]
    #[inline]
    pub(crate) const fn new_validated(scheme: &str) -> &Scheme;

    /// Converts a string slice to `&Scheme`.
    ///
    /// # Panics
    ///
    /// Panics if the string is not a valid scheme name according to
    /// [Section 3.1 of RFC 3986][scheme]. For a non-panicking variant,
    /// use [`try_new`](Self::try_new).
    ///
    /// [scheme]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.1
    #[inline]
    pub const fn new(s: &str) -> &Scheme {
        match Self::try_new(s) {
            Some(scheme) => scheme,
            None => panic!("invalid scheme"),
        }
    }

    /// Converts a string slice to `&Scheme`, returning `None` if the conversion fails.
    ///
    /// This is the non-panicking variant of [`new`](Self::new).
    #[inline]
    pub const fn try_new(s: &str) -> Option<&Scheme> {
        if matches!(s.as_bytes(), [first, rem @ ..]
        if first.is_ascii_alphabetic() && table::SCHEME.validate(rem))
        {
            Some(Scheme::new_validated(s))
        } else {
            None
        }
    }

    /// Returns the scheme as a string slice.
    ///
    /// Note that the scheme is case-insensitive in the generic URI syntax.
    /// You may want to use [`str::eq_ignore_ascii_case`]
    /// for a case-insensitive comparison.
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let uri = Uri::parse("http://example.com/")?;
    /// assert_eq!(uri.scheme().unwrap().as_str(), "http");
    /// let uri = Uri::parse("HTTP://EXAMPLE.COM/")?;
    /// assert_eq!(uri.scheme().unwrap().as_str(), "HTTP");
    /// # Ok::<_, fluent_uri::ParseError>(())
    /// ```
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.inner
    }
}

/// The [authority] component of URI reference.
///
/// [authority]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2
#[derive(RefCastCustom)]
#[repr(transparent)]
pub struct Authority<T> {
    uri: Uri<T>,
}

impl<'i, 'o, T: BorrowOrShare<'i, 'o, str>> Authority<T> {
    /// Converts from `&Uri<T>` to `&Authority<T>`,
    /// assuming that authority is present.
    #[ref_cast_custom]
    pub(crate) fn new(uri: &Uri<T>) -> &Authority<T>;

    fn meta(&self) -> &AuthMeta {
        self.uri.auth_meta.as_ref().unwrap()
    }

    fn start(&self) -> u32 {
        self.meta().start
    }

    fn end(&self) -> u32 {
        self.uri.path_bounds.0
    }

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
    pub fn userinfo(&'i self) -> Option<&'o EStr<Userinfo>> {
        let (start, host_start) = (self.start(), self.host_bounds().0);
        (start != host_start).then(|| self.uri.eslice(start, host_start - 1))
    }

    /// Returns the [host] subcomponent as a string slice.
    ///
    /// The square brackets enclosing an IP literal are included.
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
    /// assert_eq!(authority.host(), "[::1]");
    /// # Ok::<_, fluent_uri::ParseError>(())
    /// ```
    pub fn host(&'i self) -> &'o str {
        let (start, end) = self.host_bounds();
        self.uri.slice(start, end)
    }

    /// Returns the parsed [host] subcomponent.
    ///
    /// [host]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.2
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::{component::Host, encoding::EStr, Uri};
    /// use std::net::{Ipv4Addr, Ipv6Addr};
    ///
    /// let uri = Uri::parse("//127.0.0.1")?;
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.host_parsed(), Host::Ipv4(Ipv4Addr::LOCALHOST));
    ///
    /// let uri = Uri::parse("//[::1]")?;
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.host_parsed(), Host::Ipv6(Ipv6Addr::LOCALHOST));
    ///
    /// let uri = Uri::parse("//[v1.addr]")?;
    /// let authority = uri.authority().unwrap();
    /// // The API design for IPvFuture addresses is to be determined.
    /// assert!(matches!(authority.host_parsed(), Host::IpvFuture { .. }));
    ///
    /// let uri = Uri::parse("//localhost")?;
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.host_parsed(), Host::RegName(EStr::new("localhost")));
    ///
    /// # Ok::<_, fluent_uri::ParseError>(())
    /// ```
    pub fn host_parsed(&'i self) -> Host<'o> {
        match self.meta().host_meta {
            #[cfg(feature = "net")]
            HostMeta::Ipv4(addr) => Host::Ipv4(addr),
            #[cfg(feature = "net")]
            HostMeta::Ipv6(addr) => Host::Ipv6(addr),

            #[cfg(not(feature = "net"))]
            HostMeta::Ipv4() => Host::Ipv4(),
            #[cfg(not(feature = "net"))]
            HostMeta::Ipv6() => Host::Ipv6(),

            HostMeta::IpvFuture => Host::IpvFuture,
            HostMeta::RegName => Host::RegName(EStr::new_validated(self.host())),
        }
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
    /// let uri = Uri::parse("//localhost:4673/")?;
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.port(), Some("4673"));
    ///
    /// let uri = Uri::parse("//localhost:/")?;
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.port(), Some(""));
    ///
    /// let uri = Uri::parse("//localhost/")?;
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.port(), None);
    ///
    /// let uri = Uri::parse("//localhost:66666/")?;
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.port(), Some("66666"));
    /// # Ok::<_, fluent_uri::ParseError>(())
    /// ```
    pub fn port(&'i self) -> Option<&'o str> {
        let (host_end, end) = (self.host_bounds().1, self.end());
        (host_end != end).then(|| self.uri.slice(host_end + 1, end))
    }

    /// Converts the [port] subcomponent to `u16`.
    ///
    /// Leading zeros are ignored.
    /// Returns `Ok(None)` if the port is not present or is empty,
    /// or `Err` if the port cannot be parsed into `u16`.
    ///
    /// [port]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.3
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let uri = Uri::parse("//localhost:4673/")?;
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.port_to_u16(), Ok(Some(4673)));
    ///
    /// let uri = Uri::parse("//localhost:/")?;
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.port_to_u16(), Ok(None));
    ///
    /// let uri = Uri::parse("//localhost/")?;
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.port_to_u16(), Ok(None));
    ///
    /// let uri = Uri::parse("//localhost:66666/")?;
    /// let authority = uri.authority().unwrap();
    /// assert!(authority.port_to_u16().is_err());
    /// # Ok::<_, fluent_uri::ParseError>(())
    /// ```
    pub fn port_to_u16(&'i self) -> Result<Option<u16>, ParseIntError> {
        self.port()
            .filter(|port| !port.is_empty())
            .map(|port| port.parse())
            .transpose()
    }

    /// Converts the authority to an iterator of resolved [`SocketAddr`]s.
    ///
    /// The default port is used if the port component is not present or is empty.
    ///
    /// A registered name is **not** normalized prior to resolution and is resolved
    /// with [`ToSocketAddrs`] as is.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the port cannot be parsed into `u16`
    /// or if the resolution of a registered name fails.
    #[cfg(all(feature = "net", feature = "std"))]
    pub fn to_socket_addrs(
        &'i self,
        default_port: u16,
    ) -> io::Result<impl Iterator<Item = SocketAddr>> {
        use std::vec;

        let port = self
            .port_to_u16()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid port value"))?
            .unwrap_or(default_port);

        match self.host_parsed() {
            Host::Ipv4(addr) => Ok(vec![(addr, port).into()].into_iter()),
            Host::Ipv6(addr) => Ok(vec![(addr, port).into()].into_iter()),
            Host::IpvFuture => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "address mechanism not supported",
            )),
            Host::RegName(name) => (name.as_str(), port).to_socket_addrs(),
        }
    }
}

/// The parsed [host] component of URI reference.
///
/// [host]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.2
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Host<'a> {
    /// An IPv4 address.
    #[cfg_attr(not(feature = "net"), non_exhaustive)]
    Ipv4(
        /// The address.
        #[cfg(feature = "net")]
        Ipv4Addr,
    ),
    /// An IPv6 address.
    #[cfg_attr(not(feature = "net"), non_exhaustive)]
    Ipv6(
        /// The address.
        #[cfg(feature = "net")]
        Ipv6Addr,
    ),
    /// An IP address of future version.
    ///
    /// This variant is marked as non-exhaustive because the API design
    /// for IPvFuture addresses is to be determined.
    #[non_exhaustive]
    IpvFuture,
    /// A registered name.
    RegName(&'a EStr<RegName>),
}

#[cfg(feature = "net")]
impl<'a> From<Ipv4Addr> for Host<'a> {
    #[inline]
    fn from(value: Ipv4Addr) -> Self {
        Self::Ipv4(value)
    }
}

#[cfg(feature = "net")]
impl<'a> From<Ipv6Addr> for Host<'a> {
    #[inline]
    fn from(value: Ipv6Addr) -> Self {
        Self::Ipv6(value)
    }
}

#[cfg(feature = "net")]
impl<'a> From<IpAddr> for Host<'a> {
    #[inline]
    fn from(value: IpAddr) -> Self {
        match value {
            IpAddr::V4(addr) => Self::Ipv4(addr),
            IpAddr::V6(addr) => Self::Ipv6(addr),
        }
    }
}

impl<'a> From<&'a EStr<RegName>> for Host<'a> {
    #[inline]
    fn from(value: &'a EStr<RegName>) -> Self {
        Self::RegName(value)
    }
}

impl<'a> From<&'a EString<RegName>> for Host<'a> {
    #[inline]
    fn from(value: &'a EString<RegName>) -> Self {
        Self::RegName(value)
    }
}
