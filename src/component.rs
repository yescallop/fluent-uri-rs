//! Components of URI reference.

use crate::{
    encoding::{
        encoder::{Port, RegName, Userinfo},
        table, EStr, EString,
    },
    internal::{AuthMeta, HostMeta},
    Uri,
};
use borrow_or_share::BorrowOrShare;
use core::iter;
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
///
/// # Comparison
///
/// `Scheme`s are compared case-insensitively. You should do a case-insensitive
/// comparison if the scheme specification allows both letter cases in the scheme name.
///
/// # Examples
///
/// ```
/// use fluent_uri::{component::Scheme, Uri};
///
/// const SCHEME_HTTP: &Scheme = Scheme::new_or_panic("http");
///
/// let uri = Uri::parse("HTTP://EXAMPLE.COM/")?;
/// let scheme = uri.scheme().unwrap();
///
/// // Case-insensitive comparison.
/// assert_eq!(scheme, SCHEME_HTTP);
/// // Case-sensitive comparison.
/// assert_eq!(scheme.as_str(), "HTTP");
/// # Ok::<_, fluent_uri::error::ParseError>(())
/// ```
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
    /// use [`new`](Self::new).
    ///
    /// [scheme]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.1
    #[inline]
    #[must_use]
    pub const fn new_or_panic(s: &str) -> &Scheme {
        match Self::new(s) {
            Some(scheme) => scheme,
            None => panic!("invalid scheme"),
        }
    }

    /// Converts a string slice to `&Scheme`, returning `None` if the conversion fails.
    #[inline]
    #[must_use]
    pub const fn new(s: &str) -> Option<&Scheme> {
        if matches!(s.as_bytes(), [first, rem @ ..]
        if first.is_ascii_alphabetic() && table::SCHEME.validate(rem))
        {
            Some(Scheme::new_validated(s))
        } else {
            None
        }
    }

    /// Returns the scheme component as a string slice.
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
    /// # Ok::<_, fluent_uri::error::ParseError>(())
    /// ```
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.inner
    }
}

impl PartialEq for Scheme {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        const ASCII_CASE_MASK: u8 = 0b0010_0000;

        let (a, b) = (self.inner.as_bytes(), other.inner.as_bytes());

        // The only characters allowed in a scheme are alphabets, digits, '+', '-' and '.'.
        // Their ASCII codes allow us to simply set the sixth bits and compare.
        a.len() == b.len()
            && iter::zip(a, b).all(|(a, b)| a | ASCII_CASE_MASK == b | ASCII_CASE_MASK)
    }
}

impl Eq for Scheme {}

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

    pub(crate) fn meta(&self) -> &AuthMeta {
        self.uri.auth_meta.as_ref().unwrap()
    }

    pub(crate) fn start(&self) -> usize {
        match self.uri.scheme_end {
            Some(i) => i.get() + 3,
            None => 2,
        }
    }

    fn end(&self) -> usize {
        self.uri.path_bounds.0
    }

    fn host_bounds(&self) -> (usize, usize) {
        self.meta().host_bounds
    }

    /// Returns the authority component as a string slice.
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let uri = Uri::parse("http://user@example.com:8080/")?;
    /// let auth = uri.authority().unwrap();
    /// assert_eq!(auth.as_str(), "user@example.com:8080");
    /// # Ok::<_, fluent_uri::error::ParseError>(())
    /// ```
    #[must_use]
    pub fn as_str(&'i self) -> &'o str {
        self.uri.slice(self.start(), self.end())
    }

    /// Returns the optional [userinfo] subcomponent.
    ///
    /// [userinfo]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.1
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::{encoding::EStr, Uri};
    ///
    /// let uri = Uri::parse("http://user@example.com/")?;
    /// let auth = uri.authority().unwrap();
    /// assert_eq!(auth.userinfo(), Some(EStr::new_or_panic("user")));
    ///
    /// let uri = Uri::parse("http://example.com/")?;
    /// let auth = uri.authority().unwrap();
    /// assert_eq!(auth.userinfo(), None);
    /// # Ok::<_, fluent_uri::error::ParseError>(())
    /// ```
    #[must_use]
    pub fn userinfo(&'i self) -> Option<&'o EStr<Userinfo>> {
        let (start, host_start) = (self.start(), self.host_bounds().0);
        (start != host_start).then(|| self.uri.eslice(start, host_start - 1))
    }

    /// Returns the [host] subcomponent as a string slice.
    ///
    /// The host subcomponent is always present, although it may be empty.
    ///
    /// The square brackets enclosing an IPv6 or IPvFuture address are included.
    ///
    /// Note that the host subcomponent is *case-insensitive*.
    ///
    /// [host]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.2
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let uri = Uri::parse("http://user@example.com:8080/")?;
    /// let auth = uri.authority().unwrap();
    /// assert_eq!(auth.host(), "example.com");
    ///
    /// let uri = Uri::parse("file:///path/to/file")?;
    /// let auth = uri.authority().unwrap();
    /// assert_eq!(auth.host(), "");
    ///
    /// let uri = Uri::parse("//[::1]")?;
    /// let auth = uri.authority().unwrap();
    /// assert_eq!(auth.host(), "[::1]");
    /// # Ok::<_, fluent_uri::error::ParseError>(())
    /// ```
    #[must_use]
    pub fn host(&'i self) -> &'o str {
        let (start, end) = self.host_bounds();
        self.uri.slice(start, end)
    }

    /// Returns the parsed [host] subcomponent.
    ///
    /// Note that the host subcomponent is *case-insensitive*.
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
    /// let auth = uri.authority().unwrap();
    /// assert!(matches!(auth.host_parsed(), Host::Ipv4(Ipv4Addr::LOCALHOST)));
    ///
    /// let uri = Uri::parse("//[::1]")?;
    /// let auth = uri.authority().unwrap();
    /// assert!(matches!(auth.host_parsed(), Host::Ipv6(Ipv6Addr::LOCALHOST)));
    ///
    /// let uri = Uri::parse("//[v1.addr]")?;
    /// let auth = uri.authority().unwrap();
    /// // The API design for IPvFuture addresses is to be determined.
    /// assert!(matches!(auth.host_parsed(), Host::IpvFuture { .. }));
    ///
    /// let uri = Uri::parse("//localhost")?;
    /// let auth = uri.authority().unwrap();
    /// assert!(matches!(auth.host_parsed(), Host::RegName(name) if name == "localhost"));
    ///
    /// # Ok::<_, fluent_uri::error::ParseError>(())
    /// ```
    #[must_use]
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

    /// Returns the optional [port] subcomponent.
    ///
    /// A scheme may define a default port to use when the port is
    /// not present or is empty.
    ///
    /// Note that the port may be empty, with leading zeros, or larger than [`u16::MAX`].
    /// It is up to you to decide whether to deny such ports, fallback to the scheme's
    /// default if it is empty, ignore the leading zeros, or use a different addressing
    /// mechanism that allows ports larger than [`u16::MAX`].
    ///
    /// [port]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.3
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::{encoding::EStr, Uri};
    ///
    /// let uri = Uri::parse("//localhost:4673/")?;
    /// let auth = uri.authority().unwrap();
    /// assert_eq!(auth.port(), Some(EStr::new_or_panic("4673")));
    ///
    /// let uri = Uri::parse("//localhost:/")?;
    /// let auth = uri.authority().unwrap();
    /// assert_eq!(auth.port(), Some(EStr::EMPTY));
    ///
    /// let uri = Uri::parse("//localhost/")?;
    /// let auth = uri.authority().unwrap();
    /// assert_eq!(auth.port(), None);
    ///
    /// let uri = Uri::parse("//localhost:123456/")?;
    /// let auth = uri.authority().unwrap();
    /// assert_eq!(auth.port(), Some(EStr::new_or_panic("123456")));
    /// # Ok::<_, fluent_uri::error::ParseError>(())
    /// ```
    #[must_use]
    pub fn port(&'i self) -> Option<&'o EStr<Port>> {
        let (host_end, end) = (self.host_bounds().1, self.end());
        (host_end != end).then(|| self.uri.eslice(host_end + 1, end))
    }

    /// Converts the [port] subcomponent to `u16`, if present.
    ///
    /// Returns `Ok(None)` if the port is not present. Leading zeros are ignored.
    ///
    /// [port]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.3
    ///
    /// # Errors
    ///
    /// Returns `Err` if the port cannot be parsed into `u16`.
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let uri = Uri::parse("//localhost:4673/")?;
    /// let auth = uri.authority().unwrap();
    /// assert_eq!(auth.port_to_u16(), Ok(Some(4673)));
    ///
    /// let uri = Uri::parse("//localhost/")?;
    /// let auth = uri.authority().unwrap();
    /// assert_eq!(auth.port_to_u16(), Ok(None));
    ///
    /// let uri = Uri::parse("//localhost:/")?;
    /// let auth = uri.authority().unwrap();
    /// assert!(auth.port_to_u16().is_err());
    ///
    /// let uri = Uri::parse("//localhost:123456/")?;
    /// let auth = uri.authority().unwrap();
    /// assert!(auth.port_to_u16().is_err());
    /// # Ok::<_, fluent_uri::error::ParseError>(())
    /// ```
    #[cfg(fluent_uri_unstable)]
    pub fn port_to_u16(&'i self) -> Result<Option<u16>, core::num::ParseIntError> {
        self.port().map(|s| s.as_str().parse()).transpose()
    }

    /// Converts the authority component to an iterator of resolved [`SocketAddr`]s.
    ///
    /// The default port is used if the port component is not present.
    ///
    /// A registered name is **not** normalized prior to resolution and is resolved
    /// with [`ToSocketAddrs`] as is. The port must **not** be empty.
    /// Use [`Uri::normalize`] if necessary.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the port cannot be parsed into `u16`,
    /// if the host is an IPvFuture address,
    /// or if the resolution of a registered name fails.
    #[cfg(all(feature = "net", feature = "std"))]
    pub fn to_socket_addrs(
        &'i self,
        default_port: u16,
    ) -> io::Result<impl Iterator<Item = SocketAddr>> {
        use std::vec;

        let port = self
            .port()
            .map(|s| s.as_str().parse())
            .transpose()
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
#[derive(Debug, Clone, Copy)]
#[cfg_attr(fuzzing, derive(PartialEq, Eq))]
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
    ///
    /// Note that registered names are *case-insensitive*.
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
