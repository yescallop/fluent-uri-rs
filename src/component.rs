//! Components of URI reference.

use crate::{
    encoding::{
        encoder::{RegName, Userinfo},
        table, EStr,
    },
    internal::{AuthMeta, HostMeta, Storage, StorageHelper},
    Uri,
};
use ref_cast::{ref_cast_custom, RefCastCustom};

#[cfg(feature = "std")]
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, ToSocketAddrs},
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
    /// Panics if the string is not a valid scheme name as per
    /// [Section 3.1 of RFC 3986](https://datatracker.ietf.org/doc/html/rfc3986/#section-3.1).
    #[inline]
    pub const fn new(s: &str) -> &Scheme {
        assert!(
            matches!(s.as_bytes(), [first, rem @ ..]
            if first.is_ascii_alphabetic() && table::SCHEME.validate(rem)),
            "invalid scheme"
        );
        Scheme::new_validated(s)
    }

    /// Returns the scheme as a string slice.
    ///
    /// Note that the scheme is case-insensitive. You should typically use
    /// [`Scheme::eq`] for testing if the scheme is a desired one.
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let uri = Uri::parse("HTTP://EXAMPLE.COM/")?;
    /// let scheme = uri.scheme().unwrap();
    ///
    /// assert_eq!(scheme.as_str(), "HTTP");
    /// assert_eq!(scheme, "http");
    /// # Ok::<_, fluent_uri::ParseError>(())
    /// ```
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.inner
    }
}

/// Implements case-insensitive equality comparisons on schemes.
impl PartialEq for Scheme {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.inner.eq_ignore_ascii_case(&other.inner)
    }
}

/// Implements case-insensitive equality comparisons between schemes and strings.
impl PartialEq<str> for Scheme {
    #[inline]
    fn eq(&self, other: &str) -> bool {
        self.inner.eq_ignore_ascii_case(other)
    }
}

/// Implements case-insensitive equality comparisons between schemes and strings.
impl PartialEq<Scheme> for str {
    #[inline]
    fn eq(&self, other: &Scheme) -> bool {
        self.eq_ignore_ascii_case(&other.inner)
    }
}

impl Eq for Scheme {}

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
    pub(crate) fn new(uri: &Uri<T>) -> &Authority<T>;

    #[inline]
    fn meta(&self) -> &AuthMeta {
        self.uri.auth_meta.as_ref().unwrap()
    }

    #[inline]
    fn start(&self) -> u32 {
        self.meta().start
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
    pub fn userinfo(&'i self) -> Option<&'o EStr<Userinfo>> {
        let (start, host_start) = (self.start(), self.host_bounds().0);
        (start != host_start).then(|| self.uri.eslice(start, host_start - 1))
    }

    /// Returns the [host] subcomponent as a string slice.
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
    #[inline]
    pub fn host(&'i self) -> &'o str {
        let (start, end) = self.host_bounds();
        self.uri.slice(start, end)
    }

    fn zone_id(&'i self) -> &'o str {
        let (start, end) = self.host_bounds();
        let addr = self.uri.slice(start + 1, end - 1);
        addr.rsplit_once('%').unwrap().1
    }

    /// Returns the parsed [host] subcomponent.
    ///
    /// [host]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.2
    pub fn host_parsed(&'i self) -> Host<'o> {
        #[cfg(feature = "std")]
        match self.meta().host_meta {
            HostMeta::Ipv4(addr) => Host::Ipv4(addr),
            HostMeta::Ipv6(addr) => Host::Ipv6 {
                addr,
                zone_id: None,
            },
            HostMeta::Ipv6Zoned(addr) => Host::Ipv6 {
                addr,
                zone_id: Some(self.zone_id()),
            },
            HostMeta::IpvFuture => Host::IpvFuture {},
            HostMeta::RegName => Host::RegName(EStr::new_validated(self.host())),
        }
        #[cfg(not(feature = "std"))]
        match self.meta().host_meta {
            HostMeta::Ipv4() => Host::Ipv4(),
            HostMeta::Ipv6() => Host::Ipv6 { zone_id: None },
            HostMeta::Ipv6Zoned() => Host::Ipv6 {
                zone_id: Some(self.zone_id()),
            },
            HostMeta::IpvFuture => Host::IpvFuture {},
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

        match self.host_parsed() {
            Host::Ipv4(addr) => Ok(vec![(addr, port).into()].into_iter()),
            Host::Ipv6 { addr, zone_id } => {
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
                        nix::net::if_::if_nametoindex(zone_id)?
                    }
                } else {
                    0
                };
                Ok(vec![SocketAddrV6::new(addr, port, 0, scope_id).into()].into_iter())
            }
            Host::IpvFuture {} => Err(io::Error::new(
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
    #[cfg_attr(not(feature = "std"), non_exhaustive)]
    Ipv4(
        /// The address.
        #[cfg(feature = "std")]
        Ipv4Addr,
    ),
    /// An IPv6 host.
    #[cfg_attr(not(feature = "std"), non_exhaustive)]
    Ipv6 {
        /// The address.
        #[cfg(feature = "std")]
        addr: Ipv6Addr,
        /// An optional zone identifier.
        zone_id: Option<&'a str>,
    },
    /// An IP address of future version.
    ///
    /// This variant is marked as non-exhaustive because the API design is to be determined.
    #[non_exhaustive]
    IpvFuture {},
    /// A registered name.
    RegName(&'a EStr<RegName>),
}
