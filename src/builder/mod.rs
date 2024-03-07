#![allow(missing_debug_implementations)]

mod state;

use crate::{
    component::{Host, Scheme},
    encoding::{
        encoder::{Fragment, Path, Query, Userinfo},
        EStr,
    },
    internal::{AuthMeta, HostMeta, Meta},
    parser::Reader,
    Uri,
};
use alloc::string::String;
use core::{fmt::Write, marker::PhantomData, num::NonZeroU32};
use state::*;

#[cfg(feature = "net")]
use std::net::SocketAddr;

/// A builder for URI reference.
///
/// This struct is created by [`Uri::builder`].
///
/// # Examples
///
/// Basic usage:
///
/// ```
/// use fluent_uri::{component::{Host, Scheme}, encoding::EStr, Uri};
///
/// let uri = Uri::builder()
///     .scheme(Scheme::new("foo"))
///     .authority(|b| {
///         b.userinfo(EStr::new("user"))
///             .host(Host::RegName(EStr::new("example.com")))
///             .port(8042)
///     })
///     .path(EStr::new("/over/there"))
///     .query(EStr::new("name=ferret"))
///     .fragment(EStr::new("nose"))
///     .build();
///
/// assert_eq!(
///     uri.as_str(),
///     "foo://user@example.com:8042/over/there?name=ferret#nose"
/// );
/// ```
///
/// Only use [`EStr::new`] when you have a percent-encoded string at hand.
/// You may otherwise encode and append data to an [`EString`]
/// which derefs to [`EStr`].
///
/// [`EString`]: crate::encoding::EString
///
/// # Constraints
///
/// Typestates are used to avoid misconfigurations,
/// which puts the following constraints:
///
/// - Components must be set from left to right, no repetition allowed.
/// - Setting [`path`] is mandatory before calling [`build`].
/// - Methods [`userinfo`], [`host`], and [`port`] are only available
///   within a call to [`authority`].
/// - Setting [`host`] is mandatory within a call to [`authority`].
///
/// You may otherwise skip setting optional components
/// ([`scheme`], [`authority`], [`userinfo`], [`port`], [`query`], and [`fragment`])
/// with [`advance`] or set them optionally with [`optional`].
///
/// The builder typestates are currently private. Please open an issue
/// if it is a problem not being able to name the type of a builder.
///
/// [`advance`]: Self::advance
/// [`optional`]: Self::optional
/// [`scheme`]: Self::scheme
/// [`authority`]: Self::authority
/// [`userinfo`]: Self::userinfo
/// [`host`]: Self::host
/// [`port`]: Self::port
/// [`path`]: Self::path
/// [`query`]: Self::query
/// [`fragment`]: Self::fragment
/// [`build`]: Self::build
pub struct Builder<S = UriStart> {
    buf: String,
    meta: Meta,
    state: PhantomData<S>,
}

impl Builder {
    #[inline]
    pub(crate) fn new() -> Self {
        Self {
            buf: String::new(),
            meta: Meta::default(),
            state: PhantomData,
        }
    }
}

impl<S> Builder<S> {
    fn cast<T>(self) -> Builder<T>
    where
        S: To<T>,
    {
        Builder {
            buf: self.buf,
            meta: self.meta,
            state: PhantomData,
        }
    }

    /// Advances the builder state, skipping optional components in between.
    ///
    /// Variable rebinding may be necessary as this changes the type of the builder.
    ///
    /// ```
    /// use fluent_uri::{component::{Host, Scheme}, encoding::EStr, Uri};
    ///
    /// fn build(relative: bool) -> Uri<String> {
    ///     let b = Uri::builder();
    ///     let b = if relative {
    ///         b.advance()
    ///     } else {
    ///         b.scheme(Scheme::new("http"))
    ///             .authority(|b| b.host(Host::RegName(EStr::new("example.com"))))
    ///     };
    ///     b.path(EStr::new("/foo")).build()
    /// }
    ///
    /// assert_eq!(build(false).as_str(), "http://example.com/foo");
    /// assert_eq!(build(true).as_str(), "/foo");
    /// ```
    pub fn advance<T>(self) -> Builder<T>
    where
        S: To<T>,
        T: AdvanceDst,
    {
        self.cast()
    }

    /// Optionally calls a builder method with a value.
    ///
    /// ```
    /// use fluent_uri::{encoding::EStr, Builder, Uri};
    ///
    /// let uri = Uri::builder()
    ///     .path(EStr::new("foo"))
    ///     .optional(Builder::query, Some(EStr::new("bar")))
    ///     .optional(Builder::fragment, None)
    ///     .build();
    ///
    /// assert_eq!(uri.as_str(), "foo?bar");
    /// ```
    pub fn optional<F, V, T>(self, f: F, opt: Option<V>) -> Builder<T>
    where
        F: FnOnce(Builder<S>, V) -> Builder<T>,
        S: To<T>,
        T: AdvanceDst,
    {
        match opt {
            Some(value) => f(self, value),
            None => self.advance(),
        }
    }
}

impl<S: To<SchemeEnd>> Builder<S> {
    /// Sets the [scheme] component.
    ///
    /// [scheme]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.1
    pub fn scheme(mut self, scheme: &Scheme) -> Builder<SchemeEnd> {
        self.buf.push_str(scheme.as_str());
        self.meta.scheme_end = NonZeroU32::new(self.buf.len() as _);
        self.buf.push(':');
        self.cast()
    }
}

impl<S: To<AuthorityStart>> Builder<S> {
    /// Builds the [authority] component with the given function.
    ///
    /// [authority]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2
    pub fn authority<F, T>(mut self, f: F) -> Builder<AuthorityEnd>
    where
        F: FnOnce(Builder<AuthorityStart>) -> Builder<T>,
        T: To<AuthorityEnd>,
    {
        self.buf.push_str("//");
        self.meta.auth_meta = Some(AuthMeta {
            start: self.buf.len() as _,
            ..AuthMeta::default()
        });
        f(self.cast()).cast()
    }
}

impl<S: To<UserinfoEnd>> Builder<S> {
    /// Sets the [userinfo] subcomponent of authority.
    ///
    /// [userinfo]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.1
    pub fn userinfo(mut self, userinfo: &EStr<Userinfo>) -> Builder<UserinfoEnd> {
        self.buf.push_str(userinfo.as_str());
        self.buf.push('@');
        self.cast()
    }
}

impl<S: To<HostEnd>> Builder<S> {
    /// Sets the [host] subcomponent of authority.
    ///
    /// If the contents of an input [`Host::RegName`] variant matches the
    /// `IPv4address` ABNF rule defined in [Section 3.2.2 of RFC 3986][host],
    /// the resulting [`Uri`] will output a [`Host::Ipv4`] variant instead.
    ///
    /// [host]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.2
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::{component::Host, encoding::EStr, Uri};
    /// use std::net::Ipv4Addr;
    ///
    /// let uri = Uri::builder()
    ///     .authority(|b| b.host(Host::RegName(EStr::new("127.0.0.1"))))
    ///     .path(EStr::new(""))
    ///     .build();
    /// assert_eq!(uri.authority().unwrap().host_parsed(), Host::Ipv4(Ipv4Addr::LOCALHOST));
    /// ```
    pub fn host(mut self, host: Host<'_>) -> Builder<HostEnd> {
        let auth_meta = self.meta.auth_meta.as_mut().unwrap();
        auth_meta.host_bounds.0 = self.buf.len() as _;

        match host {
            #[cfg(feature = "net")]
            Host::Ipv4(addr) => {
                write!(self.buf, "{addr}").unwrap();
                auth_meta.host_meta = HostMeta::Ipv4(addr);
            }
            #[cfg(feature = "net")]
            Host::Ipv6(addr) => {
                write!(self.buf, "[{addr}]").unwrap();
                auth_meta.host_meta = HostMeta::Ipv6(addr);
            }
            Host::RegName(name) => {
                let mut reader = Reader::new(name.as_str().as_bytes());
                auth_meta.host_meta = match reader.read_v4() {
                    Some(_addr) if !reader.has_remaining() => HostMeta::Ipv4(
                        #[cfg(feature = "net")]
                        _addr.into(),
                    ),
                    _ => HostMeta::RegName,
                };
                self.buf.push_str(name.as_str());
            }
            _ => unreachable!(),
        }

        auth_meta.host_bounds.1 = self.buf.len() as _;
        self.cast()
    }

    /// Sets the [host] and the [port] subcomponent of authority to the given socket address.
    ///
    /// The port component is omitted when it equals the default value.
    ///
    /// [host]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.2
    /// [port]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.3
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::{encoding::EStr, Uri};
    /// use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
    ///
    /// let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80);
    /// let uri = Uri::builder()
    ///     .authority(|b| b.host_port_from_socket_addr(addr, 80))
    ///     .path(EStr::new(""))
    ///     .build();
    /// assert_eq!(uri.as_str(), "//127.0.0.1");
    ///
    /// let uri = Uri::builder()
    ///     .authority(|b| b.host_port_from_socket_addr(addr, 21))
    ///     .path(EStr::new(""))
    ///     .build();
    /// assert_eq!(uri.as_str(), "//127.0.0.1:80");
    ///
    /// let addr = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 80, 0, 0);
    /// let uri = Uri::builder()
    ///     .authority(|b| b.host_port_from_socket_addr(addr, 80))
    ///     .path(EStr::new(""))
    ///     .build();
    /// assert_eq!(uri.as_str(), "//[::1]");
    /// ```
    #[cfg(feature = "net")]
    pub fn host_port_from_socket_addr<A: Into<SocketAddr>>(
        mut self,
        addr: A,
        default_port: u16,
    ) -> Builder<PortEnd> {
        let auth_meta = self.meta.auth_meta.as_mut().unwrap();
        auth_meta.host_bounds.0 = self.buf.len() as _;

        let addr = addr.into();
        match addr {
            SocketAddr::V4(addr) => {
                write!(self.buf, "{}", addr.ip()).unwrap();
                auth_meta.host_meta = HostMeta::Ipv4(*addr.ip());
            }
            SocketAddr::V6(addr) => {
                write!(self.buf, "[{}]", addr.ip()).unwrap();
                auth_meta.host_meta = HostMeta::Ipv6(*addr.ip());
            }
        }

        auth_meta.host_bounds.1 = self.buf.len() as _;
        self.cast().port_with_default(addr.port(), default_port)
    }
}

pub trait PortLike {
    fn write(&self, buf: &mut String);
}

impl PortLike for u16 {
    fn write(&self, buf: &mut String) {
        write!(buf, "{self}").unwrap();
    }
}

impl PortLike for &str {
    fn write(&self, buf: &mut String) {
        assert!(self.bytes().all(|x| x.is_ascii_digit()), "invalid port");
        buf.push_str(self)
    }
}

impl<S: To<PortEnd>> Builder<S> {
    /// Sets the [port] subcomponent of authority.
    ///
    /// This method takes either a `u16` or `&str` as argument.
    ///
    /// # Panics
    ///
    /// Panics if an input string is not a valid port according to
    /// [Section 3.2.3 of RFC 3986][port].
    ///
    /// [port]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.3
    pub fn port<T: PortLike>(mut self, port: T) -> Builder<PortEnd> {
        self.buf.push(':');
        port.write(&mut self.buf);
        self.cast()
    }

    /// Sets the [port] subcomponent of authority, omitting it when it equals the default value.
    ///
    /// [port]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.3
    pub fn port_with_default(self, port: u16, default: u16) -> Builder<PortEnd> {
        self.optional(Builder::port, Some(port).filter(|&port| port != default))
    }
}

fn first_segment_contains_colon(path: &str) -> bool {
    path.split_once('/')
        .map(|x| x.0)
        .unwrap_or(path)
        .contains(':')
}

impl<S: To<PathEnd>> Builder<S> {
    /// Sets the [path] component.
    ///
    /// # Panics
    ///
    /// Panics if any of the following conditions is not met, as required in
    /// [Section 3.3 of RFC 3986][path].
    ///
    /// - When authority is present, the path must either be empty or start with `'/'`.
    /// - When authority is absent, the path cannot start with `"//"`.
    /// - In a [relative-path reference][rel-ref], the first path segment cannot contain `':'`.
    ///
    /// [path]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.3
    /// [rel-ref]: https://datatracker.ietf.org/doc/html/rfc3986/#section-4.2
    pub fn path(mut self, path: &EStr<Path>) -> Builder<PathEnd> {
        let path = path.as_str();

        if self.meta.auth_meta.is_some() {
            assert!(
                path.is_empty() || path.starts_with('/'),
                "path must either be empty or start with '/' when authority is present"
            );
        } else {
            assert!(
                !path.starts_with("//"),
                "path cannot start with \"//\" when authority is absent"
            );
            if self.meta.scheme_end.is_none() {
                assert!(
                    !first_segment_contains_colon(path),
                    "first path segment cannot contain ':' in relative-path reference"
                );
            }
        }

        self.meta.path_bounds.0 = self.buf.len() as _;
        self.buf.push_str(path);
        self.meta.path_bounds.1 = self.buf.len() as _;
        self.cast()
    }
}

impl<S: To<QueryEnd>> Builder<S> {
    /// Sets the [query] component.
    ///
    /// [query]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.4
    pub fn query(mut self, query: &EStr<Query>) -> Builder<QueryEnd> {
        self.buf.push('?');
        self.buf.push_str(query.as_str());
        self.meta.query_end = NonZeroU32::new(self.buf.len() as _);
        self.cast()
    }
}

impl<S: To<FragmentEnd>> Builder<S> {
    /// Sets the [fragment] component.
    ///
    /// [fragment]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.5
    pub fn fragment(mut self, fragment: &EStr<Fragment>) -> Builder<FragmentEnd> {
        self.buf.push('#');
        self.buf.push_str(fragment.as_str());
        self.cast()
    }
}

impl<S: To<UriEnd>> Builder<S> {
    /// Builds the URI reference.
    ///
    /// # Panics
    ///
    /// Panics if the output length would be greater than [`u32::MAX`].
    pub fn build(self) -> Uri<String> {
        assert!(
            self.buf.len() <= u32::MAX as usize,
            "output length > u32::MAX"
        );
        Uri {
            val: self.buf,
            meta: self.meta,
        }
    }
}
