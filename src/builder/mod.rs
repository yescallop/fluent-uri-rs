#![allow(missing_debug_implementations)]

mod state;

use crate::{
    component::{Host, Scheme},
    encoding::{
        encoder::{Fragment, Path, Query, Userinfo},
        EStr,
    },
    internal::{AuthMeta, Meta},
    Uri,
};
use alloc::string::String;
use core::{fmt::Write, marker::PhantomData, num::NonZeroU32};
use state::*;

#[cfg(feature = "std")]
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
/// const SCHEME: &Scheme = Scheme::new("foo");
/// const HOST: Host<'_> = Host::RegName(EStr::new("example.com"));
///
/// let uri = Uri::builder()
///     .scheme(SCHEME)
///     .authority(|b| {
///         b.userinfo(EStr::new("user"))
///             .host(HOST)
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
/// You may otherwise encode and concatenate strings to an [`EString`]
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
}

impl<S> Builder<S> {
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
    /// [host]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.2
    ///
    /// # Panics
    ///
    /// Panics if an input IPv6 zone identifier is empty or does not
    /// contain only [unreserved] characters.
    ///
    /// [unreserved]: https://datatracker.ietf.org/doc/html/rfc3986/#section-2.3
    pub fn host(mut self, host: Host<'_>) -> Builder<HostEnd> {
        let auth_meta = self.meta.auth_meta.as_mut().unwrap();
        auth_meta.host_bounds.0 = self.buf.len() as _;

        #[cfg(feature = "std")]
        use crate::internal::HostMeta;

        match host {
            #[cfg(feature = "std")]
            Host::Ipv4(addr) => {
                write!(self.buf, "{addr}").unwrap();
                auth_meta.host_meta = HostMeta::Ipv4(addr);
            }
            #[cfg(feature = "std")]
            Host::Ipv6 { addr, zone_id } => {
                use crate::encoding::table;

                write!(self.buf, "[{addr}]").unwrap();
                if let Some(zone_id) = zone_id {
                    assert!(
                        !zone_id.is_empty() && table::ZONE_ID.validate(zone_id.as_bytes()),
                        "invalid zone identifier"
                    );
                    self.buf.push('%');
                    self.buf.push_str(zone_id);
                    auth_meta.host_meta = HostMeta::Ipv6Zoned(addr);
                } else {
                    auth_meta.host_meta = HostMeta::Ipv6(addr);
                }
            }
            Host::RegName(name) => self.buf.push_str(name.as_str()),
            _ => unreachable!(),
        }

        auth_meta.host_bounds.1 = self.buf.len() as _;
        self.cast()
    }

    /// Sets the host and the port subcomponent of authority to the given socket address.
    ///
    /// The port component is omitted when it equals the default port.
    #[cfg(feature = "std")]
    pub fn host_port_from_socket_addr<A: Into<SocketAddr>>(
        mut self,
        addr: A,
        default_port: u16,
    ) -> Builder<PortEnd> {
        let auth_meta = self.meta.auth_meta.as_mut().unwrap();
        auth_meta.host_bounds.0 = self.buf.len() as _;

        use crate::internal::HostMeta;

        let addr = addr.into();
        match addr {
            SocketAddr::V4(addr) => {
                write!(self.buf, "{}", addr.ip()).unwrap();
                auth_meta.host_meta = HostMeta::Ipv4(*addr.ip());
            }
            SocketAddr::V6(addr) => {
                let ip = *addr.ip();
                let scope_id = addr.scope_id();
                if scope_id != 0 {
                    write!(self.buf, "[{ip}%{scope_id}]").unwrap();
                    auth_meta.host_meta = HostMeta::Ipv6Zoned(ip);
                } else {
                    write!(self.buf, "[{ip}]").unwrap();
                    auth_meta.host_meta = HostMeta::Ipv6(ip);
                }
            }
        }

        auth_meta.host_bounds.1 = self.buf.len() as _;
        self.cast().optional(
            Builder::port,
            Some(addr.port()).filter(|&port| port != default_port),
        )
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

impl<S: AsRef<str> + ?Sized> PortLike for &S {
    fn write(&self, buf: &mut String) {
        let s = self.as_ref();
        assert!(s.bytes().all(|x| x.is_ascii_digit()), "invalid port");
        buf.push_str(s)
    }
}

impl<S: To<PortEnd>> Builder<S> {
    /// Sets the [port] subcomponent of authority.
    ///
    /// Takes either a `u16` or `&S` where `S: AsRef<str> + ?Sized` as argument.
    ///
    /// # Panics
    ///
    /// Panics if an input string is not a valid port as per [Section 3.2.3 of RFC 3986][port].
    ///
    /// [port]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.3
    pub fn port<T: PortLike>(mut self, port: T) -> Builder<PortEnd> {
        self.buf.push(':');
        port.write(&mut self.buf);
        self.cast()
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
    /// Panics if any of the following conditions is not met, as per [Section 3.3 of RFC 3986][path].
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
            storage: self.buf,
            meta: self.meta,
        }
    }
}