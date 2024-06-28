#![allow(missing_debug_implementations)]

mod state;

use crate::{
    component::Scheme,
    encoding::{
        encoder::{Fragment, Path, Port, Query, RegName, Userinfo},
        EStr,
    },
    error::{BuildError, BuildErrorKind},
    internal::{AuthMeta, HostMeta, Meta},
    parser, Uri,
};
use alloc::string::String;
use core::{fmt::Write, marker::PhantomData, num::NonZeroUsize};
use state::*;

#[cfg(feature = "net")]
use crate::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A builder for URI reference.
///
/// This struct is created by [`Uri::builder`].
///
/// # Examples
///
/// Basic usage:
///
/// ```
/// use fluent_uri::{component::Scheme, encoding::EStr, Uri};
///
/// const SCHEME_FOO: &Scheme = Scheme::new_or_panic("foo");
///
/// let uri = Uri::builder()
///     .scheme(SCHEME_FOO)
///     .authority(|b| {
///         b.userinfo(EStr::new_or_panic("user"))
///             .host(EStr::new_or_panic("example.com"))
///             .port(8042)
///     })
///     .path(EStr::new_or_panic("/over/there"))
///     .query(EStr::new_or_panic("name=ferret"))
///     .fragment(EStr::new_or_panic("nose"))
///     .build()
///     .unwrap();
///
/// assert_eq!(
///     uri.as_str(),
///     "foo://user@example.com:8042/over/there?name=ferret#nose"
/// );
/// ```
///
/// Note that [`EStr::new_or_panic`] *panics* on invalid input and
/// should normally be used with constant strings.
/// If you want to build a percent-encoded string from scratch,
/// use [`EString`] instead.
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
#[must_use]
pub struct Builder<S> {
    inner: BuilderInner,
    state: PhantomData<S>,
}

pub struct BuilderInner {
    buf: String,
    meta: Meta,
}

impl BuilderInner {
    fn push_scheme(&mut self, v: &str) {
        self.buf.push_str(v);
        self.meta.scheme_end = NonZeroUsize::new(self.buf.len());
        self.buf.push(':');
    }

    fn start_authority(&mut self) {
        self.buf.push_str("//");
    }

    fn push_userinfo(&mut self, v: &str) {
        self.buf.push_str(v);
        self.buf.push('@');
    }

    fn push_host(&mut self, meta: HostMeta, f: impl FnOnce(&mut String)) {
        let start = self.buf.len();
        f(&mut self.buf);
        self.meta.auth_meta = Some(AuthMeta {
            host_bounds: (start, self.buf.len()),
            host_meta: meta,
        });
    }

    fn push_path(&mut self, v: &str) {
        self.meta.path_bounds.0 = self.buf.len();
        self.buf.push_str(v);
        self.meta.path_bounds.1 = self.buf.len();
    }

    fn push_query(&mut self, v: &str) {
        self.buf.push('?');
        self.buf.push_str(v);
        self.meta.query_end = NonZeroUsize::new(self.buf.len());
    }

    fn push_fragment(&mut self, v: &str) {
        self.buf.push('#');
        self.buf.push_str(v);
    }

    fn validate(&self) -> Result<(), BuildError> {
        fn first_segment_contains_colon(path: &str) -> bool {
            path.split_once('/').map_or(path, |x| x.0).contains(':')
        }

        let (start, end) = self.meta.path_bounds;
        let path = &self.buf[start..end];

        if self.meta.auth_meta.is_some() {
            if !path.is_empty() && !path.starts_with('/') {
                return Err(BuildError(BuildErrorKind::NonAbemptyPath));
            }
        } else {
            if path.starts_with("//") {
                return Err(BuildError(BuildErrorKind::PathStartingWithDoubleSlash));
            }
            if self.meta.scheme_end.is_none() && first_segment_contains_colon(path) {
                return Err(BuildError(BuildErrorKind::ColonInFirstPathSegment));
            }
        }
        Ok(())
    }
}

pub(crate) type BuilderStart = Builder<Start>;

impl Builder<Start> {
    #[inline]
    pub(crate) fn new() -> Self {
        Self {
            inner: BuilderInner {
                buf: String::new(),
                meta: Meta::default(),
            },
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
            inner: self.inner,
            state: PhantomData,
        }
    }

    /// Advances the builder state, skipping optional components in between.
    ///
    /// Variable rebinding may be necessary as this changes the type of the builder.
    ///
    /// ```
    /// use fluent_uri::{component::Scheme, encoding::EStr, Uri};
    ///
    /// fn build(relative: bool) -> Uri<String> {
    ///     let b = Uri::builder();
    ///     let b = if relative {
    ///         b.advance()
    ///     } else {
    ///         b.scheme(Scheme::new_or_panic("http"))
    ///             .authority(|b| b.host(EStr::new_or_panic("example.com")))
    ///     };
    ///     b.path(EStr::new_or_panic("/foo")).build().unwrap()
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
    ///     .path(EStr::new_or_panic("foo"))
    ///     .optional(Builder::query, Some(EStr::new_or_panic("bar")))
    ///     .optional(Builder::fragment, None)
    ///     .build()
    ///     .unwrap();
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
    /// Note that the scheme component is *case-insensitive* and is normalized to
    /// *lowercase*. For consistency, you should only produce lowercase scheme names.
    ///
    /// [scheme]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.1
    pub fn scheme(mut self, scheme: &Scheme) -> Builder<SchemeEnd> {
        self.inner.push_scheme(scheme.as_str());
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
        self.inner.start_authority();
        f(self.cast()).cast()
    }
}

impl<S: To<UserinfoEnd>> Builder<S> {
    /// Sets the [userinfo] subcomponent of authority.
    ///
    /// [userinfo]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.1
    pub fn userinfo(mut self, userinfo: &EStr<Userinfo>) -> Builder<UserinfoEnd> {
        self.inner.push_userinfo(userinfo.as_str());
        self.cast()
    }
}

pub trait AsHost<'a> {
    fn push_to(self, b: &mut BuilderInner);
}

#[cfg(feature = "net")]
impl<'a> AsHost<'a> for Ipv4Addr {
    fn push_to(self, b: &mut BuilderInner) {
        b.push_host(HostMeta::Ipv4(self), |buf| {
            write!(buf, "{self}").unwrap();
        });
    }
}

#[cfg(feature = "net")]
impl<'a> AsHost<'a> for Ipv6Addr {
    fn push_to(self, b: &mut BuilderInner) {
        b.push_host(HostMeta::Ipv6(self), |buf| {
            write!(buf, "[{self}]").unwrap();
        });
    }
}

#[cfg(feature = "net")]
impl<'a> AsHost<'a> for IpAddr {
    fn push_to(self, b: &mut BuilderInner) {
        match self {
            IpAddr::V4(addr) => addr.push_to(b),
            IpAddr::V6(addr) => addr.push_to(b),
        }
    }
}

impl<'a> AsHost<'a> for &'a EStr<RegName> {
    fn push_to(self, b: &mut BuilderInner) {
        let meta = parser::parse_v4_or_reg_name(self.as_str().as_bytes());
        b.push_host(meta, |buf| {
            buf.push_str(self.as_str());
        });
    }
}

impl<S: To<HostEnd>> Builder<S> {
    /// Sets the [host] subcomponent of authority.
    ///
    /// This method takes either an [`Ipv4Addr`], [`Ipv6Addr`], [`IpAddr`],
    /// or <code>&amp;[EStr]&lt;[RegName]&gt;</code> as argument.
    ///
    /// If the contents of an input `&EStr<RegName>` matches the
    /// `IPv4address` ABNF rule defined in [Section 3.2.2 of RFC 3986][host],
    /// the resulting [`Uri`] will output a [`Host::Ipv4`] variant instead.
    ///
    /// Note that the host subcomponent is *case-insensitive* and is normalized to
    /// *lowercase*. For consistency, you should only produce lowercase registered names.
    ///
    /// [host]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.2
    /// [`Host::Ipv4`]: crate::component::Host::Ipv4
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::{component::Host, encoding::EStr, Uri};
    ///
    /// let uri = Uri::builder()
    ///     .authority(|b| b.host(EStr::new_or_panic("127.0.0.1")))
    ///     .path(EStr::EMPTY)
    ///     .build()
    ///     .unwrap();
    /// assert!(matches!(uri.authority().unwrap().host_parsed(), Host::Ipv4(_)));
    /// ```
    pub fn host<'a>(mut self, host: impl AsHost<'a>) -> Builder<HostEnd> {
        host.push_to(&mut self.inner);
        self.cast()
    }
}

pub trait AsPort {
    fn push_to(self, buf: &mut String);
}

impl AsPort for u16 {
    fn push_to(self, buf: &mut String) {
        write!(buf, ":{self}").unwrap();
    }
}

impl AsPort for &EStr<Port> {
    fn push_to(self, buf: &mut String) {
        buf.push(':');
        buf.push_str(self.as_str());
    }
}

impl<S: To<PortEnd>> Builder<S> {
    /// Sets the [port][port-spec] subcomponent of authority.
    ///
    /// This method takes either a `u16` or <code>&amp;[EStr]&lt;[Port]&gt;</code> as argument.
    ///
    /// For consistency, you should not produce an empty port.
    ///
    /// [port-spec]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.3
    pub fn port<P: AsPort>(mut self, port: P) -> Builder<PortEnd> {
        port.push_to(&mut self.inner.buf);
        self.cast()
    }

    /// Sets the [port] subcomponent of authority, omitting it when it equals the default value.
    ///
    /// [port]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.3
    #[cfg(fluent_uri_unstable)]
    pub fn port_with_default(self, port: u16, default: u16) -> Builder<PortEnd> {
        self.optional(Builder::port, Some(port).filter(|&port| port != default))
    }
}

impl<S: To<PathEnd>> Builder<S> {
    /// Sets the [path] component.
    ///
    /// [path]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.3
    pub fn path(mut self, path: &EStr<Path>) -> Builder<PathEnd> {
        self.inner.push_path(path.as_str());
        self.cast()
    }
}

impl<S: To<QueryEnd>> Builder<S> {
    /// Sets the [query] component.
    ///
    /// [query]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.4
    pub fn query(mut self, query: &EStr<Query>) -> Builder<QueryEnd> {
        self.inner.push_query(query.as_str());
        self.cast()
    }
}

impl<S: To<FragmentEnd>> Builder<S> {
    /// Sets the [fragment] component.
    ///
    /// [fragment]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.5
    pub fn fragment(mut self, fragment: &EStr<Fragment>) -> Builder<FragmentEnd> {
        self.inner.push_fragment(fragment.as_str());
        self.cast()
    }
}

impl<S: To<End>> Builder<S> {
    /// Builds the URI reference.
    ///
    /// # Errors
    ///
    /// Returns `Err` if any of the following conditions is not met.
    ///
    /// - When authority is present, the path must either be empty or start with `'/'`.
    /// - When authority is not present, the path cannot start with `"//"`.
    /// - In a [relative-path reference][rel-ref], the first path segment cannot contain `':'`.
    ///
    /// [rel-ref]: https://datatracker.ietf.org/doc/html/rfc3986/#section-4.2
    pub fn build(self) -> Result<Uri<String>, BuildError> {
        self.inner.validate().map(|()| Uri {
            val: self.inner.buf,
            meta: self.inner.meta,
        })
    }
}
