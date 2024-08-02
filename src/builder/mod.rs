#![allow(missing_debug_implementations)]

pub mod state;

use crate::{
    common::RiRef,
    component::{Authority, Scheme},
    encoding::{
        encoder::{Fragment, Path, Port, Query, RegName, Userinfo},
        EStr,
    },
    error::{BuildError, BuildErrorKind},
    internal::{AuthMeta, HostMeta, Meta},
    parser,
};
use alloc::string::String;
use core::{fmt::Write, marker::PhantomData, num::NonZeroUsize};
use state::*;

#[cfg(feature = "net")]
use crate::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A builder for URI (reference).
///
/// This struct is created by the `builder` associated
/// functions on [`Uri`] and [`UriRef`].
///
/// [`Uri`]: crate::Uri
/// [`UriRef`]: crate::UriRef
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
///     .authority_with(|b| {
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
/// - Setting [`scheme`] is mandatory when building a URI.
/// - Setting [`path`] is mandatory.
/// - Methods [`userinfo`], [`host`], and [`port`] are only available
///   within a call to [`authority_with`].
/// - Setting [`host`] is mandatory within a call to [`authority_with`].
///
/// You may otherwise skip setting optional components
/// (scheme, authority, userinfo, port, query, and fragment)
/// with [`advance`] or set them optionally with [`optional`].
///
/// The builder typestates are currently private. Please open an issue
/// if it is a problem not being able to name the type of a builder.
///
/// [`advance`]: Self::advance
/// [`optional`]: Self::optional
/// [`scheme`]: Self::scheme
/// [`authority_with`]: Self::authority_with
/// [`userinfo`]: Self::userinfo
/// [`host`]: Self::host
/// [`port`]: Self::port
/// [`path`]: Self::path
/// [`build`]: Self::build
#[must_use]
pub struct Builder<R, S> {
    inner: BuilderInner,
    _marker: PhantomData<(R, S)>,
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

    fn push_authority(&mut self, v: Authority<'_>) {
        self.buf.push_str("//");
        let start = self.buf.len();
        self.buf.push_str(v.as_str());

        let mut meta = v.meta();
        meta.host_bounds.0 += start;
        meta.host_bounds.1 += start;
        self.meta.auth_meta = Some(meta);
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

impl<R, S> Builder<R, S> {
    #[inline]
    pub(crate) fn new() -> Self {
        Self {
            inner: BuilderInner {
                buf: String::new(),
                meta: Meta::default(),
            },
            _marker: PhantomData,
        }
    }
}

impl<R, S> Builder<R, S> {
    fn cast<T>(self) -> Builder<R, T>
    where
        S: To<T>,
    {
        Builder {
            inner: self.inner,
            _marker: PhantomData,
        }
    }

    /// Advances the builder state, skipping optional components in between.
    ///
    /// Variable rebinding may be necessary as this changes the type of the builder.
    ///
    /// ```
    /// use fluent_uri::{component::Scheme, encoding::EStr, UriRef};
    ///
    /// fn build(relative: bool) -> UriRef<String> {
    ///     let b = UriRef::builder();
    ///     let b = if relative {
    ///         b.advance()
    ///     } else {
    ///         b.scheme(Scheme::new_or_panic("http"))
    ///             .authority_with(|b| b.host(EStr::new_or_panic("example.com")))
    ///     };
    ///     b.path(EStr::new_or_panic("/foo")).build().unwrap()
    /// }
    ///
    /// assert_eq!(build(false).as_str(), "http://example.com/foo");
    /// assert_eq!(build(true).as_str(), "/foo");
    /// ```
    pub fn advance<T>(self) -> Builder<R, T>
    where
        S: AdvanceTo<T>,
    {
        self.cast()
    }

    /// Optionally calls a builder method with a value.
    ///
    /// ```
    /// use fluent_uri::{encoding::EStr, Builder, UriRef};
    ///
    /// let uri_ref = UriRef::builder()
    ///     .path(EStr::new_or_panic("foo"))
    ///     .optional(Builder::query, Some(EStr::new_or_panic("bar")))
    ///     .optional(Builder::fragment, None)
    ///     .build()
    ///     .unwrap();
    ///
    /// assert_eq!(uri_ref.as_str(), "foo?bar");
    /// ```
    pub fn optional<F, V, T>(self, f: F, opt: Option<V>) -> Builder<R, T>
    where
        F: FnOnce(Builder<R, S>, V) -> Builder<R, T>,
        S: AdvanceTo<T>,
    {
        match opt {
            Some(value) => f(self, value),
            None => self.advance(),
        }
    }
}

impl<R, S: To<SchemeEnd>> Builder<R, S> {
    /// Sets the [scheme] component.
    ///
    /// Note that the scheme component is *case-insensitive* and its canonical form is
    /// *lowercase*. For consistency, you should only produce lowercase scheme names.
    ///
    /// [scheme]: https://datatracker.ietf.org/doc/html/rfc3986#section-3.1
    pub fn scheme(mut self, scheme: &Scheme) -> Builder<R, SchemeEnd> {
        self.inner.push_scheme(scheme.as_str());
        self.cast()
    }
}

impl<R, S: To<AuthorityStart>> Builder<R, S> {
    /// Builds the [authority] component with the given function.
    ///
    /// [authority]: https://datatracker.ietf.org/doc/html/rfc3986#section-3.2
    pub fn authority_with<F, T>(mut self, f: F) -> Builder<R, AuthorityEnd>
    where
        F: FnOnce(Builder<R, AuthorityStart>) -> Builder<R, T>,
        T: To<AuthorityEnd>,
    {
        self.inner.start_authority();
        f(self.cast()).cast()
    }

    /// Sets the [authority] component.
    ///
    /// This method is normally used with an authority which is empty ([`Authority::EMPTY`])
    /// or is obtained from a URI (reference). If you need to build an authority from its
    /// subcomponents (userinfo, host, and port), use [`authority_with`] instead.
    ///
    /// [authority]: https://datatracker.ietf.org/doc/html/rfc3986#section-3.2
    /// [`authority_with`]: Self::authority_with
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::{
    ///     component::{Authority, Scheme},
    ///     encoding::EStr,
    ///     Builder, Uri,
    /// };
    ///
    /// let uri = Uri::builder()
    ///     .scheme(Scheme::new_or_panic("file"))
    ///     .authority(Authority::EMPTY)
    ///     .path(EStr::new_or_panic("/path/to/file"))
    ///     .build()
    ///     .unwrap();
    ///
    /// assert_eq!(uri, "file:///path/to/file");
    ///
    /// let auth = Uri::parse("foo://user@example.com:8042")?
    ///     .authority()
    ///     .unwrap();
    /// let uri = Uri::builder()
    ///     .scheme(Scheme::new_or_panic("http"))
    ///     .authority(auth)
    ///     .path(EStr::EMPTY)
    ///     .build()
    ///     .unwrap();
    ///
    /// assert_eq!(uri, "http://user@example.com:8042");
    /// # Ok::<_, fluent_uri::error::ParseError>(())
    /// ```
    pub fn authority(mut self, authority: Authority<'_>) -> Builder<R, AuthorityEnd> {
        self.inner.push_authority(authority);
        self.cast::<AuthorityEnd>()
    }
}

impl<R, S: To<UserinfoEnd>> Builder<R, S> {
    /// Sets the [userinfo] subcomponent of authority.
    ///
    /// [userinfo]: https://datatracker.ietf.org/doc/html/rfc3986#section-3.2.1
    pub fn userinfo(mut self, userinfo: &EStr<Userinfo>) -> Builder<R, UserinfoEnd> {
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

impl<R, S: To<HostEnd>> Builder<R, S> {
    /// Sets the [host] subcomponent of authority.
    ///
    /// This method takes either an [`Ipv4Addr`], [`Ipv6Addr`], [`IpAddr`],
    /// or <code>&amp;[EStr]&lt;[RegName]&gt;</code> as argument.
    ///
    /// If the contents of an input `&EStr<RegName>` matches the
    /// `IPv4address` ABNF rule defined in [Section 3.2.2 of RFC 3986][host],
    /// the resulting URI (reference) will output a [`Host::Ipv4`] variant instead.
    ///
    /// Note that the host subcomponent is *case-insensitive*.
    /// For consistency, you should only produce [normalized] hosts.
    ///
    /// [host]: https://datatracker.ietf.org/doc/html/rfc3986#section-3.2.2
    /// [`Host::Ipv4`]: crate::component::Host::Ipv4
    /// [normalized]: crate::Uri::normalize
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::{component::Host, encoding::EStr, UriRef};
    ///
    /// let uri_ref = UriRef::builder()
    ///     .authority_with(|b| b.host(EStr::new_or_panic("127.0.0.1")))
    ///     .path(EStr::EMPTY)
    ///     .build()
    ///     .unwrap();
    ///
    /// assert!(matches!(uri_ref.authority().unwrap().host_parsed(), Host::Ipv4(_)));
    /// ```
    pub fn host<'a>(mut self, host: impl AsHost<'a>) -> Builder<R, HostEnd> {
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

impl<R, S: To<PortEnd>> Builder<R, S> {
    /// Sets the [port][port-spec] subcomponent of authority.
    ///
    /// This method takes either a `u16` or <code>&amp;[EStr]&lt;[Port]&gt;</code> as argument.
    ///
    /// For consistency, you should not produce an empty port.
    ///
    /// [port-spec]: https://datatracker.ietf.org/doc/html/rfc3986#section-3.2.3
    pub fn port(mut self, port: impl AsPort) -> Builder<R, PortEnd> {
        port.push_to(&mut self.inner.buf);
        self.cast()
    }

    /// Sets the [port] subcomponent of authority, omitting it when it equals the default value.
    ///
    /// [port]: https://datatracker.ietf.org/doc/html/rfc3986#section-3.2.3
    #[cfg(fluent_uri_unstable)]
    pub fn port_with_default(self, port: u16, default: u16) -> Builder<PortEnd> {
        self.optional(Builder::port, Some(port).filter(|&port| port != default))
    }
}

impl<R, S: To<PathEnd>> Builder<R, S> {
    /// Sets the [path] component.
    ///
    /// [path]: https://datatracker.ietf.org/doc/html/rfc3986#section-3.3
    pub fn path(mut self, path: &EStr<Path>) -> Builder<R, PathEnd> {
        self.inner.push_path(path.as_str());
        self.cast()
    }
}

impl<R, S: To<QueryEnd>> Builder<R, S> {
    /// Sets the [query] component.
    ///
    /// [query]: https://datatracker.ietf.org/doc/html/rfc3986#section-3.4
    pub fn query(mut self, query: &EStr<Query>) -> Builder<R, QueryEnd> {
        self.inner.push_query(query.as_str());
        self.cast()
    }
}

impl<R, S: To<FragmentEnd>> Builder<R, S> {
    /// Sets the [fragment] component.
    ///
    /// [fragment]: https://datatracker.ietf.org/doc/html/rfc3986#section-3.5
    pub fn fragment(mut self, fragment: &EStr<Fragment>) -> Builder<R, FragmentEnd> {
        self.inner.push_fragment(fragment.as_str());
        self.cast()
    }
}

impl<R: RiRef<Val = String>, S: To<End>> Builder<R, S> {
    /// Builds the URI (reference).
    ///
    /// # Errors
    ///
    /// Returns `Err` if any of the following conditions is not met.
    ///
    /// - When authority is present, the path must either be empty or start with `'/'`.
    /// - When authority is not present, the path cannot start with `"//"`.
    /// - In a [relative-path reference][rel-ref], the first path segment cannot contain `':'`.
    ///
    /// [rel-ref]: https://datatracker.ietf.org/doc/html/rfc3986#section-4.2
    pub fn build(self) -> Result<R, BuildError> {
        self.inner
            .validate()
            .map(|()| R::new(self.inner.buf, self.inner.meta))
    }
}
