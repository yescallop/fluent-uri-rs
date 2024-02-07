#![allow(missing_debug_implementations)]

//! Module for building URI references.

mod internal;
/// Builder typestates.
pub mod state;

use crate::{
    encoding::table::*,
    internal::{AuthMeta, Meta},
    ParsedHost, Uri,
};
use alloc::string::String;
use core::{marker::PhantomData, num::NonZeroU32};
use internal::{To, ToPathEnd};
use state::*;

/// A builder of URI reference.
pub struct UriBuilder<S = UriStart> {
    buf: String,
    meta: Meta,
    state: PhantomData<S>,
}

impl UriBuilder {
    pub(crate) fn new() -> Self {
        Self {
            buf: String::new(),
            meta: Meta::default(),
            state: PhantomData,
        }
    }
}

impl<S> UriBuilder<S> {
    fn cast<T>(self) -> UriBuilder<T>
    where
        S: To<T>,
    {
        UriBuilder {
            buf: self.buf,
            meta: self.meta,
            state: PhantomData,
        }
    }
}

impl<S: To<SchemeEnd>> UriBuilder<S> {
    #[inline]
    pub fn scheme(mut self, scheme: &str) -> UriBuilder<SchemeEnd> {
        assert!(
            matches!(scheme.as_bytes(), [first, rest @ ..]
            if first.is_ascii_alphabetic() && SCHEME.validate(rest)),
            "invalid scheme"
        );
        self.buf.push_str(scheme);
        self.meta.scheme_end = NonZeroU32::new(self.buf.len() as _);
        self.buf.push(':');
        self.cast()
    }
}

impl<S: To<AuthorityStart>> UriBuilder<S> {
    #[inline]
    pub fn start_authority(mut self) -> UriBuilder<AuthorityStart> {
        self.buf.push_str("//");
        self.meta.auth_meta = Some(AuthMeta {
            start: self.buf.len() as _,
            ..AuthMeta::default()
        });
        self.cast()
    }
}

impl<S: To<UserinfoEnd>> UriBuilder<S> {
    #[inline]
    pub fn userinfo(mut self, userinfo: &str) -> UriBuilder<UserinfoEnd> {
        assert!(UNRESERVED.validate(userinfo.as_bytes()), "invalid userinfo");
        self.buf.push_str(userinfo);
        self.buf.push('@');
        self.cast()
    }
}

impl<S: To<HostEnd>> UriBuilder<S> {
    #[inline]
    pub fn host(mut self, host: ParsedHost<'_>) -> UriBuilder<HostEnd> {
        let auth_meta = self.meta.auth_meta.as_mut().unwrap();
        auth_meta.host_bounds.0 = self.buf.len() as _;

        #[cfg(feature = "std")]
        use crate::internal::HostMeta;
        #[cfg(feature = "std")]
        use core::fmt::Write;

        match host {
            #[cfg(feature = "std")]
            ParsedHost::Ipv4(addr) => {
                write!(self.buf, "{addr}").unwrap();
                auth_meta.host_meta = HostMeta::Ipv4(addr);
            }
            #[cfg(feature = "std")]
            ParsedHost::Ipv6 { addr, zone_id } => {
                write!(self.buf, "[{addr}]").unwrap();
                if let Some(zone_id) = zone_id {
                    assert!(
                        !zone_id.is_empty() && ZONE_ID.validate(zone_id.as_bytes()),
                        "invalid zone identifier"
                    );
                    self.buf.push('%');
                    self.buf.push_str(zone_id);
                    auth_meta.host_meta = HostMeta::Ipv6Zoned(addr);
                } else {
                    auth_meta.host_meta = HostMeta::Ipv6(addr);
                }
            }
            ParsedHost::RegName(name) => {
                assert!(
                    REG_NAME.validate(name.as_str().as_bytes()),
                    "invalid registered name"
                );
                self.buf.push_str(name.as_str());
            }
            _ => unreachable!(),
        }

        auth_meta.host_bounds.1 = self.buf.len() as _;
        self.cast()
    }
}

impl<S: To<PortEnd>> UriBuilder<S> {
    #[inline]
    pub fn port(mut self, port: &str) -> UriBuilder<PortEnd> {
        assert!(port.bytes().all(|x| x.is_ascii_digit()), "invalid port");
        self.buf.push(':');
        self.buf.push_str(port);
        self.cast()
    }
}

impl<S: To<AuthorityEnd>> UriBuilder<S> {
    #[inline]
    pub fn end_authority(self) -> UriBuilder<AuthorityEnd> {
        self.cast()
    }
}

impl<S: ToPathEnd> UriBuilder<S> {
    #[inline]
    pub fn path(mut self, path: &str) -> UriBuilder<PathEnd> {
        assert!(
            PATH.validate(path.as_bytes()) && S::validate_path_extra(path),
            "invalid path"
        );
        self.meta.path_bounds.0 = self.buf.len() as _;
        self.buf.push_str(path);
        self.meta.path_bounds.1 = self.buf.len() as _;
        self.cast()
    }
}

impl<S: To<QueryEnd>> UriBuilder<S> {
    #[inline]
    pub fn query(mut self, query: &str) -> UriBuilder<QueryEnd> {
        assert!(QUERY_FRAGMENT.validate(query.as_bytes()), "invalid query");
        self.buf.push('?');
        self.buf.push_str(query);
        self.meta.query_end = NonZeroU32::new(self.buf.len() as _);
        self.cast()
    }
}

impl<S: To<FragmentEnd>> UriBuilder<S> {
    #[inline]
    pub fn fragment(mut self, fragment: &str) -> UriBuilder<FragmentEnd> {
        assert!(
            QUERY_FRAGMENT.validate(fragment.as_bytes()),
            "invalid fragment"
        );
        self.buf.push('#');
        self.buf.push_str(fragment);
        self.cast()
    }
}

impl<S: To<UriEnd>> UriBuilder<S> {
    #[inline]
    pub fn build(self) -> Uri<String> {
        assert!(
            self.buf.len() <= i32::MAX as usize,
            "output length > i32::MAX"
        );
        Uri {
            storage: self.buf,
            meta: self.meta,
        }
    }
}
