#![allow(missing_debug_implementations)]

use crate::{error::ParseError, parser, UriRef};
use alloc::string::String;
use core::{num::NonZeroUsize, str};

#[cfg(feature = "net")]
use crate::net::{Ipv4Addr, Ipv6Addr};

pub trait Value: Default {}

impl Value for &str {}
impl Value for String {}

pub struct NoInput;

pub trait ToUriRef {
    type Val: Value;
    type Err;

    fn to_uri_ref(self) -> Result<UriRef<Self::Val>, Self::Err>;
}

impl<'a> ToUriRef for &'a str {
    type Val = &'a str;
    type Err = ParseError;

    #[inline]
    fn to_uri_ref(self) -> Result<UriRef<Self::Val>, Self::Err> {
        parser::parse(self.as_bytes()).map(|meta| UriRef { val: self, meta })
    }
}

impl ToUriRef for String {
    type Val = String;
    type Err = ParseError<String>;

    #[inline]
    fn to_uri_ref(self) -> Result<UriRef<Self::Val>, Self::Err> {
        match parser::parse(self.as_bytes()) {
            Ok(meta) => Ok(UriRef { val: self, meta }),
            Err(e) => Err(e.with_input(self)),
        }
    }
}

#[derive(Clone, Copy, Default)]
pub struct Meta {
    // The index of the trailing colon.
    pub scheme_end: Option<NonZeroUsize>,
    pub auth_meta: Option<AuthMeta>,
    pub path_bounds: (usize, usize),
    // One byte past the last byte of query.
    pub query_end: Option<NonZeroUsize>,
}

#[derive(Clone, Copy, Default)]
pub struct AuthMeta {
    pub host_bounds: (usize, usize),
    pub host_meta: HostMeta,
}

impl AuthMeta {
    pub const EMPTY: Self = Self {
        host_bounds: (0, 0),
        host_meta: HostMeta::RegName,
    };
}

#[derive(Clone, Copy, Default)]
pub enum HostMeta {
    Ipv4(#[cfg(feature = "net")] Ipv4Addr),
    Ipv6(#[cfg(feature = "net")] Ipv6Addr),
    IpvFuture,
    #[default]
    RegName,
}
