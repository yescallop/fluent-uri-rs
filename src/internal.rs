#![allow(missing_debug_implementations)]

use crate::{error::ParseError, parser, Uri};
use alloc::string::String;
use core::{num::NonZeroUsize, str};

#[cfg(feature = "net")]
use crate::net::{Ipv4Addr, Ipv6Addr};

pub trait Value: Default {}

impl Value for &str {}
impl Value for String {}

pub struct NoInput;

pub trait ToUri {
    type Val: Value;
    type Err;

    fn to_uri(self) -> Result<Uri<Self::Val>, Self::Err>;
}

impl<'a> ToUri for &'a str {
    type Val = &'a str;
    type Err = ParseError;

    #[inline]
    fn to_uri(self) -> Result<Uri<Self::Val>, Self::Err> {
        parser::parse(self.as_bytes()).map(|meta| Uri { val: self, meta })
    }
}

impl ToUri for String {
    type Val = String;
    type Err = ParseError<String>;

    #[inline]
    fn to_uri(self) -> Result<Uri<Self::Val>, Self::Err> {
        match parser::parse(self.as_bytes()) {
            Ok(meta) => Ok(Uri { val: self, meta }),
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

#[derive(Clone, Copy, Default)]
pub enum HostMeta {
    Ipv4(#[cfg(feature = "net")] Ipv4Addr),
    Ipv6(#[cfg(feature = "net")] Ipv6Addr),
    IpvFuture,
    #[default]
    RegName,
}
