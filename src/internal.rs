#![allow(missing_debug_implementations)]

use crate::{parser, ParseError, Uri};
use alloc::string::String;
use core::{num::NonZeroU32, ops, str};

#[cfg(feature = "net")]
use crate::net::{Ipv4Addr, Ipv6Addr};

pub trait Val: Default {}

impl Val for &str {}
impl Val for String {}

pub trait ToUri {
    type Val;
    type Err;

    fn to_uri(self) -> Result<Uri<Self::Val>, Self::Err>;
}

impl<'a> ToUri for &'a str {
    type Val = &'a str;
    type Err = ParseError;

    #[inline]
    fn to_uri(self) -> Result<Uri<Self::Val>, Self::Err> {
        let meta = parser::parse(self.as_bytes())?;
        Ok(Uri { val: self, meta })
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
    pub scheme_end: Option<NonZeroU32>,
    pub auth_meta: Option<AuthMeta>,
    pub path_bounds: (u32, u32),
    // One byte past the last byte of query.
    pub query_end: Option<NonZeroU32>,
}

#[doc(hidden)]
impl<T> ops::Deref for Uri<T> {
    type Target = Meta;

    fn deref(&self) -> &Meta {
        &self.meta
    }
}

#[doc(hidden)]
impl<T> ops::DerefMut for Uri<T> {
    fn deref_mut(&mut self) -> &mut Meta {
        &mut self.meta
    }
}

#[derive(Clone, Copy, Default)]
pub struct AuthMeta {
    /// One byte past the preceding "//".
    pub start: u32,
    pub host_bounds: (u32, u32),
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
