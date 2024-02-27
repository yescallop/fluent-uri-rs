#![allow(missing_debug_implementations)]

use crate::{parser, ParseError, Uri};
use alloc::string::String;
use core::{num::NonZeroU32, ops, str};

#[cfg(feature = "net")]
use std::net::{Ipv4Addr, Ipv6Addr};

pub trait Str {
    fn cast<'a>(self) -> &'a str
    where
        Self: 'a;
}

impl Str for &str {
    #[inline]
    fn cast<'a>(self) -> &'a str
    where
        Self: 'a,
    {
        self
    }
}

pub trait Val: Default {
    type Str<'a>: Str
    where
        Self: 'a;

    fn as_str_assoc(&self) -> Self::Str<'_>;
}

impl<'o> Val for &'o str {
    type Str<'i> = &'o str where Self: 'i;

    #[inline]
    fn as_str_assoc(&self) -> Self::Str<'_> {
        self
    }
}

impl Val for String {
    type Str<'a> = &'a str where Self: 'a;

    #[inline]
    fn as_str_assoc(&self) -> Self::Str<'_> {
        self
    }
}

/// Allows output references outlive a `Uri`.
///
/// # Examples
///
/// ```
/// fn borrowed_as_str<'a>(uri: &fluent_uri::Uri<&'a str>) -> &'a str {
///     uri.as_str()
/// }
///
/// fn owned_as_str(uri: &fluent_uri::Uri<String>) -> &str {
///     uri.as_str()
/// }
/// ```
pub trait ValExt<'i, 'o>: Val {
    fn as_str(&'i self) -> &'o str;
}

impl<'i, 'o, T: Val + 'i> ValExt<'i, 'o> for T
where
    T::Str<'i>: 'o,
{
    fn as_str(&'i self) -> &'o str {
        (self.as_str_assoc() as T::Str<'i>).cast()
    }
}

pub trait ToUri {
    type Val;
    type Err;

    fn to_uri(self) -> Result<Uri<Self::Val>, Self::Err>;
}

#[cold]
fn len_overflow() -> ! {
    panic!("input length > u32::MAX");
}

impl<'a> ToUri for &'a str {
    type Val = &'a str;
    type Err = ParseError;

    #[inline]
    fn to_uri(self) -> Result<Uri<Self::Val>, Self::Err> {
        if self.len() > u32::MAX as usize {
            len_overflow();
        }

        let meta = parser::parse(self.as_bytes())?;
        Ok(Uri { val: self, meta })
    }
}

impl ToUri for String {
    type Val = String;
    type Err = ParseError<String>;

    #[inline]
    fn to_uri(self) -> Result<Uri<Self::Val>, Self::Err> {
        if self.len() > u32::MAX as usize {
            len_overflow();
        }

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
