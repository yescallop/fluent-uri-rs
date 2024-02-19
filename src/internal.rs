#![allow(missing_debug_implementations)]

use crate::{parser, ParseError, Uri};
use alloc::string::String;
use core::{num::NonZeroU32, ops, str};

#[cfg(feature = "net")]
use std::net::{Ipv4Addr, Ipv6Addr};

pub trait Str {
    fn concretize<'a>(self) -> &'a str
    where
        Self: 'a;
}

impl Str for &str {
    #[inline]
    fn concretize<'a>(self) -> &'a str
    where
        Self: 'a,
    {
        self
    }
}

pub trait Data {
    type Str<'a>: Str
    where
        Self: 'a;

    fn as_str_opaque(&self) -> Self::Str<'_>;
}

impl<'o> Data for &'o str {
    type Str<'i> = &'o str where Self: 'i;

    #[inline]
    fn as_str_opaque(&self) -> Self::Str<'_> {
        self
    }
}

impl Data for String {
    type Str<'a> = &'a str where Self: 'a;

    #[inline]
    fn as_str_opaque(&self) -> Self::Str<'_> {
        self
    }
}

/// Helper trait that allows output references outlive a `Uri`.
///
/// # Tests
///
/// ```
/// fn ref_outlives_borrowed_uri(s: &str) -> &str {
///     fluent_uri::Uri::parse(s).unwrap().as_str()
/// }
/// ```
///
/// ```compile_fail
/// fn ref_does_not_outlive_owned_uri() -> &'static str {
///     fluent_uri::Uri::parse(String::new()).unwrap().as_str()
/// }
/// ```
///
/// ```compile_fail
/// fn ref_does_not_outlive_borrowed_data() -> &'static str {
///     let s = String::new();
///     fluent_uri::Uri::parse(&s).unwrap().as_str()
/// }
/// ```
pub trait DataHelper<'i, 'o>: Data {
    fn as_str(&'i self) -> &'o str;
}

impl<'i, 'o, T: Data + 'i> DataHelper<'i, 'o> for T
where
    T::Str<'i>: 'o,
{
    #[inline]
    fn as_str(&'i self) -> &'o str {
        let s: T::Str<'i> = self.as_str_opaque();
        s.concretize()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Syntax {
    Rfc3986,
    Extended,
}

pub trait ToUri {
    type Data: Data;
    type Err;

    fn to_uri(self, syntax: Syntax) -> Result<Uri<Self::Data>, Self::Err>;
}

#[cold]
fn len_overflow() -> ! {
    panic!("input length > u32::MAX");
}

impl<'a, S: AsRef<str> + ?Sized> ToUri for &'a S {
    type Data = &'a str;
    type Err = ParseError;

    #[inline]
    fn to_uri(self, syntax: Syntax) -> Result<Uri<Self::Data>, Self::Err> {
        let s = self.as_ref();
        if s.len() > u32::MAX as usize {
            len_overflow();
        }

        let meta = parser::parse(s.as_bytes(), syntax)?;
        Ok(Uri { data: s, meta })
    }
}

impl ToUri for String {
    type Data = String;
    type Err = ParseError<String>;

    #[inline]
    fn to_uri(self, syntax: Syntax) -> Result<Uri<Self::Data>, Self::Err> {
        if self.len() > u32::MAX as usize {
            len_overflow();
        }

        match parser::parse(self.as_bytes(), syntax) {
            Ok(meta) => Ok(Uri { data: self, meta }),
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
impl<T: Data> ops::Deref for Uri<T> {
    type Target = Meta;

    #[inline]
    fn deref(&self) -> &Meta {
        &self.meta
    }
}

#[doc(hidden)]
impl<T: Data> ops::DerefMut for Uri<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Meta {
        &mut self.meta
    }
}

#[derive(Clone, Copy, Default)]
pub struct AuthMeta {
    pub start: u32,
    pub host_bounds: (u32, u32),
    pub host_meta: HostMeta,
}

#[derive(Clone, Copy, Default)]
pub enum HostMeta {
    Ipv4(#[cfg(feature = "net")] Ipv4Addr),
    Ipv6(#[cfg(feature = "net")] Ipv6Addr),
    Ipv6Scoped(#[cfg(feature = "net")] Ipv6Addr),
    IpvFuture,
    #[default]
    RegName,
}
