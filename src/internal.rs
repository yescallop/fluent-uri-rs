#![allow(missing_debug_implementations)]

use crate::{parser, ParseError, Uri};
use alloc::{string::String, vec::Vec};
use bitflags::bitflags;
use core::{
    num::NonZeroU32,
    ops::{Deref, DerefMut},
    str,
};

#[cfg(feature = "std")]
use std::net::{Ipv4Addr, Ipv6Addr};

pub trait Str {
    fn as_str<'a>(self) -> &'a str
    where
        Self: 'a;
}

impl Str for &str {
    fn as_str<'a>(self) -> &'a str
    where
        Self: 'a,
    {
        self
    }
}

pub trait Storage {
    type Str<'a>: Str
    where
        Self: 'a;
    fn _as_str<'a>(&'a self) -> Self::Str<'a>;
}

impl<'o> Storage for &'o str {
    type Str<'i> = &'o str where Self: 'i;
    fn _as_str<'a>(&'a self) -> Self::Str<'a> {
        self
    }
}

impl Storage for String {
    type Str<'a> = &'a str where Self: 'a;
    fn _as_str<'a>(&'a self) -> Self::Str<'a> {
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
pub trait StorageHelper<'i, 'o>: Storage {
    fn as_str(&'i self) -> &'o str;
}

impl<'i, 'o, T: Storage + 'i> StorageHelper<'i, 'o> for T
where
    T::Str<'i>: 'o,
{
    fn as_str(&'i self) -> &'o str {
        let s: T::Str<'i> = self._as_str();
        s.as_str()
    }
}

pub trait ToUri {
    type Storage;
    type Err;

    fn to_uri(self) -> Result<Uri<Self::Storage>, Self::Err>;
}

#[cold]
fn len_overflow() -> ! {
    panic!("input length exceeds i32::MAX");
}

impl<'a, S: AsRef<[u8]> + ?Sized> ToUri for &'a S {
    type Storage = &'a str;
    type Err = ParseError;

    fn to_uri(self) -> Result<Uri<Self::Storage>, Self::Err> {
        let bytes = self.as_ref();
        if bytes.len() > i32::MAX as usize {
            len_overflow();
        }

        let meta = parser::parse(bytes)?;
        Ok(Uri {
            // SAFETY: The parser guarantees that the bytes are valid UTF-8.
            storage: unsafe { str::from_utf8_unchecked(bytes) },
            meta,
        })
    }
}

impl ToUri for String {
    type Storage = String;
    type Err = ParseError<String>;

    fn to_uri(self) -> Result<Uri<Self::Storage>, Self::Err> {
        if self.len() > i32::MAX as usize {
            len_overflow();
        }

        match parser::parse(self.as_bytes()) {
            Ok(meta) => Ok(Uri {
                storage: self,
                meta,
            }),
            Err(e) => Err(e.with_input(self)),
        }
    }
}

impl ToUri for Vec<u8> {
    type Storage = String;
    type Err = ParseError<Vec<u8>>;

    fn to_uri(self) -> Result<Uri<Self::Storage>, Self::Err> {
        if self.len() > i32::MAX as usize {
            len_overflow();
        }

        match parser::parse(&self) {
            Ok(meta) => Ok(Uri {
                // SAFETY: The parser guarantees that the bytes are valid UTF-8.
                storage: unsafe { String::from_utf8_unchecked(self) },
                meta,
            }),
            Err(e) => Err(e.with_input(self)),
        }
    }
}

#[derive(Clone, Copy, Default)]
pub struct Meta {
    pub flags: Flags,
    // The index of the trailing colon.
    pub scheme_end: Option<NonZeroU32>,
    pub authority_meta: Option<AuthorityMeta>,
    pub path_bounds: (u32, u32),
    // One byte past the last byte of query.
    pub query_end: Option<NonZeroU32>,
}

#[doc(hidden)]
impl<T> Deref for Uri<T> {
    type Target = Meta;
    #[inline]
    fn deref(&self) -> &Meta {
        &self.meta
    }
}

#[doc(hidden)]
impl<T> DerefMut for Uri<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Meta {
        &mut self.meta
    }
}

bitflags! {
    #[derive(Clone, Copy, Default)]
    pub struct Flags: u32 {
        const HOST_REG_NAME = 0b00000001;
        const HOST_IPV4     = 0b00000010;
        const HAS_ZONE_ID   = 0b00000100;
    }
}

#[derive(Clone, Copy)]
pub struct AuthorityMeta {
    pub start: NonZeroU32,
    pub host_bounds: (u32, u32),
    pub host_meta: HostMeta,
}

#[derive(Clone, Copy)]
pub union HostMeta {
    #[cfg(feature = "std")]
    pub ipv4_addr: Ipv4Addr,
    #[cfg(feature = "std")]
    pub ipv6_addr: Ipv6Addr,
    pub none: (),
}
