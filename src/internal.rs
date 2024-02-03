#![allow(missing_debug_implementations)]

use crate::{parser, ParseError, Uri};
use alloc::{borrow::ToOwned, string::String, vec::Vec};
use bitflags::bitflags;
use core::{
    marker::PhantomData,
    mem::{ManuallyDrop, MaybeUninit},
    num::NonZeroU32,
    ops::{Deref, DerefMut},
    ptr::NonNull,
    slice, str,
};

#[cfg(feature = "std")]
use std::net::{Ipv4Addr, Ipv6Addr};

pub trait Pointer: Clone + Default {
    fn get(&self) -> *mut u8;
    fn len(&self) -> u32;
}

#[derive(Clone)]
#[repr(C)]
pub struct Uncapped {
    ptr: NonNull<u8>,
    len: u32,
    _pad: MaybeUninit<u32>,
}

impl Uncapped {
    pub fn new(s: &[u8]) -> Uncapped {
        Uncapped {
            // SAFETY: `s.as_ptr()` cannot be null.
            ptr: unsafe { NonNull::new_unchecked(s.as_ptr() as _) },
            len: s.len() as _,
            _pad: MaybeUninit::uninit(),
        }
    }
}

impl Pointer for Uncapped {
    #[inline]
    fn get(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    #[inline]
    fn len(&self) -> u32 {
        self.len
    }
}

impl Default for Uncapped {
    #[inline]
    fn default() -> Self {
        Self {
            ptr: NonNull::dangling(),
            len: 0,
            _pad: MaybeUninit::uninit(),
        }
    }
}

#[repr(C)]
pub struct Capped {
    ptr: NonNull<u8>,
    len: u32,
    cap: u32,
}

impl Capped {
    #[inline]
    pub fn new(s: Vec<u8>) -> Capped {
        let s = ManuallyDrop::new(s);
        Capped {
            // SAFETY: `s.as_ptr()` cannot be null.
            ptr: unsafe { NonNull::new_unchecked(s.as_ptr() as _) },
            len: s.len() as _,
            cap: s.capacity() as _,
        }
    }

    #[inline]
    pub fn into_bytes(self) -> Vec<u8> {
        let me = ManuallyDrop::new(self);
        // SAFETY: `Capped` is created from a `Vec<u8>`.
        unsafe { Vec::from_raw_parts(me.get(), me.len as _, me.cap as _) }
    }
}

impl Pointer for Capped {
    #[inline]
    fn get(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    #[inline]
    fn len(&self) -> u32 {
        self.len
    }
}

impl Clone for Capped {
    #[inline]
    fn clone(&self) -> Capped {
        // SAFETY: `Capped` is created from a `Vec<u8>`.
        let s = unsafe { slice::from_raw_parts(self.get(), self.len as _) };
        Capped::new(s.to_owned())
    }
}

impl Default for Capped {
    #[inline]
    fn default() -> Self {
        Self {
            ptr: NonNull::dangling(),
            len: 0,
            cap: 0,
        }
    }
}

impl Drop for Capped {
    #[inline]
    fn drop(&mut self) {
        // SAFETY: `Capped` is created from a `Vec<u8>`.
        let _ = unsafe { Vec::from_raw_parts(self.get(), 0, self.cap as _) };
    }
}

pub trait Storage {
    type Ptr: Pointer;
    type Ref<'a>;
}

impl<'o> Storage for &'o str {
    type Ptr = Uncapped;
    type Ref<'i> = &'o str;
}

impl Storage for String {
    type Ptr = Capped;
    type Ref<'a> = &'a str;
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
pub trait StorageHelper<'i, 'o>: Storage {}

impl<'i, 'o, T: Storage> StorageHelper<'i, 'o> for T where T::Ref<'i>: 'o {}

pub trait ToUri {
    type Storage: Storage;
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
            ptr: Uncapped::new(bytes),
            meta,
            _marker: PhantomData,
        })
    }
}

#[cold]
fn cap_overflow() -> ! {
    panic!("input capacity exceeds i32::MAX");
}

impl ToUri for String {
    type Storage = String;
    type Err = ParseError<String>;

    fn to_uri(self) -> Result<Uri<Self::Storage>, Self::Err> {
        if self.capacity() > i32::MAX as usize {
            cap_overflow();
        }

        match parser::parse(self.as_bytes()) {
            Ok(meta) => Ok(Uri {
                ptr: Capped::new(self.into()),
                meta,
                _marker: PhantomData,
            }),
            Err(e) => Err(e.with_input(self)),
        }
    }
}

impl ToUri for Vec<u8> {
    type Storage = String;
    type Err = ParseError<Vec<u8>>;

    fn to_uri(self) -> Result<Uri<Self::Storage>, Self::Err> {
        if self.capacity() > i32::MAX as usize {
            cap_overflow();
        }

        match parser::parse(&self) {
            Ok(meta) => Ok(Uri {
                ptr: Capped::new(self),
                meta,
                _marker: PhantomData,
            }),
            Err(e) => Err(e.with_input(self)),
        }
    }
}

#[derive(Clone, Default)]
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
impl<C: Storage> Deref for Uri<C> {
    type Target = Meta;
    #[inline]
    fn deref(&self) -> &Meta {
        &self.meta
    }
}

#[doc(hidden)]
impl<C: Storage> DerefMut for Uri<C> {
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

#[derive(Clone)]
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
