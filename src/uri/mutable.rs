//! Mutable URI components that allow in-place percent-decoding.

use std::{mem, ops::Deref};

use super::*;
use crate::encoding::{EStrMut, SplitMut};

pub(super) mod internal {
    use crate::encoding::CapOverflowError;
    use std::{convert::Infallible, mem::MaybeUninit};

    pub trait Buf {
        type ReserveError;

        fn reserve(&mut self, additional: u32) -> Result<*mut u8, Self::ReserveError>;

        unsafe fn inc_len(&mut self, inc: u32);
    }

    impl Buf for Vec<u8> {
        type ReserveError = Infallible;

        #[inline]
        fn reserve(&mut self, additional: u32) -> Result<*mut u8, Infallible> {
            self.reserve(additional as usize);
            Ok(self.as_mut_ptr_range().end)
        }

        #[inline]
        unsafe fn inc_len(&mut self, inc: u32) {
            // SAFETY: The caller must ensure that the additional `inc` bytes are initialized.
            unsafe { self.set_len(self.len() + inc as usize) }
        }
    }

    impl Buf for [u8] {
        type ReserveError = CapOverflowError;

        #[inline]
        fn reserve(&mut self, len: u32) -> Result<*mut u8, CapOverflowError> {
            if self.len() < len as usize {
                Err(CapOverflowError)
            } else {
                Ok(self.as_mut_ptr())
            }
        }

        #[inline]
        unsafe fn inc_len(&mut self, _inc: u32) {}
    }

    impl Buf for [MaybeUninit<u8>] {
        type ReserveError = CapOverflowError;

        #[inline]
        fn reserve(&mut self, len: u32) -> Result<*mut u8, CapOverflowError> {
            if self.len() < len as usize {
                Err(CapOverflowError)
            } else {
                Ok(self.as_mut_ptr().cast())
            }
        }

        #[inline]
        unsafe fn inc_len(&mut self, _inc: u32) {}
    }
}

/// A mutable authority component.
#[repr(transparent)]
pub struct AuthorityMut<'i, 'a> {
    inner: &'i mut Authority<&'a mut [u8]>,
}

impl<'i, 'a> Deref for AuthorityMut<'i, 'a> {
    type Target = Authority<&'a mut [u8]>;
    #[inline]
    fn deref(&self) -> &Authority<&'a mut [u8]> {
        self.inner
    }
}

impl<'i, 'a> AuthorityMut<'i, 'a> {
    #[inline]
    pub(super) unsafe fn new(uri: &'i mut Uri<&'a mut [u8]>) -> AuthorityMut<'i, 'a> {
        // SAFETY: Transparency holds.
        AuthorityMut {
            inner: unsafe { &mut *(uri as *mut Uri<_> as *mut Authority<_>) },
        }
    }

    #[inline]
    fn host_internal_mut(&mut self) -> &mut HostInternal {
        // SAFETY: When authority is present, `host` must be `Some`.
        let host = unsafe { self.inner.uri.host.as_mut().unwrap_unchecked() };
        &mut host.2
    }

    /// Consumes this `AuthorityMut` and yields the underlying mutable byte slice.
    #[inline]
    pub fn into_mut_bytes(self) -> &'a mut [u8] {
        // SAFETY: The indexes are within bounds.
        unsafe { self.inner.uri.slice_mut(self.start(), self.uri.path.0) }
    }

    /// Takes the mutable userinfo subcomponent out of the `AuthorityMut`, leaving a `None` in its place.
    #[inline]
    pub fn take_userinfo_mut(&mut self) -> Option<EStrMut<'a>> {
        let tag = &mut self.host_internal_mut().tag;
        if tag.contains(HostTag::HAS_USERINFO) {
            tag.remove(HostTag::HAS_USERINFO);

            let start = self.start();
            let host_start = self.host_bounds().0;
            // SAFETY: The indexes are within bounds and we have done the validation.
            Some(unsafe { self.inner.uri.eslice_mut(start, host_start - 1) })
        } else {
            None
        }
    }

    /// Consumes this `AuthorityMut` and returns the raw mutable host subcomponent.
    #[inline]
    pub fn into_host_raw_mut(self) -> &'a mut [u8] {
        let bounds = self.host_bounds();
        // SAFETY: The indexes are within bounds.
        unsafe { self.inner.uri.slice_mut(bounds.0, bounds.1) }
    }

    /// Consumes this `AuthorityMut` and returns the parsed mutable host subcomponent.
    pub fn into_host_mut(self) -> HostMut<'a> {
        HostMut::from_authority(self)
    }
}

impl<'i, 'a> Drop for AuthorityMut<'i, 'a> {
    #[inline]
    fn drop(&mut self) {
        self.inner.uri.host = None;
    }
}

/// A mutable host subcomponent of authority.
#[derive(Debug)]
pub enum HostMut<'a> {
    /// An IPv4 address.
    Ipv4(Ipv4Addr),
    /// An IPv6 address.
    ///
    /// In the future an optional zone identifier may be supported.
    Ipv6(Ipv6Addr),
    /// An IP address of future version.
    ///
    /// Note that neither `ver` nor `addr` is percent-encoded.
    ///
    /// This is supported on **crate feature `ipv_future`** only.
    #[cfg(feature = "ipv_future")]
    IpvFuture {
        /// The version.
        ver: EStrMut<'a>,
        /// The address.
        addr: EStrMut<'a>,
    },
    /// A registered name.
    RegName(EStrMut<'a>),
}

impl<'a> HostMut<'a> {
    fn from_authority(auth: AuthorityMut<'_, 'a>) -> HostMut<'a> {
        let HostInternal { tag, ref data } = *auth.host_internal();
        unsafe {
            if tag.contains(HostTag::REG_NAME) {
                return HostMut::RegName(EStrMut::new(auth.into_host_raw_mut()));
            } else if tag.contains(HostTag::IPV4) {
                return HostMut::Ipv4(data.ipv4_addr);
            }
            #[cfg(feature = "ipv_future")]
            if tag.contains(HostTag::IPV6) {
                HostMut::Ipv6(data.ipv6_addr)
            } else {
                let dot_i = data.ipv_future_dot_i;
                let bounds = auth.host_bounds();
                // SAFETY: The indexes are within bounds and we have done the validation.
                HostMut::IpvFuture {
                    ver: auth.inner.uri.eslice_mut(bounds.0 + 2, dot_i),
                    addr: auth.inner.uri.eslice_mut(dot_i + 1, bounds.1 - 1),
                }
            }
            #[cfg(not(feature = "ipv_future"))]
            HostMut::Ipv6(data.ipv6_addr)
        }
    }
}

/// A mutable path component.
#[repr(transparent)]
#[derive(Debug)]
pub struct PathMut<'a>(&'a mut Path);

impl<'a> Deref for PathMut<'a> {
    type Target = Path;
    #[inline]
    fn deref(&self) -> &Path {
        self.0
    }
}

impl<'a> PathMut<'a> {
    #[inline]
    pub(super) fn new(path: EStrMut<'_>) -> PathMut<'_> {
        // SAFETY: Transparency holds.
        unsafe { mem::transmute(path) }
    }

    /// Consumes this `PathMut` and yields the underlying `EStrMut`.
    #[inline]
    pub fn into_estr_mut(self) -> EStrMut<'a> {
        // SAFETY: Transparency holds.
        unsafe { mem::transmute(self) }
    }

    /// Returns an iterator over the mutable segments of the path.
    #[inline]
    pub fn segments_mut(self) -> SplitMut<'a> {
        let absolute = self.is_absolute();
        let mut path = self.into_estr_mut().into_mut_bytes();
        let empty = path.is_empty();

        if absolute {
            // SAFETY: Skipping "/" is fine.
            path = unsafe { path.get_unchecked_mut(1..) };
        }
        // SAFETY: We have done the validation.
        let path = unsafe { EStrMut::new(path) };

        let mut split = path.split_mut('/');
        split.finished = empty;
        split
    }
}
