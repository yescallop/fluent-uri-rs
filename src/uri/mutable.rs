//! Mutable URI components that allow in-place percent-decoding.

use std::{mem, ops::Deref};

use super::*;
use crate::encoding::{EStrMut, SplitMut};

/// A mutable authority component.
#[repr(transparent)]
pub struct AuthorityMut<'uri, 'out> {
    inner: &'uri mut Authority<&'out mut [u8]>,
}

impl<'uri, 'out> Deref for AuthorityMut<'uri, 'out> {
    type Target = Authority<&'out mut [u8]>;
    #[inline]
    fn deref(&self) -> &Authority<&'out mut [u8]> {
        self.inner
    }
}

impl<'uri, 'out> AuthorityMut<'uri, 'out> {
    #[inline]
    pub(super) unsafe fn new(
        uri: &'uri mut Uri<&'out mut [u8]>,
    ) -> AuthorityMut<'uri, 'out> {
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

    /// Takes the userinfo subcomponent out of the `Authority`, leaving a `None` in its place.
    #[inline]
    pub fn take_userinfo_mut(&mut self) -> Option<EStrMut<'out>> {
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

    /// Turns into the mutable raw host subcomponent.
    #[inline]
    pub fn into_host_raw_mut(self) -> &'out mut [u8] {
        let bounds = self.host_bounds();
        // SAFETY: The indexes are within bounds.
        unsafe { self.inner.uri.slice_mut(bounds.0, bounds.1) }
    }

    /// Turns into the mutable parsed host subcomponent.
    pub fn into_host_mut(self) -> HostMut<'out> {
        HostMut::from_authority(self)
    }
}

impl<'uri, 'out> Drop for AuthorityMut<'uri, 'out> {
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
    Ipv6 {
        /// The address.
        addr: Ipv6Addr,
        // /// The zone identifier.
        // zone_id: Option<&'a EStr>,
    },
    /// An IP address of future version.
    ///
    /// This is supported on **crate feature `ipv_future`** only.
    #[cfg(feature = "ipv_future")]
    IpvFuture {
        /// The version.
        ver: &'a mut [u8],
        /// The address.
        addr: &'a mut [u8],
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
                HostMut::Ipv6 {
                    addr: data.ipv6_addr,
                }
            } else {
                let dot_i = data.ipv_future_dot_i;
                let bounds = auth.host_bounds();
                // SAFETY: The indexes are within bounds.
                HostMut::IpvFuture {
                    ver: auth.inner.uri.slice_mut(bounds.0 + 2, dot_i),
                    addr: auth.inner.uri.slice_mut(dot_i + 1, bounds.1 - 1),
                }
            }
            #[cfg(not(feature = "ipv_future"))]
            HostMut::Ipv6 {
                addr: data.ipv6_addr,
            }
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

    /// Returns the path as a mutable `EStr` slice.
    #[inline]
    pub fn into_mut_estr(self) -> EStrMut<'a> {
        // SAFETY: Transparency holds.
        unsafe { mem::transmute(self) }
    }

    /// Turns into an iterator over the mutable segments of the path.
    #[inline]
    pub fn into_mut_segments(self) -> SplitMut<'a> {
        let absolute = self.is_absolute();
        let mut path = self.into_mut_estr().into_mut_bytes();
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
