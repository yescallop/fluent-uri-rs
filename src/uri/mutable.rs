//! Mutable URI components that allow in-place percent-decoding.

use std::{mem, ops::Deref};

use super::*;
use crate::encoding::{EStrMut, SplitMut};

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

    /// Consumes this `AuthorityMut` and yields the underlying mutable byte slice.
    ///
    /// The userinfo subcomponent is truncated if it is already taken.
    ///
    /// # Panics
    ///
    /// Panics if the host subcomponent is already taken.
    #[inline]
    pub fn into_bytes(self) -> &'a mut [u8] {
        if self.uri.tag.contains(Tag::HOST_TAKEN) {
            component_taken();
        }
        // SAFETY: The indexes are within bounds.
        unsafe {
            self.inner
                .uri
                .slice_mut(self.start(), self.uri.path_bounds.0)
        }
    }

    /// Takes the mutable userinfo subcomponent, leaving a `None` in its place.
    #[inline]
    pub fn take_userinfo(&mut self) -> Option<EStrMut<'a>> {
        let (start, host_start) = (self.start(), self.host_bounds().0);
        (start != host_start).then(|| unsafe {
            // SAFETY: Host won't start at index 0.
            self.inner.internal_mut().start = NonZeroU32::new_unchecked(host_start);
            // SAFETY: The indexes are within bounds and we have done the validation.
            self.inner.uri.eslice_mut(start, host_start - 1)
        })
    }

    /// Takes the raw mutable host subcomponent.
    ///
    /// # Panics
    ///
    /// Panics if the host subcomponent is already taken.
    #[inline]
    pub fn take_host_raw(&mut self) -> &'a mut [u8] {
        if self.uri.tag.contains(Tag::HOST_TAKEN) {
            component_taken();
        }
        self.inner.uri.tag |= Tag::HOST_TAKEN;

        let bounds = self.host_bounds();
        // SAFETY: The indexes are within bounds.
        unsafe { self.inner.uri.slice_mut(bounds.0, bounds.1) }
    }

    /// Takes the parsed mutable host subcomponent.
    ///
    /// # Panics
    ///
    /// Panics if the host subcomponent is already taken.
    pub fn take_host(&mut self) -> HostMut<'a> {
        if self.uri.tag.contains(Tag::HOST_TAKEN) {
            component_taken();
        }
        self.inner.uri.tag |= Tag::HOST_TAKEN;

        HostMut::from_authority(self)
    }
}

impl<'i, 'a> Drop for AuthorityMut<'i, 'a> {
    #[inline]
    fn drop(&mut self) {
        self.inner.uri.auth = None;
    }
}

/// A mutable host subcomponent of authority.
///
/// A field is [`EStrMut`] not necessarily because it is percent-encoded.
/// See the documentation of [`EStrMut`] for more details.
#[derive(Debug)]
pub enum HostMut<'a> {
    /// An IPv4 address.
    Ipv4(Ipv4Addr),
    /// An IPv6 address.
    Ipv6 {
        /// The address.
        addr: Ipv6Addr,
        /// An optional zone identifier.
        ///
        /// This is supported on **crate feature `rfc6874bis`** only.
        #[cfg(feature = "rfc6874bis")]
        zone_id: Option<EStrMut<'a>>,
    },
    /// An IP address of future version.
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
    fn from_authority(auth: &mut AuthorityMut<'_, 'a>) -> HostMut<'a> {
        let tag = auth.uri.tag;
        let data = auth.host_data();
        unsafe {
            if tag.contains(Tag::HOST_REG_NAME) {
                let bounds = auth.host_bounds();
                // SAFETY: The indexes are within bounds.
                return HostMut::RegName(auth.inner.uri.eslice_mut(bounds.0, bounds.1));
            } else if tag.contains(Tag::HOST_IPV4) {
                return HostMut::Ipv4(data.ipv4_addr);
            }
            #[cfg(feature = "ipv_future")]
            if !tag.contains(Tag::HOST_IPV6) {
                let dot_i = data.ipv_future_dot_i;
                let bounds = auth.host_bounds();
                // SAFETY: The indexes are within bounds and we have done the validation.
                return HostMut::IpvFuture {
                    ver: auth.inner.uri.eslice_mut(bounds.0 + 2, dot_i),
                    addr: auth.inner.uri.eslice_mut(dot_i + 1, bounds.1 - 1),
                };
            }
            HostMut::Ipv6 {
                addr: data.ipv6.addr,
                // SAFETY: The indexes are within bounds and we have done the validation.
                #[cfg(feature = "rfc6874bis")]
                zone_id: data.ipv6.zone_id_start.map(|start| {
                    auth.inner
                        .uri
                        .eslice_mut(start.get(), auth.host_bounds().1 - 1)
                }),
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

    /// Consumes this `PathMut` and yields the underlying [`EStrMut`].
    #[inline]
    pub fn into_estr_mut(self) -> EStrMut<'a> {
        // SAFETY: Transparency holds.
        unsafe { mem::transmute(self) }
    }

    /// Returns an iterator over the mutable segments of the path.
    #[inline]
    pub fn segments_mut(self) -> SplitMut<'a> {
        let absolute = self.is_absolute();
        let mut path = self.into_estr_mut().into_bytes();
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
