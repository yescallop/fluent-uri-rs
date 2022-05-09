//! Mutable URI components that allow in-place percent-decoding.

use std::{mem, ops::Deref};

use super::*;
use crate::encoding::SplitMut;

/// A wrapper around a mutable reference that may not be mutably reborrowed.
///
/// This struct was introduced considering the fact that a bare `&mut EStr` wouldn't
/// do for in-place decoding because such decoding breaks the invariant of [`EStr`].
///
/// For non-percent-encoded data to be in-place mutable, we also have `OnceMut<str>`
/// that can be first borrowed as an `&str` and then cast to an `&mut [u8]`.
#[derive(Debug)]
#[repr(transparent)]
pub struct OnceMut<'a, T: ?Sized>(pub(crate) &'a mut T);

impl<'a, T: ?Sized> Deref for OnceMut<'a, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        self.0
    }
}

impl<'a, T: ?Sized> AsRef<T> for OnceMut<'a, T> {
    #[inline]
    fn as_ref(&self) -> &T {
        self.0
    }
}

impl<'a, T: ?Sized> OnceMut<'a, T> {
    /// Consumes this `OnceMut` and yields the underlying immutable reference.
    #[inline]
    pub fn into_ref(self) -> &'a T {
        self.0
    }
}

/// A wrapper around a mutable string slice that may be cast to a mutable byte slice.
impl<'a> OnceMut<'a, str> {
    /// Converts a byte slice into a `OnceMut<str>` assuming validity.
    #[inline]
    pub(crate) unsafe fn new_str(s: &mut [u8]) -> OnceMut<'_, str> {
        // SAFETY: The caller must ensure that the bytes are valid percent-encoded UTF-8.
        OnceMut(unsafe { str::from_utf8_unchecked_mut(s) })
    }

    /// Consumes this `OnceMut<str>` and yields the underlying mutable byte slice.
    #[inline]
    pub fn into_bytes(self) -> &'a mut [u8] {
        // SAFETY: A `OnceMut<str>` may only be created by `new_str`,
        // which takes a mutable byte slice as argument.
        unsafe { self.0.as_bytes_mut() }
    }
}

/// A mutable scheme component.
impl<'a> OnceMut<'a, Scheme> {
    /// Converts a byte slice into a `OnceMut<Scheme>` assuming validity.
    #[inline]
    pub(super) unsafe fn new_scheme(s: &mut [u8]) -> OnceMut<'_, Scheme> {
        // SAFETY: The caller must ensure that the bytes are valid for scheme.
        // Transparency holds.
        OnceMut(unsafe { &mut *(s as *mut [u8] as *mut Scheme) })
    }

    /// Consumes this `OnceMut<Scheme>` and yields the underlying mutable byte slice.
    #[inline]
    pub fn into_bytes(self) -> &'a mut [u8] {
        // SAFETY: A `OnceMut<Scheme>` may only be created by `new_scheme`,
        // which takes a mutable byte slice as argument.
        unsafe { self.0 .0.as_bytes_mut() }
    }

    /// Converts the scheme to lower case in-place.
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let mut vec = b"HTTP://example.com/".to_vec();
    /// let mut uri = Uri::parse_mut(&mut vec)?;
    ///
    /// let mut scheme = uri.take_scheme().unwrap();
    /// scheme.make_lowercase();
    /// assert_eq!(scheme.as_str(), "http");
    /// # Ok::<_, fluent_uri::ParseError>(())
    /// ```
    #[inline]
    pub fn make_lowercase(&mut self) {
        // SAFETY: Setting the sixth bit keeps UTF-8.
        let bytes = unsafe { self.0 .0.as_bytes_mut() };
        for byte in bytes {
            *byte |= ASCII_CASE_MASK;
        }
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

    /// Consumes this `AuthorityMut` and yields the underlying [`OnceMut<str>`].
    ///
    /// # Panics
    ///
    /// Panics if any of the subcomponents is already taken.
    #[inline]
    pub fn into_once_mut_str(self) -> OnceMut<'a, str> {
        if self.uri.tag.intersects(Tag::AUTH_SUB_TAKEN) {
            component_taken();
        }
        // SAFETY: The indexes are within bounds.
        unsafe {
            self.inner
                .uri
                .sslice_mut(self.start(), self.uri.path_bounds.0)
        }
    }

    /// Takes the mutable userinfo subcomponent, leaving a `None` in its place.
    #[inline]
    pub fn take_userinfo(&mut self) -> Option<OnceMut<'a, EStr>> {
        if self.uri.tag.contains(Tag::USERINFO_TAKEN) {
            return None;
        }
        self.inner.uri.tag |= Tag::USERINFO_TAKEN;

        let (start, host_start) = (self.start(), self.host_bounds().0);
        // SAFETY: The indexes are within bounds and we have done the validation.
        (start != host_start).then(|| unsafe { self.inner.uri.eslice_mut(start, host_start - 1) })
    }

    /// Takes the raw mutable host subcomponent.
    ///
    /// # Panics
    ///
    /// Panics if the host subcomponent is already taken.
    #[inline]
    pub fn take_host_raw(&mut self) -> OnceMut<'a, str> {
        if self.uri.tag.contains(Tag::HOST_TAKEN) {
            component_taken();
        }
        self.inner.uri.tag |= Tag::HOST_TAKEN;

        let bounds = self.host_bounds();
        // SAFETY: The indexes are within bounds.
        unsafe { self.inner.uri.sslice_mut(bounds.0, bounds.1) }
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

    /// Takes the raw mutable port subcomponent, leaving a `None` in its place.
    #[inline]
    pub fn take_port_raw(&mut self) -> Option<OnceMut<'a, str>> {
        if self.uri.tag.contains(Tag::PORT_TAKEN) {
            return None;
        }
        self.inner.uri.tag |= Tag::PORT_TAKEN;

        let host_end = self.host_bounds().1;
        // SAFETY: The indexes are within bounds.
        (host_end != self.uri.path_bounds.0).then(|| unsafe {
            self.inner
                .uri
                .sslice_mut(host_end + 1, self.uri.path_bounds.0)
        })
    }

    /// Takes the parsed mutable port subcomponent, leaving a `None` in its place.
    #[inline]
    pub fn take_port(&mut self) -> Option<Result<u16, OnceMut<'a, str>>> {
        match self.port_raw().filter(|s| !s.is_empty()) {
            Some(s) => match s.parse() {
                Ok(port) => Some(Ok(port)),
                Err(_) => Some(Err(self.take_port_raw().unwrap())),
            },
            None => None,
        }
    }
}

impl<'i, 'a> Drop for AuthorityMut<'i, 'a> {
    #[inline]
    fn drop(&mut self) {
        self.inner.uri.auth = None;
    }
}

/// A mutable host subcomponent of authority.
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
        zone_id: Option<OnceMut<'a, str>>,
    },
    /// An IP address of future version.
    ///
    /// This is supported on **crate feature `ipv_future`** only.
    #[cfg(feature = "ipv_future")]
    IpvFuture {
        /// The version.
        ver: OnceMut<'a, str>,
        /// The address.
        addr: OnceMut<'a, str>,
    },
    /// A registered name.
    RegName(OnceMut<'a, EStr>),
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
                    ver: auth.inner.uri.sslice_mut(bounds.0 + 2, dot_i),
                    addr: auth.inner.uri.sslice_mut(dot_i + 1, bounds.1 - 1),
                };
            }
            HostMut::Ipv6 {
                addr: data.ipv6.addr,
                // SAFETY: The indexes are within bounds and we have done the validation.
                #[cfg(feature = "rfc6874bis")]
                zone_id: data.ipv6.zone_id_start.map(|start| {
                    auth.inner
                        .uri
                        .sslice_mut(start.get(), auth.host_bounds().1 - 1)
                }),
            }
        }
    }
}

/// A mutable path component.
impl<'a> OnceMut<'a, Path> {
    #[inline]
    pub(super) fn new_path(path: OnceMut<'_, EStr>) -> OnceMut<'_, Path> {
        // SAFETY: Transparency holds.
        unsafe { mem::transmute(path) }
    }

    /// Consumes this `OnceMut<Path>` and yields the underlying `OnceMut<EStr>`.
    #[inline]
    pub fn into_once_mut_estr(self) -> OnceMut<'a, EStr> {
        // SAFETY: Transparency holds.
        unsafe { mem::transmute(self) }
    }

    /// Returns an iterator over the mutable segments of the path.
    #[inline]
    pub fn segments_mut(self) -> SplitMut<'a> {
        let absolute = self.is_absolute();
        let mut path = self.into_once_mut_estr().into_bytes();
        let empty = path.is_empty();

        if absolute {
            // SAFETY: Skipping "/" is fine.
            path = unsafe { path.get_unchecked_mut(1..) };
        }
        // SAFETY: We have done the validation.
        let path = unsafe { OnceMut::new_estr(path) };

        let mut split = path.split_mut('/');
        split.finished = empty;
        split
    }
}
