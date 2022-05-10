//! In-place mutable views of URI components.

use std::ops::Deref;

use super::*;
use crate::enc::SplitView;

mod internal {
    use super::*;

    pub trait Lens {
        /// Views the inner bytes of a `View<Self>` as `&Self`.
        fn view(bytes: &[u8]) -> &Self;
    }

    impl Lens for EStr {
        #[inline]
        fn view(bytes: &[u8]) -> &Self {
            // SAFETY: A `View` may only be created through `new`,
            // of which the caller must guarantee that the bytes are properly encoded.
            unsafe { EStr::new_unchecked(bytes) }
        }
    }

    impl Lens for str {
        #[inline]
        fn view(bytes: &[u8]) -> &Self {
            // SAFETY: A `View` may only be created through `new`,
            // of which the caller must guarantee that the bytes are valid UTF-8.
            unsafe { str::from_utf8_unchecked(bytes) }
        }
    }

    impl Lens for Scheme {
        #[inline]
        fn view(bytes: &[u8]) -> &Self {
            Scheme::new(str::view(bytes))
        }
    }

    impl Lens for Path {
        #[inline]
        fn view(bytes: &[u8]) -> &Self {
            Path::new(EStr::view(bytes))
        }
    }
}

pub(crate) use self::internal::Lens;

/// A smart pointer that allows viewing a mutable byte slice as `&T`.
///
/// This struct was introduced considering the fact that a bare `&mut EStr` wouldn't
/// do for in-place decoding because such decoding breaks the invariant of [`EStr`].
///
/// Four types of *lenses* may be used as `T`: [`EStr`], [`prim@str`], [`Scheme`], and [`Path`].
#[derive(Debug)]
#[repr(transparent)]
pub struct View<'a, T: ?Sized + Lens>(&'a mut [u8], PhantomData<&'a T>);

impl<'a, T: ?Sized + Lens> Deref for View<'a, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        T::view(self.0)
    }
}

impl<'a, T: ?Sized + Lens> AsRef<T> for View<'a, T> {
    #[inline]
    fn as_ref(&self) -> &T {
        self
    }
}

impl<'a, T: ?Sized + Lens> View<'a, T> {
    /// Creates a `View<T>` from a mutable byte slice assuming validity.
    ///
    /// # Safety
    ///
    /// The bytes must be valid as `T`.
    #[inline]
    pub(crate) unsafe fn new(bytes: &'a mut [u8]) -> Self {
        View(bytes, PhantomData)
    }

    /// Consumes this `View` and yields the underlying mutable byte slice.
    #[inline]
    pub fn into_bytes(self) -> &'a mut [u8] {
        self.0
    }

    /// Consumes this `View` and yields the underlying `&T`.
    #[inline]
    pub fn into_ref(self) -> &'a T {
        T::view(self.0)
    }
}

/// A [`Scheme`] view into a mutable byte slice that allows lowercasing in-place.
impl<'a> View<'a, Scheme> {
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
        for byte in &mut *self.0 {
            *byte |= ASCII_CASE_MASK;
        }
    }
}

/// A view of the authority component.
#[repr(transparent)]
pub struct AuthorityView<'i, 'a> {
    inner: &'i mut Authority<&'a mut [u8]>,
}

impl<'i, 'a> Deref for AuthorityView<'i, 'a> {
    type Target = Authority<&'a mut [u8]>;
    #[inline]
    fn deref(&self) -> &Authority<&'a mut [u8]> {
        self.inner
    }
}

impl<'i, 'a> AuthorityView<'i, 'a> {
    #[inline]
    pub(super) unsafe fn new(uri: &'i mut Uri<&'a mut [u8]>) -> AuthorityView<'i, 'a> {
        // SAFETY: Transparency holds.
        AuthorityView {
            inner: unsafe { &mut *(uri as *mut Uri<_> as *mut Authority<_>) },
        }
    }

    #[inline]
    unsafe fn view<T: ?Sized + Lens>(&mut self, start: u32, end: u32) -> View<'a, T> {
        // SAFETY: The same as `Uri::view`.
        unsafe { self.inner.uri.view(start, end) }
    }

    /// Consumes this `AuthorityView` and yields the underlying [`View<str>`].
    ///
    /// # Panics
    ///
    /// Panics if any of the subcomponents is already taken.
    #[inline]
    pub fn into_str_view(mut self) -> View<'a, str> {
        if self.uri.tag.intersects(Tag::AUTH_SUB_TAKEN) {
            component_taken();
        }
        // SAFETY: The indexes are within bounds and the validation is done.
        unsafe { self.view(self.start(), self.uri.path_bounds.0) }
    }

    /// Takes a view of the userinfo subcomponent, leaving a `None` in its place.
    #[inline]
    pub fn take_userinfo(&mut self) -> Option<View<'a, EStr>> {
        if self.uri.tag.contains(Tag::USERINFO_TAKEN) {
            return None;
        }
        self.inner.uri.tag |= Tag::USERINFO_TAKEN;

        let (start, host_start) = (self.start(), self.host_bounds().0);
        // SAFETY: The indexes are within bounds and the validation is done.
        (start != host_start).then(|| unsafe { self.view(start, host_start - 1) })
    }

    /// Takes a view of the raw host subcomponent.
    ///
    /// # Panics
    ///
    /// Panics if the host subcomponent is already taken.
    #[inline]
    pub fn take_host_raw(&mut self) -> View<'a, str> {
        if self.uri.tag.contains(Tag::HOST_TAKEN) {
            component_taken();
        }
        self.inner.uri.tag |= Tag::HOST_TAKEN;

        let bounds = self.host_bounds();
        // SAFETY: The indexes are within bounds and the validation is done.
        unsafe { self.view(bounds.0, bounds.1) }
    }

    /// Takes a view of the parsed host subcomponent.
    ///
    /// # Panics
    ///
    /// Panics if the host subcomponent is already taken.
    pub fn take_host(&mut self) -> HostView<'a> {
        if self.uri.tag.contains(Tag::HOST_TAKEN) {
            component_taken();
        }
        self.inner.uri.tag |= Tag::HOST_TAKEN;

        HostView::from_authority(self)
    }

    /// Takes a view of the raw port subcomponent, leaving a `None` in its place.
    #[inline]
    pub fn take_port_raw(&mut self) -> Option<View<'a, str>> {
        if self.uri.tag.contains(Tag::PORT_TAKEN) {
            return None;
        }
        self.inner.uri.tag |= Tag::PORT_TAKEN;

        let (host_end, end) = (self.host_bounds().1, self.uri.path_bounds.0);
        // SAFETY: The indexes are within bounds and the validation is done.
        (host_end != end).then(|| unsafe { self.view(host_end + 1, end) })
    }

    /// Takes a view of the parsed port subcomponent, leaving a `None` in its place.
    #[inline]
    pub fn take_port(&mut self) -> Option<Result<u16, View<'a, str>>> {
        match self.port_raw().filter(|s| !s.is_empty()) {
            Some(s) => match s.parse() {
                Ok(port) => Some(Ok(port)),
                Err(_) => Some(Err(self.take_port_raw().unwrap())),
            },
            None => None,
        }
    }
}

impl<'i, 'a> Drop for AuthorityView<'i, 'a> {
    #[inline]
    fn drop(&mut self) {
        self.inner.uri.auth = None;
    }
}

/// A view of the host subcomponent of authority.
#[derive(Debug)]
pub enum HostView<'a> {
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
        zone_id: Option<View<'a, str>>,
    },
    /// An IP address of future version.
    ///
    /// This is supported on **crate feature `ipv_future`** only.
    #[cfg(feature = "ipv_future")]
    IpvFuture {
        /// The version.
        ver: View<'a, str>,
        /// The address.
        addr: View<'a, str>,
    },
    /// A registered name.
    RegName(View<'a, EStr>),
}

impl<'a> HostView<'a> {
    fn from_authority(auth: &mut AuthorityView<'_, 'a>) -> HostView<'a> {
        let tag = auth.uri.tag;
        let data = auth.host_data();
        unsafe {
            if tag.contains(Tag::HOST_REG_NAME) {
                let bounds = auth.host_bounds();
                // SAFETY: The indexes are within bounds and the validation is done.
                return HostView::RegName(auth.view(bounds.0, bounds.1));
            } else if tag.contains(Tag::HOST_IPV4) {
                return HostView::Ipv4(data.ipv4_addr);
            }
            #[cfg(feature = "ipv_future")]
            if !tag.contains(Tag::HOST_IPV6) {
                let dot_i = data.ipv_future_dot_i;
                let bounds = auth.host_bounds();
                // SAFETY: The indexes are within bounds and the validation is done.
                return HostView::IpvFuture {
                    ver: auth.view(bounds.0 + 2, dot_i),
                    addr: auth.view(dot_i + 1, bounds.1 - 1),
                };
            }
            HostView::Ipv6 {
                addr: data.ipv6.addr,
                // SAFETY: The indexes are within bounds and the validation is done.
                #[cfg(feature = "rfc6874bis")]
                zone_id: data
                    .ipv6
                    .zone_id_start
                    .map(|start| auth.view(start.get(), auth.host_bounds().1 - 1)),
            }
        }
    }
}

/// A [`Path`] view into a mutable byte slice.
impl<'a> View<'a, Path> {
    /// Consumes this `View<Path>` and yields the underlying `View<EStr>`.
    #[inline]
    pub fn into_estr_view(self) -> View<'a, EStr> {
        View(self.0, PhantomData)
    }

    /// Returns an iterator over the views of path segments.
    #[inline]
    pub fn segments_view(self) -> SplitView<'a> {
        let absolute = self.is_absolute();
        let mut path = self.into_estr_view().into_bytes();
        let empty = path.is_empty();

        if absolute {
            // SAFETY: Skipping "/" is fine.
            path = unsafe { path.get_unchecked_mut(1..) };
        }
        // SAFETY: We have done the validation.
        let path = unsafe { View::<EStr>::new(path) };

        let mut split = path.split_view('/');
        split.finished = empty;
        split
    }
}
