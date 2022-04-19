mod fmt;

pub mod mutable;
use mutable::*;

mod parser;

use crate::encoding::{EStr, EStrMut, Split};
use bitflags::bitflags;
use std::{
    marker::PhantomData,
    mem::ManuallyDrop,
    net::{Ipv4Addr, Ipv6Addr},
    num::NonZeroU32,
    ptr::NonNull,
    slice, str,
};

mod internal {
    pub trait Storage<'uri, 'out> {
        type Output: 'out;
    }

    impl<'uri, 'a> Storage<'uri, 'a> for &'a str {
        type Output = &'a str;
    }

    impl<'uri, 'a> Storage<'uri, 'a> for &'a mut [u8] {
        type Output = &'a mut [u8];
    }

    impl<'uri> Storage<'uri, 'uri> for String {
        type Output = &'uri str;
    }

    pub trait Buf {
        fn as_raw_parts(&self) -> (*mut u8, usize, usize);
    }

    impl Buf for String {
        #[inline]
        fn as_raw_parts(&self) -> (*mut u8, usize, usize) {
            (self.as_ptr() as _, self.len(), self.capacity())
        }
    }

    impl Buf for Vec<u8> {
        #[inline]
        fn as_raw_parts(&self) -> (*mut u8, usize, usize) {
            (self.as_ptr() as _, self.len(), self.capacity())
        }
    }
}

use internal::{Buf, Storage};

/// Detailed cause of a [`SyntaxError`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyntaxErrorKind {
    /// Invalid percent-encoded octet that is either non-hexadecimal or incomplete.
    ///
    /// The error index points to the percent character "%" of the octet.
    InvalidOctet,
    /// Unexpected character that is not allowed by the URI syntax.
    ///
    /// The error index points to the character.
    UnexpectedChar,
    /// Invalid IP literal.
    ///
    /// The error index points to the preceding left square bracket "[".
    InvalidIpLiteral,
}

/// A syntax error occurred when parsing, decoding or validating strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyntaxError {
    pub(crate) index: usize,
    pub(crate) kind: SyntaxErrorKind,
}

impl SyntaxError {
    /// Returns the index where the error occurred in the input string.
    #[inline]
    pub fn index(self) -> usize {
        self.index
    }

    /// Returns the detailed cause of the error.
    #[inline]
    pub fn kind(self) -> SyntaxErrorKind {
        self.kind
    }
}

impl std::error::Error for SyntaxError {}

pub(crate) type Result<T, E = SyntaxError> = std::result::Result<T, E>;

/// A URI reference defined in [RFC 3986].
///
/// [RFC 3986]: https://datatracker.ietf.org/doc/html/rfc3986/
#[repr(C)]
pub struct Uri<T> {
    ptr: NonNull<u8>,
    cap: u32,
    len: u32,
    // One byte past the trailing ':'.
    // This encoding is chosen so that no extra branch is introduced
    // when indexing the start of the authority.
    scheme_end: Option<NonZeroU32>,
    host: Option<(NonZeroU32, u32, HostInternal)>,
    path: (u32, u32),
    // One byte past the last byte of query.
    query_end: Option<NonZeroU32>,
    // One byte past the preceding '#'.
    fragment_start: Option<NonZeroU32>,
    _marker: PhantomData<T>,
}

impl Uri<&str> {
    /// Parses a URI reference from a byte sequence into a `Uri<&str>`.
    ///
    /// This function validates the input strictly except that UTF-8 validation is not
    /// performed on a percent-encoded registered name (see [Section 3.2.2, RFC 3986][1]).
    /// Care should be taken when dealing with such cases.
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.2
    ///
    /// # Panics
    ///
    /// Panics if the input length is greater than `i32::MAX`.
    pub fn parse<S: AsRef<[u8]> + ?Sized>(s: &S) -> Result<Uri<&str>> {
        #[cold]
        fn len_overflow() -> ! {
            panic!("input length exceeds i32::MAX");
        }

        let bytes = s.as_ref();
        if bytes.len() > i32::MAX as usize {
            len_overflow();
        }
        // SAFETY: We're using the right pointer, length, capacity, and generics.
        unsafe { parser::parse(bytes.as_ptr() as *mut _, bytes.len() as u32, 0) }
    }
}

impl<'uri, 'out, T: Storage<'uri, 'out, Output = &'out str>> Uri<T> {
    #[inline]
    /// Returns the URI reference as a string slice.
    pub fn as_str(&'uri self) -> &'out str {
        // SAFETY: The indexes are within bounds.
        unsafe { self.slice(0, self.len) }
    }
}

impl<'uri, 'out, T: Storage<'uri, 'out>> Uri<T> {
    #[inline]
    unsafe fn slice(&'uri self, start: u32, end: u32) -> &'out str {
        debug_assert!(start <= end && end <= self.len);
        // SAFETY: The caller must ensure that the indexes are within bounds.
        let bytes = unsafe {
            slice::from_raw_parts(
                self.ptr.as_ptr().add(start as usize),
                (end - start) as usize,
            )
        };
        // SAFETY: The parser guarantees that the bytes are valid UTF-8.
        unsafe { str::from_utf8_unchecked(bytes) }
    }

    #[inline]
    unsafe fn eslice(&'uri self, start: u32, end: u32) -> &'out EStr {
        // SAFETY: The caller must ensure that the indexes are within bounds.
        let s = unsafe { self.slice(start, end) };
        // SAFETY: The caller must ensure that the subslice is properly encoded.
        unsafe { EStr::new_unchecked(s.as_bytes()) }
    }

    /// Returns the [scheme] component.
    ///
    /// [scheme]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.1
    #[inline]
    pub fn scheme(&'uri self) -> Option<&'out Scheme> {
        // SAFETY: The indexes are within bounds.
        self.scheme_end
            .map(|i| Scheme::new(unsafe { self.slice(0, i.get() - 1) }))
    }

    /// Returns the [authority] component.
    ///
    /// [authority]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2
    #[inline]
    pub fn authority(&'uri self) -> Option<&'uri Authority<T>> {
        if self.host.is_some() {
            // SAFETY: `host` is `Some`.
            Some(unsafe { Authority::new(self) })
        } else {
            None
        }
    }

    /// Returns the [path] component.
    ///
    /// [path]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.3
    #[inline]
    pub fn path(&'uri self) -> &'out Path {
        // SAFETY: The indexes are within bounds and we have done the validation.
        Path::new(unsafe { self.eslice(self.path.0, self.path.1) })
    }

    /// Returns the [query] component.
    ///
    /// [query]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.4
    #[inline]
    pub fn query(&'uri self) -> Option<&'out EStr> {
        // SAFETY: The indexes are within bounds and we have done the validation.
        self.query_end
            .map(|i| unsafe { self.eslice(self.path.1 + 1, i.get()) })
    }

    /// Returns the [fragment] component.
    ///
    /// [fragment]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.5
    #[inline]
    pub fn fragment(&'uri self) -> Option<&'out EStr> {
        // SAFETY: The indexes are within bounds and we have done the validation.
        self.fragment_start
            .map(|i| unsafe { self.eslice(i.get(), self.len) })
    }

    /// Returns `true` if the URI reference is [relative], i.e., without a scheme.
    ///
    /// Note that this function is not the opposite of [`is_absolute`].
    ///
    /// [relative]: https://datatracker.ietf.org/doc/html/rfc3986/#section-4.2
    /// [`is_absolute`]: Self::is_absolute
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let uri = Uri::parse("/path/to/file")?;
    /// assert!(uri.is_relative());
    /// let uri = Uri::parse("http://example.com/")?;
    /// assert!(!uri.is_relative());
    /// # Ok::<_, fluent_uri::SyntaxError>(())
    /// ```
    #[inline]
    pub fn is_relative(&'uri self) -> bool {
        self.scheme_end.is_none()
    }

    /// Returns `true` if the URI reference is [absolute], i.e., with a scheme and without a fragment.
    ///
    /// Note that this function is not the opposite of [`is_relative`].
    ///
    /// [absolute]: https://datatracker.ietf.org/doc/html/rfc3986/#section-4.3
    /// [`is_relative`]: Self::is_relative
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let uri = Uri::parse("http://example.com/")?;
    /// assert!(uri.is_absolute());
    /// let uri = Uri::parse("http://example.com/#title1")?;
    /// assert!(!uri.is_absolute());
    /// let uri = Uri::parse("/path/to/file")?;
    /// assert!(!uri.is_absolute());
    /// # Ok::<_, fluent_uri::SyntaxError>(())
    /// ```
    #[inline]
    pub fn is_absolute(&'uri self) -> bool {
        self.scheme_end.is_some() && self.fragment_start.is_none()
    }
}

impl<'a> Uri<&'a mut [u8]> {
    /// Parses a URI reference from a mutable byte sequence into a `Uri<&mut [u8]>`.
    ///
    /// # Panics
    ///
    /// Panics if the input length is greater than `i32::MAX`.
    #[inline]
    pub fn parse_mut<S: AsMut<[u8]> + ?Sized>(s: &mut S) -> Result<Uri<&mut [u8]>> {
        let bytes = s.as_mut();
        assert!(
            bytes.len() <= i32::MAX as usize,
            "input length exceeds i32::MAX"
        );
        // SAFETY: We're using the right pointer, length, capacity, and generics.
        unsafe { parser::parse(bytes.as_mut_ptr(), bytes.len() as u32, 0) }
    }

    #[inline]
    unsafe fn slice_mut(&mut self, start: u32, end: u32) -> &'a mut [u8] {
        debug_assert!(start <= end && end <= self.len);
        // SAFETY: The caller must ensure that the indexes are within bounds.
        unsafe {
            slice::from_raw_parts_mut(
                self.ptr.as_ptr().add(start as usize),
                (end - start) as usize,
            )
        }
    }

    #[inline]
    unsafe fn eslice_mut(&mut self, start: u32, end: u32) -> EStrMut<'a> {
        // SAFETY: The caller must ensure that the indexes are within bounds.
        let s = unsafe { self.slice_mut(start, end) };
        // SAFETY: The caller must ensure that the subslice is properly encoded.
        unsafe { EStrMut::new(s) }
    }

    /// Returns the mutable scheme component.
    #[inline]
    pub fn scheme_mut(&mut self) -> Option<&'a mut Scheme> {
        // SAFETY: The indexes are within bounds. Scheme is valid UTF-8.
        self.scheme_end
            .map(|i| unsafe { Scheme::new_mut(self.slice_mut(0, i.get() - 1)) })
    }

    /// Takes the mutable authority component out of the `Uri`, leaving a `None` in its place.
    #[inline]
    pub fn take_authority_mut(&mut self) -> Option<AuthorityMut<'_, 'a>> {
        if self.host.is_some() {
            // SAFETY: `host` is `Some`.
            // `AuthorityMut` will set `host` to `None` when it gets dropped.
            Some(unsafe { AuthorityMut::new(self) })
        } else {
            None
        }
    }

    /// Turns into the mutable path component.
    #[inline]
    pub fn into_path_mut(mut self) -> PathMut<'a> {
        // SAFETY: The indexes are within bounds and we have done the validation.
        PathMut::new(unsafe { self.eslice_mut(self.path.0, self.path.1) })
    }

    /// Takes the mutable query component out of the `Uri`, leaving a `None` in its place.
    #[inline]
    pub fn take_query_mut(&mut self) -> Option<EStrMut<'a>> {
        // SAFETY: The indexes are within bounds and we have done the validation.
        self.query_end
            .take()
            .map(|i| unsafe { self.eslice_mut(self.path.1 + 1, i.get()) })
    }

    /// Takes the mutable fragment component out of the `Uri`, leaving a `None` in its place.
    #[inline]
    pub fn take_fragment_mut(&mut self) -> Option<EStrMut<'a>> {
        // SAFETY: The indexes are within bounds and we have done the validation.
        self.fragment_start
            .take()
            .map(|i| unsafe { self.eslice_mut(i.get(), self.len) })
    }
}

impl Uri<String> {
    /// Parses a URI reference from a [`String`] or [`Vec<u8>`] into a `Uri<String>`.
    ///
    /// # Panics
    ///
    /// Panics if the input capacity is greater than `i32::MAX`.
    #[inline]
    pub fn parse_from<B: Buf>(buf: B) -> Result<Uri<String>, (B, SyntaxError)> {
        #[cold]
        fn capacity_overflow() -> ! {
            panic!("input capacity exceeds i32::MAX");
        }

        let me = ManuallyDrop::new(buf);
        let (ptr, len, cap) = me.as_raw_parts();
        if cap > i32::MAX as usize {
            capacity_overflow();
        }

        // SAFETY: We're using the right pointer, length, capacity, and generics.
        match unsafe { parser::parse(ptr, len as u32, cap as u32) } {
            Ok(out) => Ok(out),
            Err(e) => Err((ManuallyDrop::into_inner(me), e)),
        }
    }

    /// Consumes the `Uri` and yields the `String` storage.
    #[inline]
    pub fn into_string(self) -> String {
        // SAFETY: Creating a `String` from the original raw parts is fine.
        unsafe { String::from_raw_parts(self.ptr.as_ptr(), self.len as usize, self.cap as usize) }
    }
}

impl<T> Drop for Uri<T> {
    #[inline]
    fn drop(&mut self) {
        if self.cap != 0 {
            // SAFETY: The capacity is nonzero iff `Self` is `Uri<String>`.
            let _ = unsafe {
                String::from_raw_parts(self.ptr.as_ptr(), self.len as usize, self.cap as usize)
            };
        }
    }
}

/// The [scheme] component of URI reference.
///
/// [scheme]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.1
#[derive(Debug)]
#[repr(transparent)]
pub struct Scheme(str);

const ASCII_CASE_MASK: u8 = 0b010_0000;

impl Scheme {
    #[inline]
    fn new(scheme: &str) -> &Scheme {
        // SAFETY: Transparency holds.
        unsafe { &*(scheme as *const str as *const Scheme) }
    }

    #[inline]
    unsafe fn new_mut(scheme: &mut [u8]) -> &mut Scheme {
        // SAFETY: Transparency holds.
        // The caller must guarantee that the bytes are valid UTF-8.
        unsafe { &mut *(scheme as *mut [u8] as *mut Scheme) }
    }

    /// Returns the scheme as a string slice in the raw form.
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let uri = Uri::parse("Http://Example.Com/")?;
    /// let scheme = uri.scheme().unwrap();
    /// assert_eq!(scheme.as_str(), "Http");
    /// # Ok::<_, fluent_uri::SyntaxError>(())
    /// ```
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the scheme as a string in the lowercase form.
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let uri = Uri::parse("Http://Example.Com/")?;
    /// let scheme = uri.scheme().unwrap();
    /// assert_eq!(scheme.to_lowercase(), "http");
    /// # Ok::<_, fluent_uri::SyntaxError>(())
    /// ```
    #[inline]
    pub fn to_lowercase(&self) -> String {
        let bytes = self.0.bytes().map(|x| x | ASCII_CASE_MASK).collect();
        // SAFETY: Setting the sixth bit keeps UTF-8.
        unsafe { String::from_utf8_unchecked(bytes) }
    }

    /// Converts the scheme to its lowercase equivalent in-place.
    #[inline]
    pub fn make_lowercase(&mut self) -> &str {
        // SAFETY: Setting the sixth bit keeps UTF-8.
        let bytes = unsafe { self.0.as_bytes_mut() };
        for byte in bytes {
            *byte |= ASCII_CASE_MASK;
        }
        &self.0
    }

    /// Checks if the scheme equals case-insensitively with a lowercase string.
    ///
    /// This function is faster than [`str::eq_ignore_ascii_case`] but will
    /// always return `false` if there is any uppercase letter in the given string.
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let uri = Uri::parse("Http://Example.Com/")?;
    /// let scheme = uri.scheme().unwrap();
    /// assert!(scheme.eq_lowercase("http"));
    /// // Always return `false` if there's any uppercase letter in the given string.
    /// assert!(!scheme.eq_lowercase("hTTp"));
    /// # Ok::<_, fluent_uri::SyntaxError>(())
    /// ```
    #[inline]
    pub fn eq_lowercase(&self, other: &str) -> bool {
        // The only characters allowed in a scheme are alphabets, digits, "+", "-" and ".",
        // the ASCII codes of which allow us to simply set the sixth bit and compare.
        self.0.len() == other.len()
            && self
                .0
                .bytes()
                .zip(other.bytes())
                .all(|(a, b)| a | ASCII_CASE_MASK == b)
    }
}

/// The [authority] component of URI reference.
///
/// [authority]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2
#[repr(transparent)]
pub struct Authority<T> {
    uri: Uri<T>,
}

impl<'uri, 'out, T: Storage<'uri, 'out, Output = &'out str>> Authority<T> {
    /// Returns the raw authority component as a string slice.
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let uri = Uri::parse("ftp://user@[fe80::abcd]:6780/")?;
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.as_str(), "user@[fe80::abcd]:6780");
    /// # Ok::<_, fluent_uri::SyntaxError>(())
    /// ```
    #[inline]
    pub fn as_str(&'uri self) -> &'out str {
        // SAFETY: The indexes are within bounds.
        unsafe { self.uri.slice(self.start(), self.uri.path.0) }
    }
}

impl<'uri, 'out, T: Storage<'uri, 'out>> Authority<T> {
    #[inline]
    unsafe fn new(uri: &'uri Uri<T>) -> &'uri Authority<T> {
        // SAFETY: Transparency holds.
        // The caller must guarantee that `host` is `Some`.
        unsafe { &*(uri as *const Uri<T> as *const Authority<T>) }
    }

    #[inline]
    fn start(&self) -> u32 {
        self.uri.scheme_end.map(|x| x.get()).unwrap_or(0) + 2
    }

    #[inline]
    fn host_bounds(&self) -> (u32, u32) {
        // SAFETY: When authority is present, `host` must be `Some`.
        let host = unsafe { self.uri.host.as_ref().unwrap_unchecked() };
        (host.0.get(), host.1)
    }

    #[inline]
    fn host_internal(&self) -> &HostInternal {
        // SAFETY: When authority is present, `host` must be `Some`.
        let host = unsafe { self.uri.host.as_ref().unwrap_unchecked() };
        &host.2
    }

    /// Returns the [userinfo] subcomponent.
    ///
    /// [userinfo]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.1
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let uri = Uri::parse("ftp://user@192.168.1.24/")?;
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.userinfo().unwrap(), "user");
    /// # Ok::<_, fluent_uri::SyntaxError>(())
    /// ```
    #[inline]
    pub fn userinfo(&'uri self) -> Option<&'out EStr> {
        if self.host_internal().tag.contains(HostTag::HAS_USERINFO) {
            let start = self.start();
            let host_start = self.host_bounds().0;
            // SAFETY: The indexes are within bounds and we have done the validation.
            Some(unsafe { self.uri.eslice(start, host_start - 1) })
        } else {
            None
        }
    }

    /// Returns the raw [host] subcomponent as a string slice.
    ///
    /// [host]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.2
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let uri = Uri::parse("ftp://user@[::1]/")?;
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.host_raw(), "[::1]");
    /// # Ok::<_, fluent_uri::SyntaxError>(())
    /// ```
    #[inline]
    pub fn host_raw(&'uri self) -> &'out str {
        let bounds = self.host_bounds();
        // SAFETY: The indexes are within bounds.
        unsafe { self.uri.slice(bounds.0, bounds.1) }
    }

    /// Returns the parsed [host] subcomponent.
    ///
    /// [host]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.2
    pub fn host(&'uri self) -> Host<'out> {
        Host::from_authority(self)
    }

    /// Returns the raw [port] subcomponent as a string slice.
    ///
    /// [port]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.3
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let uri = Uri::parse("ssh://device.local:4673/")?;
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.port_raw(), Some("4673"));
    ///
    /// let uri = Uri::parse("ssh://device.local:/")?;
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.port_raw(), Some(""));
    ///
    /// let uri = Uri::parse("ssh://device.local/")?;
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.port_raw(), None);
    /// # Ok::<_, fluent_uri::SyntaxError>(())
    /// ```
    #[inline]
    pub fn port_raw(&'uri self) -> Option<&'out str> {
        let host_end = self.host_bounds().1;
        // SAFETY: The indexes are within bounds.
        (host_end != self.uri.path.0)
            .then(|| unsafe { self.uri.slice(host_end + 1, self.uri.path.0) })
    }

    /// Parses the [port] subcomponent as `u16`.
    ///
    /// An empty port is interpreted as `None`.
    ///
    /// If the raw port overflows a `u16`, a `Some(Err)` containing the raw port will be returned.
    ///
    /// [port]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.3
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let uri = Uri::parse("ssh://device.local:4673/")?;
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.port(), Some(Ok(4673)));
    ///
    /// let uri = Uri::parse("ssh://device.local:/")?;
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.port(), None);
    ///
    /// let uri = Uri::parse("ssh://device.local/")?;
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.port(), None);
    ///
    /// let uri = Uri::parse("example://device.local:31415926/")?;
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.port(), Some(Err("31415926")));
    /// # Ok::<_, fluent_uri::SyntaxError>(())
    /// ```
    #[inline]
    pub fn port(&'uri self) -> Option<Result<u16, &'out str>> {
        self.port_raw()
            .filter(|s| !s.is_empty())
            .map(|s| s.parse().map_err(|_| s))
    }
}

struct HostInternal {
    tag: HostTag,
    data: HostData,
}

bitflags! {
    struct HostTag: u32 {
        const REG_NAME     = 0b0001;
        const IPV4         = 0b0010;
        const IPV6         = 0b0100;
        const HAS_USERINFO = 0b1000;
    }
}

union HostData {
    ipv4_addr: Ipv4Addr,
    ipv6_addr: Ipv6Addr,
    #[cfg(feature = "ipv_future")]
    ipv_future_dot_i: u32,
    reg_name: (),
}

/// The [host] subcomponent of authority.
///
/// [host]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.2
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Host<'a> {
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
        ver: &'a str,
        /// The address.
        addr: &'a str,
    },
    /// A registered name.
    RegName(&'a EStr),
}

impl<'a> Host<'a> {
    fn from_authority<'uri, T: Storage<'uri, 'a>>(auth: &'uri Authority<T>) -> Host<'a> {
        let HostInternal { tag, ref data } = *auth.host_internal();
        // SAFETY: We only access the union after checking the tag.
        unsafe {
            if tag.contains(HostTag::REG_NAME) {
                return Host::RegName(EStr::new_unchecked(auth.host_raw().as_bytes()));
            } else if tag.contains(HostTag::IPV4) {
                return Host::Ipv4(data.ipv4_addr);
            }
            #[cfg(feature = "ipv_future")]
            if tag.contains(HostTag::IPV6) {
                Host::Ipv6 {
                    addr: data.ipv6_addr,
                }
            } else {
                let dot_i = data.ipv_future_dot_i;
                let bounds = auth.host_bounds();
                // SAFETY: The indexes are within bounds.
                Host::IpvFuture {
                    ver: auth.uri.slice(bounds.0 + 2, dot_i),
                    addr: auth.uri.slice(dot_i + 1, bounds.1 - 1),
                }
            }
            #[cfg(not(feature = "ipv_future"))]
            Host::Ipv6 {
                addr: data.ipv6_addr,
            }
        }
    }
}

/// The [path] component of URI reference.
///
/// [path]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.3
#[derive(Debug)]
#[repr(transparent)]
pub struct Path {
    inner: EStr,
}

impl Path {
    #[inline]
    pub(super) fn new(path: &EStr) -> &Path {
        // SAFETY: Transparency holds.
        unsafe { &*(path as *const EStr as *const Path) }
    }

    /// Returns the path as an `EStr` slice.
    #[inline]
    pub fn as_estr(&self) -> &EStr {
        &self.inner
    }

    /// Returns the path as a string slice.
    #[inline]
    pub fn as_str(&self) -> &str {
        self.inner.as_str()
    }

    /// Returns `true` if the path is absolute, i.e., beginning with "/".
    #[inline]
    pub fn is_absolute(&self) -> bool {
        self.as_str().starts_with('/')
    }

    /// Returns `true` if the path is rootless, i.e., not beginning with "/".
    #[inline]
    pub fn is_rootless(&self) -> bool {
        !self.is_absolute()
    }

    /// Returns an iterator over the [segments] of the path.
    ///
    /// [segments]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.3
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// // An empty path has no segments.
    /// let uri = Uri::parse("")?;
    /// assert_eq!(uri.path().segments().next(), None);
    ///
    /// let uri = Uri::parse("a/b/c")?;
    /// assert!(uri.path().segments().eq(["a", "b", "c"]));
    ///
    /// // The empty string before a preceding "/" is not a segment.
    /// // However, segments can be empty in the other cases.
    /// let uri = Uri::parse("/path/to//dir/")?;
    /// assert!(uri.path().segments().eq(["path", "to", "", "dir", ""]));
    /// # Ok::<_, fluent_uri::SyntaxError>(())
    /// ```
    #[inline]
    pub fn segments(&self) -> Split<'_> {
        let mut path = self.inner.as_str();
        if self.is_absolute() {
            // SAFETY: Skipping "/" is fine.
            path = unsafe { path.get_unchecked(1..) };
        }
        // SAFETY: We have done the validation.
        let path = unsafe { EStr::new_unchecked(path.as_bytes()) };

        let mut split = path.split('/');
        split.finished = self.as_str().is_empty();
        split
    }
}
