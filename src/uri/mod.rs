mod fmt;

pub mod mutable;
use mutable::*;

mod parser;

use crate::encoding::{internal::Buf, EStr, EStrMut, Split};
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
    pub trait Storage {
        fn needs_drop() -> bool;
        fn is_mut() -> bool;
    }

    impl Storage for &str {
        #[inline]
        fn needs_drop() -> bool {
            false
        }

        #[inline]
        fn is_mut() -> bool {
            false
        }
    }

    impl Storage for &mut [u8] {
        #[inline]
        fn needs_drop() -> bool {
            false
        }

        #[inline]
        fn is_mut() -> bool {
            true
        }
    }

    impl Storage for String {
        #[inline]
        fn needs_drop() -> bool {
            true
        }

        #[inline]
        fn is_mut() -> bool {
            false
        }
    }

    pub trait Io<'i, 'o>: Storage {}

    impl<'i, 'a> Io<'i, 'a> for &'a str {}

    impl<'i, 'a> Io<'i, 'a> for &'a mut [u8] {}

    impl<'a> Io<'a, 'a> for String {}

    pub trait IntoOwnedUri {
        fn as_raw_parts(&self) -> (*mut u8, usize, usize);
    }

    impl IntoOwnedUri for String {
        #[inline]
        fn as_raw_parts(&self) -> (*mut u8, usize, usize) {
            (self.as_ptr() as _, self.len(), self.capacity())
        }
    }

    impl IntoOwnedUri for Vec<u8> {
        #[inline]
        fn as_raw_parts(&self) -> (*mut u8, usize, usize) {
            (self.as_ptr() as _, self.len(), self.capacity())
        }
    }
}

use internal::*;

/// Detailed cause of a [`UriParseError`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UriParseErrorKind {
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

/// An error occurred when parsing URI references.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UriParseError {
    index: u32,
    kind: UriParseErrorKind,
}

impl UriParseError {
    /// Returns the index where the error occurred in the input string.
    #[inline]
    pub fn index(&self) -> usize {
        self.index as usize
    }

    /// Returns the detailed cause of the error.
    #[inline]
    pub fn kind(&self) -> UriParseErrorKind {
        self.kind
    }
}

impl std::error::Error for UriParseError {}

pub(super) type Result<T, E = UriParseError> = std::result::Result<T, E>;

#[cold]
fn len_overflow() -> ! {
    panic!("input length exceeds i32::MAX");
}

/// A URI reference defined in [RFC 3986].
///
/// [RFC 3986]: https://datatracker.ietf.org/doc/html/rfc3986/
///
/// # Variants
///
/// There are three variants of `Uri` in total:
///
/// - `Uri<&str>`: borrowed; immutable.
/// - `Uri<&mut [u8]>`: borrowed; in-place mutable.
/// - `Uri<String>`: owned; immutable.
///
/// Lifetimes are correctly handled in a way that `Uri<&'a str>` and `Uri<&'a mut [u8]>` both
/// output references with lifetime `'a`. This allows you to drop a temporary `Uri` while keeping
/// the output references.
///
/// ```
/// use fluent_uri::Uri;
///
/// let uri = Uri::parse("foo:bar").expect("invalid URI reference");
/// let path = uri.path();
/// drop(uri);
/// assert_eq!(path.as_str(), "bar");
/// ```
///
/// # Examples
///
/// Create and convert between `Uri<&str>` and `Uri<String>`.
///   
/// ```
/// use fluent_uri::Uri;
///
/// // Create a `Uri<&str>`.
/// let uri_a: Uri<&str> = Uri::parse("").expect("invalid URI reference");
///
/// // Create a `Uri<String>`.
/// let uri_b: Uri<String> = Uri::parse_from(String::new()).expect("invalid URI reference");
///
/// // Convert a `Uri<&str>` to a `Uri<String>`.
/// let uri_c: Uri<String> = uri_a.to_owned();
///
/// // Borrow a `Uri<String>` as a `Uri<&str>`.
/// let uri_d: &Uri<&str> = uri_b.borrow();
/// ```
///
/// Decode path segments in-place and collect them into a `Vec`.
///
/// ```
/// use fluent_uri::Uri;
///
/// fn decode_path_segments(uri: &mut [u8]) -> Option<Vec<&str>> {
///     let mut uri = Uri::parse_mut(uri).ok()?;
///     let segs = uri.take_path_mut().segments_mut();
///     let mut out = Vec::new();
///     for seg in segs {
///         out.push(seg.decode_in_place().into_str().ok()?);
///     }
///     Some(out)
/// }
///   
/// let mut uri = b"/path/to/my%20music".to_vec();
/// assert_eq!(decode_path_segments(&mut uri).unwrap(), ["path", "to", "my music"]);
/// ```
///
/// Create a mutable copy of an immutable `Uri` in a buffer.
///
/// ```
/// use fluent_uri::Uri;
/// use std::mem::MaybeUninit;
///
/// let uri = Uri::parse("https://www.rust-lang.org/").expect("invalid URI reference");
/// let mut buf = [MaybeUninit::uninit(); 256];
/// let uri_mut = uri
///     .to_mut_in(&mut buf[..])
///     .expect("buffer capacity overflow");
/// ```
#[repr(C)]
pub struct Uri<T: Storage> {
    ptr: NonNull<u8>,
    cap: u32,
    len: u32,
    tag: Tag,
    // One byte past the trailing ':'.
    // This encoding is chosen so that no extra branch is introduced
    // when indexing the start of the authority.
    scheme_end: Option<NonZeroU32>,
    host: Option<(NonZeroU32, u32, HostData)>,
    path: (u32, u32),
    // One byte past the last byte of query.
    query_end: Option<NonZeroU32>,
    // One byte past the preceding '#'.
    fragment_start: Option<NonZeroU32>,
    _marker: PhantomData<T>,
}

impl<'a> Uri<&'a str> {
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
    /// Panics if the input length is greater than [`i32::MAX`].
    pub fn parse<S: AsRef<[u8]> + ?Sized>(s: &S) -> Result<Uri<&str>> {
        let bytes = s.as_ref();
        if bytes.len() > i32::MAX as usize {
            len_overflow();
        }
        // SAFETY: We're using the right pointer, length, capacity, and generics.
        unsafe { parser::parse(bytes.as_ptr() as *mut _, bytes.len() as u32, 0) }
    }

    /// Duplicates this `Uri<&str>`.
    #[inline]
    pub fn dup(&self) -> Uri<&'a str> {
        Uri { ..*self }
    }

    /// Creates a new `Uri<String>` by cloning the contents of this `Uri<&str>`.
    #[inline]
    pub fn to_owned(&self) -> Uri<String> {
        // We're allocating manually because there is no guarantee that
        // `String::to_owned` gives the exact capacity of `self.len`.
        let mut vec = ManuallyDrop::new(Vec::with_capacity(self.len as usize));
        let ptr = vec.as_mut_ptr();

        // SAFETY: The capacity of `vec` is exactly `self.len`.
        // Newly allocated `Vec` won't overlap with existing data.
        unsafe {
            self.ptr
                .as_ptr()
                .copy_to_nonoverlapping(ptr, self.len as usize);
        }

        Uri {
            ptr: NonNull::new(ptr).unwrap(),
            cap: self.len,
            len: self.len,
            tag: self.tag,
            scheme_end: self.scheme_end,
            host: self.host,
            path: self.path,
            query_end: self.query_end,
            fragment_start: self.fragment_start,
            _marker: PhantomData,
        }
    }
}

impl<'i, 'o, T: Io<'i, 'o> + AsRef<str>> Uri<T> {
    #[inline]
    /// Returns the URI reference as a string slice.
    pub fn as_str(&'i self) -> &'o str {
        // SAFETY: The indexes are within bounds.
        unsafe { self.slice(0, self.len) }
    }

    /// Creates a mutable copy of this `Uri` in the given buffer.
    ///
    /// The type of a buffer may be:
    ///
    /// - [`Vec<u8>`]: bytes appended to the end; triggers a [`TryReserveError`]
    ///   when the allocation fails.
    ///
    /// - [`[u8]`](prim@slice) or [`[MaybeUninit<u8>]`](prim@slice): bytes
    ///   written from the start; triggers a [`BufferTooSmallError`] when
    ///   the buffer is too small.
    ///
    /// [`TryReserveError`]: std::collections::TryReserveError
    /// [`BufferTooSmallError`]: crate::encoding::BufferTooSmallError
    #[inline]
    pub fn to_mut_in<'b, B: Buf + ?Sized>(
        &self,
        buf: &'b mut B,
    ) -> Result<Uri<&'b mut [u8]>, B::PrepareError> {
        let ptr = buf.prepare(self.len as usize)?;

        // SAFETY: We have reserved enough space in the buffer, and
        // mutable reference `buf` ensures exclusive access.
        unsafe {
            self.ptr
                .as_ptr()
                .copy_to_nonoverlapping(ptr, self.len as usize);
            buf.finish(self.len as usize);
        }

        Ok(Uri {
            ptr: NonNull::new(ptr).unwrap(),
            cap: 0,
            len: self.len,
            tag: self.tag,
            scheme_end: self.scheme_end,
            host: self.host,
            path: self.path,
            query_end: self.query_end,
            fragment_start: self.fragment_start,
            _marker: PhantomData,
        })
    }
}

#[cold]
fn component_taken() -> ! {
    panic!("component already taken");
}

impl<'i, 'o, T: Io<'i, 'o>> Uri<T> {
    #[inline]
    unsafe fn slice(&'i self, start: u32, end: u32) -> &'o str {
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
    unsafe fn eslice(&'i self, start: u32, end: u32) -> &'o EStr {
        // SAFETY: The caller must ensure that the indexes are within bounds.
        let s = unsafe { self.slice(start, end) };
        // SAFETY: The caller must ensure that the subslice is properly encoded.
        unsafe { EStr::new_unchecked(s.as_bytes()) }
    }

    /// Returns the [scheme] component.
    ///
    /// [scheme]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.1
    #[inline]
    pub fn scheme(&'i self) -> Option<&'o Scheme> {
        // SAFETY: The indexes are within bounds.
        self.scheme_end
            .map(|i| Scheme::new(unsafe { self.slice(0, i.get() - 1) }))
    }

    /// Returns the [authority] component.
    ///
    /// [authority]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2
    #[inline]
    pub fn authority(&self) -> Option<&Authority<T>> {
        if self.host.is_some() {
            // SAFETY: `host` is `Some`.
            Some(unsafe { Authority::new(self) })
        } else {
            None
        }
    }

    #[inline]
    fn path_opt(&'i self) -> Option<&'o Path> {
        if T::is_mut() && self.tag.contains(Tag::PATH_TAKEN) {
            None
        } else {
            // SAFETY: The indexes are within bounds and we have done the validation.
            Some(Path::new(unsafe { self.eslice(self.path.0, self.path.1) }))
        }
    }

    /// Returns the [path] component.
    ///
    /// [path]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.3
    ///
    /// # Panics
    ///
    /// Panics if the path component is already taken.
    #[inline]
    pub fn path(&'i self) -> &'o Path {
        match self.path_opt() {
            Some(path) => path,
            None => component_taken(),
        }
    }

    /// Returns the [query] component.
    ///
    /// [query]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.4
    #[inline]
    pub fn query(&'i self) -> Option<&'o EStr> {
        // SAFETY: The indexes are within bounds and we have done the validation.
        self.query_end
            .map(|i| unsafe { self.eslice(self.path.1 + 1, i.get()) })
    }

    /// Returns the [fragment] component.
    ///
    /// [fragment]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.5
    #[inline]
    pub fn fragment(&'i self) -> Option<&'o EStr> {
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
    /// # Ok::<_, fluent_uri::UriParseError>(())
    /// ```
    #[inline]
    pub fn is_relative(&self) -> bool {
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
    /// # Ok::<_, fluent_uri::UriParseError>(())
    /// ```
    #[inline]
    pub fn is_absolute(&self) -> bool {
        self.scheme_end.is_some() && self.fragment_start.is_none()
    }
}

impl<'a> Uri<&'a mut [u8]> {
    /// Parses a URI reference from a mutable byte sequence into a `Uri<&mut [u8]>`.
    ///
    /// # Panics
    ///
    /// Panics if the input length is greater than [`i32::MAX`].
    #[inline]
    pub fn parse_mut<S: AsMut<[u8]> + ?Sized>(s: &mut S) -> Result<Uri<&mut [u8]>> {
        let bytes = s.as_mut();
        if bytes.len() > i32::MAX as usize {
            len_overflow();
        }
        // SAFETY: We're using the right pointer, length, capacity, and generics.
        unsafe { parser::parse(bytes.as_mut_ptr(), bytes.len() as u32, 0) }
    }

    /// Consumes this `Uri` and yields the underlying mutable byte slice.
    #[inline]
    pub fn into_mut_bytes(mut self) -> &'a mut [u8] {
        // SAFETY: The indexes are within bounds.
        unsafe { self.slice_mut(0, self.len) }
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

    /// Takes the mutable authority component, leaving a `None` in its place.
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

    /// Takes the mutable path component.
    ///
    /// # Panics
    ///
    /// Panics if the path component is already taken.
    #[inline]
    pub fn take_path_mut(&mut self) -> PathMut<'a> {
        if self.tag.contains(Tag::PATH_TAKEN) {
            component_taken();
        }
        self.tag |= Tag::PATH_TAKEN;

        // SAFETY: The indexes are within bounds and we have done the validation.
        PathMut::new(unsafe { self.eslice_mut(self.path.0, self.path.1) })
    }

    /// Takes the mutable query component, leaving a `None` in its place.
    #[inline]
    pub fn take_query_mut(&mut self) -> Option<EStrMut<'a>> {
        // SAFETY: The indexes are within bounds and we have done the validation.
        self.query_end
            .take()
            .map(|i| unsafe { self.eslice_mut(self.path.1 + 1, i.get()) })
    }

    /// Takes the mutable fragment component, leaving a `None` in its place.
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
    /// Panics if the input capacity is greater than [`i32::MAX`].
    #[inline]
    pub fn parse_from<T: IntoOwnedUri>(t: T) -> Result<Uri<String>, (T, UriParseError)> {
        #[cold]
        fn cap_overflow() -> ! {
            panic!("input capacity exceeds i32::MAX");
        }

        let buf = ManuallyDrop::new(t);
        let (ptr, len, cap) = buf.as_raw_parts();
        if cap > i32::MAX as usize {
            cap_overflow();
        }

        // SAFETY: We're using the right pointer, length, capacity, and generics.
        match unsafe { parser::parse(ptr, len as u32, cap as u32) } {
            Ok(out) => Ok(out),
            Err(e) => Err((ManuallyDrop::into_inner(buf), e)),
        }
    }

    /// Consumes this `Uri` and yields the underlying [`String`] storage.
    #[inline]
    pub fn into_string(self) -> String {
        // SAFETY: Creating a `String` from the original raw parts is fine.
        unsafe { String::from_raw_parts(self.ptr.as_ptr(), self.len as usize, self.cap as usize) }
    }

    /// Borrows this `Uri<String>` as a reference to `Uri<&str>`.
    #[inline]
    // We can't impl `Borrow` due to the limitation of lifetimes.
    #[allow(clippy::should_implement_trait)]
    pub fn borrow(&self) -> &Uri<&str> {
        // SAFETY: `Uri` has a fixed layout, `Uri<&str>` with a capacity is
        // always fine and the lifetimes are correct.
        unsafe { &*(self as *const Uri<String> as *const Uri<&str>) }
    }
}

impl Clone for Uri<String> {
    #[inline]
    fn clone(&self) -> Self {
        self.borrow().to_owned()
    }
}

// SAFETY: `&str`, `&mut [u8]` and `String` are all Send and Sync.
unsafe impl<T: Storage> Send for Uri<T> {}
unsafe impl<T: Storage> Sync for Uri<T> {}

impl<T: Storage> Drop for Uri<T> {
    #[inline]
    fn drop(&mut self) {
        // Can't use `mem::needs_drop` here because there's no guarantee of its return value.
        if T::needs_drop() {
            // SAFETY: `T::needs_drop()` returns true iff `T` is `String`.
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
    /// # Ok::<_, fluent_uri::UriParseError>(())
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
    /// # Ok::<_, fluent_uri::UriParseError>(())
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
    /// # Ok::<_, fluent_uri::UriParseError>(())
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
pub struct Authority<T: Storage> {
    uri: Uri<T>,
}

impl<'i, 'o, T: Io<'i, 'o> + AsRef<str>> Authority<T> {
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
    /// # Ok::<_, fluent_uri::UriParseError>(())
    /// ```
    #[inline]
    pub fn as_str(&'i self) -> &'o str {
        // SAFETY: The indexes are within bounds.
        unsafe { self.uri.slice(self.start(), self.uri.path.0) }
    }
}

impl<'i, 'o, T: Io<'i, 'o>> Authority<T> {
    #[inline]
    unsafe fn new(uri: &Uri<T>) -> &Authority<T> {
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
    fn host_data(&self) -> &HostData {
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
    /// # Ok::<_, fluent_uri::UriParseError>(())
    /// ```
    #[inline]
    pub fn userinfo(&'i self) -> Option<&'o EStr> {
        if self.uri.tag.contains(Tag::HAS_USERINFO) {
            let start = self.start();
            let host_start = self.host_bounds().0;
            // SAFETY: The indexes are within bounds and we have done the validation.
            Some(unsafe { self.uri.eslice(start, host_start - 1) })
        } else {
            None
        }
    }

    #[inline]
    fn host_raw_opt(&'i self) -> Option<&'o str> {
        if T::is_mut() && self.uri.tag.contains(Tag::HOST_TAKEN) {
            None
        } else {
            let bounds = self.host_bounds();
            // SAFETY: The indexes are within bounds.
            Some(unsafe { self.uri.slice(bounds.0, bounds.1) })
        }
    }

    /// Returns the raw [host] subcomponent as a string slice.
    ///
    /// [host]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.2
    ///
    /// # Panics
    ///
    /// Panics if the host subcomponent is already taken.
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// let uri = Uri::parse("ftp://user@[::1]/")?;
    /// let authority = uri.authority().unwrap();
    /// assert_eq!(authority.host_raw(), "[::1]");
    /// # Ok::<_, fluent_uri::UriParseError>(())
    /// ```
    #[inline]
    pub fn host_raw(&'i self) -> &'o str {
        match self.host_raw_opt() {
            Some(host) => host,
            None => component_taken(),
        }
    }

    /// Returns the parsed [host] subcomponent.
    ///
    /// [host]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.2
    ///
    /// # Panics
    ///
    /// Panics if the host subcomponent is already taken.
    pub fn host(&'i self) -> Host<'o> {
        if T::is_mut() && self.uri.tag.contains(Tag::HOST_TAKEN) {
            component_taken();
        }
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
    /// # Ok::<_, fluent_uri::UriParseError>(())
    /// ```
    #[inline]
    pub fn port_raw(&'i self) -> Option<&'o str> {
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
    /// # Ok::<_, fluent_uri::UriParseError>(())
    /// ```
    #[inline]
    pub fn port(&'i self) -> Option<Result<u16, &'o str>> {
        self.port_raw()
            .filter(|s| !s.is_empty())
            .map(|s| s.parse().map_err(|_| s))
    }
}

bitflags! {
    struct Tag: u32 {
        const HOST_REG_NAME = 0b000001;
        const HOST_IPV4 = 0b000010;
        const HOST_IPV6 = 0b000100;
        const HAS_USERINFO = 0b001000;
        const PATH_TAKEN = 0b010000;
        const HOST_TAKEN = 0b100000;
    }
}

#[derive(Clone, Copy)]
union HostData {
    ipv4_addr: Ipv4Addr,
    ipv6: Ipv6Data,
    #[cfg(feature = "ipv_future")]
    ipv_future_dot_i: u32,
    reg_name: (),
}

#[derive(Clone, Copy)]
struct Ipv6Data {
    addr: Ipv6Addr,
    #[cfg(feature = "rfc6874bis")]
    zone_id_start: Option<NonZeroU32>,
}

/// The [host] subcomponent of authority.
///
/// [host]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.2
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Host<'a> {
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
        zone_id: Option<&'a str>,
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
    fn from_authority<'i, T: Io<'i, 'a>>(auth: &'i Authority<T>) -> Host<'a> {
        let tag = auth.uri.tag;
        let data = auth.host_data();
        // SAFETY: We only access the union after checking the tag.
        unsafe {
            if tag.contains(Tag::HOST_REG_NAME) {
                return Host::RegName(EStr::new_unchecked(auth.host_raw().as_bytes()));
            } else if tag.contains(Tag::HOST_IPV4) {
                return Host::Ipv4(data.ipv4_addr);
            }
            #[cfg(feature = "ipv_future")]
            if !tag.contains(Tag::HOST_IPV6) {
                let dot_i = data.ipv_future_dot_i;
                let bounds = auth.host_bounds();
                // SAFETY: The indexes are within bounds.
                return Host::IpvFuture {
                    ver: auth.uri.slice(bounds.0 + 2, dot_i),
                    addr: auth.uri.slice(dot_i + 1, bounds.1 - 1),
                };
            }
            Host::Ipv6 {
                addr: data.ipv6.addr,
                #[cfg(feature = "rfc6874bis")]
                zone_id: data
                    .ipv6
                    .zone_id_start
                    .map(|start| auth.uri.slice(start.get(), auth.host_bounds().1 - 1)),
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

    /// Yields the underlying [`EStr`].
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
    /// # Ok::<_, fluent_uri::UriParseError>(())
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
