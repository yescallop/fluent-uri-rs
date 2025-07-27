//! Module for reference resolution.

use crate::imp::{Meta, Ri, RiMaybeRef, RmrRef};
use alloc::string::String;
use borrow_or_share::Bos;
use core::num::NonZeroUsize;

/// An error occurred when resolving a URI/IRI reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolveError {
    /// The base has a fragment.
    BaseWithFragment,
    /// The base has no authority and its path is rootless, but the reference
    /// is relative, is not empty and does not start with `'#'`.
    InvalidReferenceAgainstOpaqueBase,
    /// An underflow occurred in path resolution.
    PathUnderflow,
}

#[cfg(feature = "impl-error")]
impl crate::Error for ResolveError {}

/// A configurable URI/IRI reference resolver against a fixed base.
///
/// # Examples
///
/// ```
/// use fluent_uri::{resolve::Resolver, Uri, UriRef};
///
/// let base = Uri::parse("http://example.com/foo/bar")?;
/// let resolver = Resolver::with_base(base);
///
/// assert_eq!(resolver.resolve(&UriRef::parse("baz")?).unwrap(), "http://example.com/foo/baz");
/// assert_eq!(resolver.resolve(&UriRef::parse("../baz")?).unwrap(), "http://example.com/baz");
/// assert_eq!(resolver.resolve(&UriRef::parse("?baz")?).unwrap(), "http://example.com/foo/bar?baz");
/// # Ok::<_, fluent_uri::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug)]
#[must_use]
pub struct Resolver<R> {
    base: R,
    allow_path_underflow: bool,
}

impl<R: Ri> Resolver<R>
where
    R::Val: Bos<str>,
{
    /// Creates a new `Resolver` with the given base.
    pub fn with_base(base: R) -> Self {
        Self {
            base,
            allow_path_underflow: true,
        }
    }

    /// Sets whether to allow underflow in path resolution.
    ///
    /// This defaults to `true`. A value of `false` is a deviation from the
    /// reference resolution algorithm defined in
    /// [Section 5 of RFC 3986](https://datatracker.ietf.org/doc/html/rfc3986/#section-5).
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::{resolve::{Resolver, ResolveError}, Uri, UriRef};
    ///
    /// let base = Uri::parse("http://example.com/foo/bar")?;
    /// let resolver = Resolver::with_base(base).allow_path_underflow(false);
    ///
    /// assert_eq!(resolver.resolve(&UriRef::parse("../../baz")?).unwrap_err(), ResolveError::PathUnderflow);
    /// assert_eq!(resolver.resolve(&UriRef::parse("../../../baz")?).unwrap_err(), ResolveError::PathUnderflow);
    /// assert_eq!(resolver.resolve(&UriRef::parse("/../baz")?).unwrap_err(), ResolveError::PathUnderflow);
    /// # Ok::<_, fluent_uri::ParseError>(())
    /// ```
    pub fn allow_path_underflow(mut self, value: bool) -> Self {
        self.allow_path_underflow = value;
        self
    }

    /// Resolves the given reference against the configured base.
    ///
    /// See [`resolve_against`] for the exact behavior of this method.
    ///
    /// # Errors
    ///
    /// Returns `Err` on the same conditions as [`resolve_against`] or if an underflow
    /// occurred in path resolution when [`allow_path_underflow`] is set to `false`.
    ///
    /// [`resolve_against`]: crate::UriRef::resolve_against
    /// [`allow_path_underflow`]: Self::allow_path_underflow
    pub fn resolve<T: Bos<str>>(
        &self,
        reference: &R::Ref<T>,
    ) -> Result<R::WithVal<String>, ResolveError> {
        resolve(
            self.base.make_ref(),
            reference.make_ref(),
            self.allow_path_underflow,
        )
        .map(RiMaybeRef::from_pair)
    }
}

pub(crate) fn resolve(
    base: RmrRef<'_, '_>,
    /* reference */ r: RmrRef<'_, '_>,
    allow_path_underflow: bool,
) -> Result<(String, Meta), ResolveError> {
    assert!(base.has_scheme());

    if base.has_fragment() {
        return Err(ResolveError::BaseWithFragment);
    }
    if !base.has_authority()
        && base.path().is_rootless()
        && !r.has_scheme()
        && !matches!(r.as_str().bytes().next(), None | Some(b'#'))
    {
        return Err(ResolveError::InvalidReferenceAgainstOpaqueBase);
    }

    let (t_scheme, t_authority, t_path, t_query, t_fragment);
    let mut buf = String::new();

    let r_scheme = r.scheme_opt();
    let r_authority = r.authority();
    let r_path = r.path();
    let r_query = r.query();
    let r_fragment = r.fragment();

    if let Some(r_scheme) = r_scheme {
        t_scheme = r_scheme;
        t_authority = r_authority;
        t_path = if r_path.is_absolute() {
            buf.reserve_exact(r_path.len());
            remove_dot_segments(&mut buf, r_path.as_str(), allow_path_underflow)?
        } else {
            r_path.as_str()
        };
        t_query = r_query;
    } else {
        if r_authority.is_some() {
            t_authority = r_authority;
            buf.reserve_exact(r_path.len());
            t_path = remove_dot_segments(&mut buf, r_path.as_str(), allow_path_underflow)?;
            t_query = r_query;
        } else {
            if r_path.is_empty() {
                let base_path = base.path();
                t_path = if base_path.is_absolute() {
                    buf.reserve_exact(base_path.len());
                    remove_dot_segments(&mut buf, base_path.as_str(), allow_path_underflow)?
                } else {
                    base_path.as_str()
                };
                if r_query.is_some() {
                    t_query = r_query;
                } else {
                    t_query = base.query();
                }
            } else {
                if r_path.is_absolute() {
                    buf.reserve_exact(r_path.len());
                    t_path = remove_dot_segments(&mut buf, r_path.as_str(), allow_path_underflow)?;
                } else {
                    // Instead of merging the paths, remove dot segments incrementally.
                    let base_path = base.path().as_str();
                    if base_path.is_empty() {
                        buf.reserve_exact(r_path.len() + 1);
                        buf.push('/');
                    } else {
                        // Make sure that swapping the order of resolution and normalization
                        // does not change the result.
                        let last_slash_i = base_path.rfind('/').unwrap();
                        let last_seg = &base_path[last_slash_i + 1..];
                        let base_path_stripped = match classify_segment(last_seg) {
                            SegKind::DoubleDot => base_path,
                            _ => &base_path[..=last_slash_i],
                        };

                        buf.reserve_exact(base_path_stripped.len() + r_path.len());
                        remove_dot_segments(&mut buf, base_path_stripped, allow_path_underflow)?;
                    }
                    t_path = remove_dot_segments(&mut buf, r_path.as_str(), allow_path_underflow)?;
                }
                t_query = r_query;
            }
            t_authority = base.authority();
        }
        t_scheme = base.scheme();
    }
    t_fragment = r_fragment;

    // Calculate the output length.
    let mut len = t_scheme.as_str().len() + 1;
    if let Some(authority) = t_authority {
        len += authority.as_str().len() + 2;
    }
    if t_authority.is_none() && t_path.starts_with("//") {
        len += 2;
    }
    len += t_path.len();
    if let Some(query) = t_query {
        len += query.len() + 1;
    }
    if let Some(fragment) = t_fragment {
        len += fragment.len() + 1;
    }

    let mut buf = String::with_capacity(len);
    let mut meta = Meta::default();

    buf.push_str(t_scheme.as_str());
    meta.scheme_end = NonZeroUsize::new(buf.len());
    buf.push(':');

    if let Some(authority) = t_authority {
        let mut auth_meta = authority.meta();
        buf.push_str("//");

        auth_meta.host_bounds.0 += buf.len();
        auth_meta.host_bounds.1 += buf.len();

        buf.push_str(authority.as_str());
        meta.auth_meta = Some(auth_meta);
    }

    meta.path_bounds.0 = buf.len();
    // Close the loophole in the original algorithm.
    if t_authority.is_none() && t_path.starts_with("//") {
        buf.push_str("/.");
    }
    buf.push_str(t_path);
    meta.path_bounds.1 = buf.len();

    if let Some(query) = t_query {
        buf.push('?');
        buf.push_str(query.as_str());
        meta.query_end = NonZeroUsize::new(buf.len());
    }

    if let Some(fragment) = t_fragment {
        buf.push('#');
        buf.push_str(fragment.as_str());
    }

    debug_assert_eq!(buf.len(), len);

    Ok((buf, meta))
}

pub(crate) fn remove_dot_segments<'a>(
    buf: &'a mut String,
    path: &str,
    allow_path_underflow: bool,
) -> Result<&'a str, ResolveError> {
    for seg in path.split_inclusive('/') {
        let seg_stripped = seg.strip_suffix('/').unwrap_or(seg);
        match classify_segment(seg_stripped) {
            SegKind::Dot => buf.truncate(buf.rfind('/').unwrap() + 1),
            SegKind::DoubleDot => {
                if buf.len() != 1 {
                    buf.truncate(buf.rfind('/').unwrap());
                    buf.truncate(buf.rfind('/').unwrap() + 1);
                } else if !allow_path_underflow {
                    return Err(ResolveError::PathUnderflow);
                }
            }
            SegKind::Normal => buf.push_str(seg),
        }
    }
    Ok(buf)
}

enum SegKind {
    Dot,
    DoubleDot,
    Normal,
}

fn classify_segment(mut seg: &str) -> SegKind {
    if seg.is_empty() {
        return SegKind::Normal;
    }
    if let Some(rem) = seg.strip_prefix('.') {
        seg = rem;
    } else if let Some(rem) = seg.strip_prefix("%2E") {
        seg = rem;
    } else if let Some(rem) = seg.strip_prefix("%2e") {
        seg = rem;
    }
    if seg.is_empty() {
        SegKind::Dot
    } else if seg == "." || seg == "%2E" || seg == "%2e" {
        SegKind::DoubleDot
    } else {
        SegKind::Normal
    }
}
