use crate::{
    error::{ResolveError, ResolveErrorKind},
    internal::Meta,
    Uri,
};
use alloc::string::String;
use borrow_or_share::Bos;
use core::num::NonZeroUsize;

/// A configurable URI reference resolver against a fixed base URI.
///
/// # Examples
///
/// ```
/// use fluent_uri::{Resolver, Uri};
///
/// let base = Uri::parse("http://example.com/foo/bar")?;
/// let resolver = Resolver::with_base(base);
///
/// assert_eq!(resolver.resolve(&Uri::parse("baz")?)?, "http://example.com/foo/baz");
/// assert_eq!(resolver.resolve(&Uri::parse("../baz")?)?, "http://example.com/baz");
/// assert_eq!(resolver.resolve(&Uri::parse("?baz")?)?, "http://example.com/foo/bar?baz");
/// # Ok::<_, Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Copy, Debug)]
#[must_use]
pub struct Resolver<T: Bos<str>> {
    base: Uri<T>,
    no_path_underflow: bool,
}

impl<T: Bos<str>> Resolver<T> {
    /// Creates a new `Resolver` with the given base URI.
    pub fn with_base(base: Uri<T>) -> Self {
        Self {
            base,
            no_path_underflow: false,
        }
    }

    /// Makes reference resolution fail if an underflow occurs in path resolution.
    ///
    /// Note that this is a deviation from the reference resolution algorithm defined in
    /// [Section 5 of RFC 3986](https://datatracker.ietf.org/doc/html/rfc3986/#section-5).
    ///
    /// You can check whether an underflow occurred by calling [`ResolveError::is_path_underflow`].
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::{Resolver, Uri};
    ///
    /// let base = Uri::parse("http://example.com/foo/bar")?;
    /// let resolver = Resolver::with_base(base).no_path_underflow();
    ///
    /// assert!(resolver.resolve(&Uri::parse("../../baz")?).unwrap_err().is_path_underflow());
    /// assert!(resolver.resolve(&Uri::parse("../../../baz")?).unwrap_err().is_path_underflow());
    /// assert!(resolver.resolve(&Uri::parse("/../baz")?).unwrap_err().is_path_underflow());
    /// # Ok::<_, fluent_uri::error::ParseError>(())
    /// ```
    pub fn no_path_underflow(mut self) -> Self {
        self.no_path_underflow = true;
        self
    }

    /// Resolves the given URI reference against the configured base URI.
    ///
    /// See [`Uri::resolve_against`] for the exact behavior of this method.
    pub fn resolve<U: Bos<str>>(&self, reference: &Uri<U>) -> Result<Uri<String>, ResolveError> {
        resolve(
            self.base.as_ref(),
            reference.as_ref(),
            self.no_path_underflow,
        )
    }
}

pub(crate) fn resolve(
    base: Uri<&str>,
    /* reference */ r: Uri<&str>,
    no_path_underflow: bool,
) -> Result<Uri<String>, ResolveError> {
    if !base.is_absolute_uri() {
        return Err(ResolveError(ResolveErrorKind::NonAbsoluteBase));
    }
    if !base.has_authority()
        && base.path().is_rootless()
        && !r.has_scheme()
        && !matches!(r.as_str().bytes().next(), None | Some(b'#'))
    {
        return Err(ResolveError(ResolveErrorKind::NonHierarchicalBase));
    }

    let (t_scheme, t_authority, t_path, t_query, t_fragment);
    let mut buf = String::new();

    let (r_scheme, r_authority, r_path, r_query, r_fragment) =
        (r.scheme(), r.authority(), r.path(), r.query(), r.fragment());

    if let Some(r_scheme) = r_scheme {
        t_scheme = r_scheme;
        t_authority = r_authority;
        t_path = if r_path.is_absolute() {
            buf.reserve_exact(r_path.len());
            remove_dot_segments(&mut buf, r_path.as_str(), no_path_underflow)?
        } else {
            r_path.as_str()
        };
        t_query = r_query;
    } else {
        if r_authority.is_some() {
            t_authority = r_authority;
            buf.reserve_exact(r_path.len());
            t_path = remove_dot_segments(&mut buf, r_path.as_str(), no_path_underflow)?;
            t_query = r_query;
        } else {
            if r_path.is_empty() {
                t_path = base.path().as_str();
                if r_query.is_some() {
                    t_query = r_query;
                } else {
                    t_query = base.query();
                }
            } else {
                if r_path.is_absolute() {
                    buf.reserve_exact(r_path.len());
                    t_path = remove_dot_segments(&mut buf, r_path.as_str(), no_path_underflow)?;
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
                        remove_dot_segments(&mut buf, base_path_stripped, no_path_underflow)?;
                    }
                    t_path = remove_dot_segments(&mut buf, r_path.as_str(), no_path_underflow)?;
                }
                t_query = r_query;
            }
            t_authority = base.authority();
        }
        t_scheme = base.scheme().unwrap();
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

    Ok(Uri { val: buf, meta })
}

pub(crate) fn remove_dot_segments<'a>(
    buf: &'a mut String,
    path: &str,
    no_underflow: bool,
) -> Result<&'a str, ResolveError> {
    for seg in path.split_inclusive('/') {
        let seg_stripped = seg.strip_suffix('/').unwrap_or(seg);
        match classify_segment(seg_stripped) {
            SegKind::Dot => buf.truncate(buf.rfind('/').unwrap() + 1),
            SegKind::DoubleDot => {
                if buf.len() != 1 {
                    buf.truncate(buf.rfind('/').unwrap());
                    buf.truncate(buf.rfind('/').unwrap() + 1);
                } else if no_underflow {
                    return Err(ResolveError(ResolveErrorKind::PathUnderflow));
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
