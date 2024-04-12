use crate::{
    error::{ResolveError, ResolveErrorKind},
    internal::Meta,
    Uri,
};
use alloc::string::String;
use core::num::NonZeroU32;

pub(crate) fn resolve(
    base: Uri<&str>,
    /* reference */ r: Uri<&str>,
) -> Result<Uri<String>, ResolveError> {
    if !base.is_absolute_uri() {
        return Err(ResolveError(ResolveErrorKind::NonAbsoluteBase));
    }
    if base.auth_meta.is_none()
        && base.path().is_rootless()
        && r.scheme_end.is_none()
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
            remove_dot_segments(&mut buf, r_path.as_str())
        } else {
            r_path.as_str()
        };
        t_query = r_query;
    } else {
        if r_authority.is_some() {
            t_authority = r_authority;
            buf.reserve_exact(r_path.len());
            t_path = remove_dot_segments(&mut buf, r_path.as_str());
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
                    t_path = remove_dot_segments(&mut buf, r_path.as_str());
                } else {
                    // Instead of merging the paths, remove dot segments incrementally.
                    let base_path = base.path().as_str();
                    if base_path.is_empty() {
                        buf.reserve_exact(r_path.len() + 1);
                        buf.push('/');
                    } else {
                        let last_slash_i = base_path.rfind('/').unwrap();
                        buf.reserve_exact(last_slash_i + r_path.len() + 1);
                        remove_dot_segments(&mut buf, &base_path[..=last_slash_i]);
                    }
                    t_path = remove_dot_segments(&mut buf, r_path.as_str());
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

    if len > u32::MAX as usize {
        return Err(ResolveError(ResolveErrorKind::OverlongOutput));
    }

    let mut buf = String::with_capacity(len);
    let mut meta = Meta::default();

    buf.push_str(t_scheme.as_str());
    meta.scheme_end = NonZeroU32::new(buf.len() as _);
    buf.push(':');

    if let Some(authority) = t_authority {
        let mut auth_meta = *authority.meta();
        let host_offsets = (
            auth_meta.host_bounds.0 - auth_meta.start,
            auth_meta.host_bounds.1 - auth_meta.start,
        );

        buf.push_str("//");
        auth_meta.start = buf.len() as _;
        auth_meta.host_bounds = (
            auth_meta.start + host_offsets.0,
            auth_meta.start + host_offsets.1,
        );
        buf.push_str(authority.as_str());

        meta.auth_meta = Some(auth_meta);
    }

    meta.path_bounds.0 = buf.len() as _;
    // Close the loophole in the original algorithm.
    if t_authority.is_none() && t_path.starts_with("//") {
        buf.push_str("/.");
    }
    buf.push_str(t_path);
    meta.path_bounds.1 = buf.len() as _;

    if let Some(query) = t_query {
        buf.push('?');
        buf.push_str(query.as_str());
        meta.query_end = NonZeroU32::new(buf.len() as _);
    }

    if let Some(fragment) = t_fragment {
        buf.push('#');
        buf.push_str(fragment.as_str());
    }

    debug_assert_eq!(buf.len(), len);

    Ok(Uri { val: buf, meta })
}

/// Removes dot segments from an absolute path.
pub(crate) fn remove_dot_segments<'a>(buf: &'a mut String, path: &str) -> &'a str {
    for seg in path.split_inclusive('/') {
        if seg == "." || seg == "./" {
            buf.truncate(buf.rfind('/').unwrap() + 1);
        } else if seg == ".." || seg == "../" {
            if buf.len() != 1 {
                buf.truncate(buf.rfind('/').unwrap());
                buf.truncate(buf.rfind('/').unwrap() + 1);
            }
        } else {
            buf.push_str(seg);
        }
    }
    buf
}
