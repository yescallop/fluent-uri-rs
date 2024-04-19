use crate::{
    encoding::{decode_octet, table::UNRESERVED},
    internal::{HostMeta, Meta},
    parser, resolver, Uri,
};
use alloc::string::String;
use core::{fmt::Write, num::NonZeroU32};

pub(crate) fn normalize(u: Uri<&str>) -> Uri<String> {
    let mut buf = String::with_capacity(u.as_str().len());

    let path = u.path().as_str();
    let mut path_buf = String::with_capacity(path.len());

    if u.scheme_end.is_some() && path.starts_with('/') {
        normalize_estr(&mut buf, path, false);
        resolver::remove_dot_segments(&mut path_buf, &buf);
        buf.clear();
    } else {
        // Don't remove dot segments from relative reference or rootless path.
        normalize_estr(&mut path_buf, path, false);
    }

    let mut meta = Meta::default();

    if let Some(scheme) = u.scheme() {
        buf.push_str(scheme.as_str());
        buf.make_ascii_lowercase();
        meta.scheme_end = NonZeroU32::new(buf.len() as _);
        buf.push(':');
    }

    if let Some(auth) = u.authority() {
        buf.push_str("//");

        if let Some(userinfo) = auth.userinfo() {
            normalize_estr(&mut buf, userinfo.as_str(), false);
            buf.push('@');
        }

        let mut auth_meta = *auth.meta();
        auth_meta.host_bounds.0 = buf.len() as _;
        match auth_meta.host_meta {
            // An IPv4 address is always canonical.
            HostMeta::Ipv4(..) => buf.push_str(auth.host()),
            #[cfg(feature = "net")]
            HostMeta::Ipv6(addr) => write!(buf, "[{addr}]").unwrap(),
            #[cfg(not(feature = "net"))]
            HostMeta::Ipv6() => {
                buf.push('[');
                write_v6(&mut buf, parser::parse_v6(&auth.host().as_bytes()[1..]));
                buf.push(']');
            }
            HostMeta::IpvFuture => {
                let start = buf.len();
                buf.push_str(auth.host());

                buf[start..].make_ascii_lowercase();
            }
            HostMeta::RegName => {
                let start = buf.len();
                let host = auth.host();
                normalize_estr(&mut buf, host, true);

                if buf.len() < start + host.len() {
                    // Only reparse when the length is less than before.
                    auth_meta.host_meta = parser::parse_v4_or_reg_name(&buf.as_bytes()[start..]);
                }
            }
        }
        auth_meta.host_bounds.1 = buf.len() as _;
        meta.auth_meta = Some(auth_meta);

        if let Some(port) = auth.port() {
            if !port.is_empty() {
                buf.push(':');
                buf.push_str(port);
            }
        }
    }

    meta.path_bounds.0 = buf.len() as _;
    // Make sure that the output is a valid URI reference.
    if u.scheme_end.is_some() && u.auth_meta.is_none() && path_buf.starts_with("//") {
        buf.push_str("/.");
    }
    buf.push_str(&path_buf);
    meta.path_bounds.1 = buf.len() as _;

    if let Some(query) = u.query() {
        buf.push('?');
        normalize_estr(&mut buf, query.as_str(), false);
        meta.query_end = NonZeroU32::new(buf.len() as _);
    }

    if let Some(fragment) = u.fragment() {
        buf.push('#');
        normalize_estr(&mut buf, fragment.as_str(), false);
    }

    debug_assert!(buf.len() <= u.as_str().len());

    // No need to check the length because it cannot grow larger.
    Uri { val: buf, meta }
}

fn normalize_estr(buf: &mut String, s: &str, to_lowercase: bool) {
    let s = s.as_bytes();
    let mut i = 0;

    while i < s.len() {
        let mut x = s[i];
        if x == b'%' {
            let (hi, lo) = (s[i + 1], s[i + 2]);
            let mut octet = decode_octet(hi, lo);
            if UNRESERVED.allows(octet) {
                if to_lowercase {
                    octet = octet.to_ascii_lowercase();
                }
                buf.push(octet as char);
            } else {
                buf.push('%');
                buf.push(hi.to_ascii_uppercase() as char);
                buf.push(lo.to_ascii_uppercase() as char);
            }
            i += 3;
        } else {
            if to_lowercase {
                x = x.to_ascii_lowercase();
            }
            buf.push(x as char);
            i += 1;
        }
    }
}

// Taken from `impl Display for Ipv6Addr`.
#[cfg(not(feature = "net"))]
fn write_v6(buf: &mut String, segments: [u16; 8]) {
    if let [0, 0, 0, 0, 0, 0xffff, ab, cd] = segments {
        let [a, b] = ab.to_be_bytes();
        let [c, d] = cd.to_be_bytes();
        write!(buf, "::ffff:{}.{}.{}.{}", a, b, c, d).unwrap();
    } else {
        #[derive(Copy, Clone, Default)]
        struct Span {
            start: usize,
            len: usize,
        }

        // Find the inner 0 span
        let zeroes = {
            let mut longest = Span::default();
            let mut current = Span::default();

            for (i, &segment) in segments.iter().enumerate() {
                if segment == 0 {
                    if current.len == 0 {
                        current.start = i;
                    }

                    current.len += 1;

                    if current.len > longest.len {
                        longest = current;
                    }
                } else {
                    current = Span::default();
                }
            }

            longest
        };

        /// Write a colon-separated part of the address
        #[inline]
        fn write_subslice(buf: &mut String, chunk: &[u16]) {
            if let Some((first, tail)) = chunk.split_first() {
                write!(buf, "{:x}", first).unwrap();
                for segment in tail {
                    write!(buf, ":{:x}", segment).unwrap();
                }
            }
        }

        if zeroes.len > 1 {
            write_subslice(buf, &segments[..zeroes.start]);
            buf.push_str("::");
            write_subslice(buf, &segments[zeroes.start + zeroes.len..]);
        } else {
            write_subslice(buf, &segments);
        }
    }
}
