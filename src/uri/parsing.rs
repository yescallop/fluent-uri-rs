use super::*;
use crate::encoding::{chr, macros::*, raw::*, table::*};

pub(crate) fn parse(mut s: &[u8]) -> RawResult<UriRef<'_>> {
    if s.is_empty() {
        return Ok(UriRef::EMPTY);
    }

    let fragment = match take!(tail, s, b'#') {
        Some(x) => Some(validate!(x, QUERY_FRAGMENT)),
        None => None,
    };

    let query = match take!(tail, s, b'?') {
        Some(x) => Some(validate!(x, QUERY_FRAGMENT)),
        None => None,
    };

    let scheme = match take!(head, s, b':' until b'/') {
        Some(x) => {
            // Scheme starts with a letter.
            if x.is_empty() || !x[0].is_ascii_alphabetic() {
                err!(x, 0);
            }
            Some(validate!(x, SCHEME, offset = 1))
        }
        None => None,
    };

    let (authority, path) = parse_hier_part(s)?;

    Ok(UriRef {
        scheme,
        authority,
        path,
        query,
        fragment,
    })
}

fn parse_hier_part(mut s: &[u8]) -> RawResult<(Option<Authority<'_>>, &str)> {
    let auth = if s.starts_with(b"//") {
        s = &s[2..];
        let auth_end = chr(s, b'/').unwrap_or(s.len());

        let auth = parse_authority(&s[..auth_end])?;
        s = &s[auth_end..];
        Some(auth)
    } else {
        None
    };

    let path = validate!(s, PATH);
    Ok((auth, path))
}

fn parse_authority(mut s: &[u8]) -> RawResult<Authority<'_>> {
    if s.is_empty() {
        return Ok(Authority::EMPTY);
    }

    let userinfo = match take!(head, s, b'@') {
        Some(x) => Some(validate!(x, USERINFO)),
        None => None,
    };

    // Note that the port subcomponent can be empty.
    let mut has_port = false;
    let host = if !s.is_empty() && s[0] == b'[' {
        s = &s[1..];
        let host = match take!(r, head, s, b']') {
            Some(x) => x,
            _ => err!(s, 0),
        };

        if !s.is_empty() {
            if s[0] != b':' {
                err!(s, 0);
            }
            s = &s[1..];
            has_port = true;
        }

        parse_ip_literal(host)?
    } else {
        let host = match take!(head, s, b':') {
            Some(x) => {
                has_port = true;
                x
            }
            None => s,
        };
        parse_non_ip_literal(host)?
    };

    let port = if has_port {
        Some(validate!(s, u8::is_ascii_digit))
    } else {
        None
    };

    Ok(Authority {
        userinfo,
        host,
        port,
    })
}

fn parse_ip_literal(mut s: &[u8]) -> RawResult<Host<'_>> {
    if s.len() < 2 {
        err!(s, 0);
    }
    // IPvFuture = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
    // RFC 2234, Section 2.3: ABNF strings are case-insensitive.
    if matches!(s[0], b'v' | b'V') {
        s = &s[1..];

        let ver = match take!(head, s, b'.') {
            Some(x) if !x.is_empty() => validate!(x, HEXDIG),
            _ => err!(s, 0),
        };

        if s.is_empty() {
            err!(s, 0);
        }
        let addr = validate!(s, IPV_FUTURE);
        Ok(Host::IpvFuture { ver, addr })
    } else {
        let zone_id = if let Some(x) = take!(tail, s, b'%') {
            // Zone ID must not be empty.
            if x.len() < 3 || !x.starts_with(b"25") {
                err!(x, 0);
            }
            Some(validate!(&x[2..], ZONE_ID))
        } else {
            None
        };

        match crate::ip::parse_v6(s) {
            Some(addr) => Ok(Host::Ipv6 {
                addr,
                // SAFETY: We have done the validation.
                zone_id: zone_id.map(|s| unsafe { EStr::new_unchecked(s) }),
            }),
            None => err!(s, 0),
        }
    }
}

fn parse_non_ip_literal(s: &[u8]) -> RawResult<Host<'_>> {
    Ok(match crate::ip::parse_v4(s) {
        Some(addr) => Host::Ipv4(addr),
        None => Host::RegName(validate!(s, REG_NAME)),
    })
}
