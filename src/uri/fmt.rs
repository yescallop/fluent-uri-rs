use super::*;
use std::fmt;

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self.kind {
            ParseErrorKind::InvalidOctet => "invalid percent-encoded octet at index ",
            ParseErrorKind::UnexpectedChar => "unexpected character at index ",
            ParseErrorKind::InvalidIpLiteral => "invalid IP literal at index ",
        };
        write!(f, "{}{}", msg, self.index)
    }
}

impl fmt::Debug for Uri<&str> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Uri")
            .field("scheme", &self.scheme().map(|s| s.as_str()))
            .field("authority", &self.authority())
            .field("path", &self.path().as_str())
            .field("query", &self.query())
            .field("fragment", &self.fragment())
            .finish()
    }
}

impl fmt::Display for Uri<&str> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.as_str(), f)
    }
}

impl fmt::Debug for Uri<&mut [u8]> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Uri")
            .field("scheme", &self.scheme().map(|s| s.as_str()))
            .field("authority", &self.authority())
            .field("path", &self.path_opt().map(|s| s.as_str()))
            .field("query", &self.query())
            .field("fragment", &self.fragment())
            .finish()
    }
}

impl fmt::Debug for Uri<String> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Uri")
            .field("scheme", &self.scheme().map(|s| s.as_str()))
            .field("authority", &self.authority())
            .field("path", &self.path().as_str())
            .field("query", &self.query())
            .field("fragment", &self.fragment())
            .finish()
    }
}

impl fmt::Display for Uri<String> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.as_str(), f)
    }
}

impl fmt::Display for Scheme {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.as_str(), f)
    }
}

impl fmt::Debug for Authority<&str> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Authority")
            .field("userinfo", &self.userinfo())
            .field("host", &self.host_raw())
            .field("port", &self.port_raw())
            .finish()
    }
}

impl fmt::Display for Authority<&str> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.as_str(), f)
    }
}

impl fmt::Debug for Authority<&mut [u8]> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Authority")
            .field("userinfo", &self.userinfo())
            .field("host", &self.host_raw_opt())
            .field("port", &self.port_raw())
            .finish()
    }
}

impl<'i, 'a> fmt::Debug for AuthorityMut<'i, 'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthorityMut")
            .field("userinfo", &self.userinfo())
            .field("host", &self.host_raw_opt())
            .field("port", &self.port_raw())
            .finish()
    }
}

impl fmt::Debug for Authority<String> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Authority")
            .field("userinfo", &self.userinfo())
            .field("host", &self.host_raw())
            .field("port", &self.port_raw())
            .finish()
    }
}

impl fmt::Display for Authority<String> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.as_str(), f)
    }
}

impl fmt::Display for Path {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.as_str(), f)
    }
}

impl<'a> fmt::Display for Host<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Host::Ipv4(addr) => write!(f, "{addr}"),
            #[cfg(feature = "rfc6874bis")]
            Host::Ipv6 { addr, zone_id } => {
                write!(f, "[{addr}")?;
                if let Some(id) = zone_id {
                    write!(f, "%{id}")?;
                }
                write!(f, "]")
            }
            #[cfg(not(feature = "rfc6874bis"))]
            Host::Ipv6 { addr } => write!(f, "[{addr}]"),
            Host::RegName(reg_name) => write!(f, "{reg_name}"),
            #[cfg(feature = "ipv_future")]
            Host::IpvFuture { ver, addr } => write!(f, "[v{ver}.{addr}]"),
        }
    }
}
