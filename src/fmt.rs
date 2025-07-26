use crate::{
    build::BuildError,
    component::{Authority, Host, Scheme},
    parse::{ParseError, ParseErrorKind},
    pct_enc::{EStr, EString, Encoder},
    resolve::ResolveError,
};
use core::fmt::{Debug, Display, Formatter, Result};

impl<E: Encoder> Debug for EStr<E> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        Debug::fmt(self.as_str(), f)
    }
}

impl<E: Encoder> Display for EStr<E> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        Display::fmt(self.as_str(), f)
    }
}

impl<E: Encoder> Debug for EString<E> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        Debug::fmt(self.as_str(), f)
    }
}

impl<E: Encoder> Display for EString<E> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        Display::fmt(self.as_str(), f)
    }
}

impl<I> Debug for ParseError<I> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct("ParseError")
            .field("index", &self.index)
            .field("kind", &self.kind)
            .finish()
    }
}

impl<I> Display for ParseError<I> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let msg = match self.kind {
            ParseErrorKind::InvalidPctEncodedOctet => "invalid percent-encoded octet at index ",
            ParseErrorKind::UnexpectedChar => "unexpected character at index ",
            ParseErrorKind::InvalidIpv6Addr => "invalid IPv6 address at index ",
            ParseErrorKind::SchemeNotPresent => return f.write_str("scheme not present"),
        };
        write!(f, "{}{}", msg, self.index)
    }
}

impl Display for BuildError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let msg = match self {
            Self::NonemptyRootlessPath => {
                "when authority is present, path should either be empty or start with '/'"
            }
            Self::PathStartsWithDoubleSlash => {
                "when authority is not present, path should not start with \"//\""
            }
            Self::FirstPathSegmentContainsColon => {
                "when neither scheme nor authority is present, first path segment should not contain ':'"
            }
        };
        f.write_str(msg)
    }
}

impl Display for ResolveError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let msg = match self {
            Self::BaseWithFragment => "base should not have fragment",
            Self::InvalidReferenceAgainstOpaqueBase => {
                "when base has no authority and its path is rootless, reference should either have scheme, be empty or start with '#'"
            }
            Self::PathUnderflow => "underflow occurred in path resolution",
        };
        f.write_str(msg)
    }
}

impl Debug for Scheme {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        Debug::fmt(self.as_str(), f)
    }
}

impl Display for Scheme {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        Display::fmt(self.as_str(), f)
    }
}

impl<RegNameE: Encoder> Debug for Host<'_, RegNameE> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            #[cfg(feature = "net")]
            Host::Ipv4(addr) => f.debug_tuple("Ipv4").field(addr).finish(),
            #[cfg(feature = "net")]
            Host::Ipv6(addr) => f.debug_tuple("Ipv6").field(addr).finish(),

            #[cfg(not(feature = "net"))]
            Host::Ipv4() => f.debug_struct("Ipv4").finish_non_exhaustive(),
            #[cfg(not(feature = "net"))]
            Host::Ipv6() => f.debug_struct("Ipv6").finish_non_exhaustive(),

            Host::IpvFuture => f.debug_struct("IpvFuture").finish_non_exhaustive(),
            Host::RegName(name) => f.debug_tuple("RegName").field(name).finish(),
        }
    }
}

impl<UserinfoE: Encoder, RegNameE: Encoder> Debug for Authority<'_, UserinfoE, RegNameE> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct("Authority")
            .field("userinfo", &self.userinfo())
            .field("host", &self.host())
            .field("host_parsed", &self.host_parsed())
            .field("port", &self.port())
            .finish()
    }
}

impl Display for Authority<'_> {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        Display::fmt(self.as_str(), f)
    }
}
