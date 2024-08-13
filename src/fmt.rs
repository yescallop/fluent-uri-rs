use crate::{
    component::{Authority, Scheme},
    encoding::{EStr, EString, Encoder},
    error::{
        BuildError, BuildErrorKind, ParseError, ParseErrorKind, ResolveError, ResolveErrorKind,
    },
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
            ParseErrorKind::InvalidOctet => "invalid percent-encoded octet at index ",
            ParseErrorKind::UnexpectedChar => "unexpected character at index ",
            ParseErrorKind::InvalidIpv6Addr => "invalid IPv6 address at index ",
        };
        write!(f, "{}{}", msg, self.index)
    }
}

impl Display for BuildError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let msg = match self.0 {
            BuildErrorKind::NonAbemptyPath => {
                "path must either be empty or start with '/' when authority is present"
            }
            BuildErrorKind::PathStartingWithDoubleSlash => {
                "path cannot start with \"//\" when authority is absent"
            }
            BuildErrorKind::ColonInFirstPathSegment => {
                "first path segment cannot contain ':' in relative-path reference"
            }
        };
        f.write_str(msg)
    }
}

impl Display for ResolveError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let msg = match self.0 {
            ResolveErrorKind::InvalidBase => "base URI with fragment",
            ResolveErrorKind::OpaqueBase => {
                "relative reference must be empty or start with '#' when resolved against authority-less base URI with rootless path"
            }
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

impl<UserinfoE: Encoder, RegNameE: Encoder + Debug> Debug for Authority<'_, UserinfoE, RegNameE> {
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
