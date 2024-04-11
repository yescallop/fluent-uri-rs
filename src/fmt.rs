use crate::{
    component::{Authority, Scheme},
    encoding::{encoder::Encoder, EStr, EString},
    error::{ParseError, ParseErrorKind, ResolveError, ResolveErrorKind},
    Uri,
};
use borrow_or_share::Bos;
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
            ParseErrorKind::OverlongInput => "overlong input at index ",
        };
        write!(f, "{}{}", msg, self.index)
    }
}

impl Display for ResolveError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let msg = match self.0 {
            ResolveErrorKind::NonAbsoluteBase => "non-absolute base URI",
            ResolveErrorKind::NonHierarchicalBase => {
                "resolving non-same-document relative reference against non-hierarchical base URI"
            }
            ResolveErrorKind::OverlongOutput => "overlong output",
        };
        f.write_str(msg)
    }
}

impl<T: Bos<str>> Debug for Uri<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct("Uri")
            .field("scheme", &self.scheme())
            .field("authority", &self.authority())
            .field("path", &self.path())
            .field("query", &self.query())
            .field("fragment", &self.fragment())
            .finish()
    }
}

impl<T: Bos<str>> Display for Uri<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        Display::fmt(self.as_str(), f)
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

impl<T: Bos<str>> Debug for Authority<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct("Authority")
            .field("userinfo", &self.userinfo())
            .field("host", &self.host())
            .field("host_parsed", &self.host_parsed())
            .field("port", &self.port())
            .finish()
    }
}

impl<T: Bos<str>> Display for Authority<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        Display::fmt(self.as_str(), f)
    }
}
