use crate::{
    encoding::EStr,
    error::{ParseError, ParseErrorKind},
    internal::Storage,
    Authority, Host, Path, Scheme, Uri,
};
use core::fmt::{Debug, Display, Formatter, Result};

impl Debug for EStr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        Debug::fmt(self.as_str(), f)
    }
}

impl Display for EStr {
    #[inline]
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
            ParseErrorKind::InvalidIpLiteral => "invalid IP literal at index ",
        };
        write!(f, "{}{}", msg, self.index)
    }
}

impl<T: Storage> Debug for Uri<T> {
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

impl<T: Storage> Display for Uri<T> {
    #[inline]
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

impl<T: Storage> Debug for Authority<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct("Authority")
            .field("userinfo", &self.userinfo())
            .field("host", &self.host())
            .field("port", &self.port())
            .finish()
    }
}

impl<T: Storage> Display for Authority<T> {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        Display::fmt(self.as_str(), f)
    }
}

impl<T: Storage> Debug for Host<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct("Host")
            .field("value", &self.as_str())
            .field("parsed", &self.parsed())
            .finish()
    }
}

impl<T: Storage> Display for Host<T> {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        Display::fmt(self.as_str(), f)
    }
}

impl Debug for Path {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        Debug::fmt(self.as_str(), f)
    }
}

impl Display for Path {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        Display::fmt(self.as_str(), f)
    }
}
