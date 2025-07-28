use crate::{
    imp::{HostMeta, Meta, RiMaybeRef, RmrRef},
    parse::ParseError,
    pct_enc::encode_byte,
    Iri, IriRef, Uri, UriRef,
};
use alloc::string::String;
use borrow_or_share::Bos;
use core::{num::NonZeroUsize, str};

macro_rules! impl_from {
    ($($x:ident => $($y:ident),+)*) => {
        $($(
            impl<T: Bos<str>> From<$x<T>> for $y<T> {
                #[doc = concat!("Consumes the `", stringify!($x), "` and creates a new [`", stringify!($y), "`] with the same contents.")]
                fn from(value: $x<T>) -> Self {
                    RiMaybeRef::new(value.val, value.meta)
                }
            }
        )+)*
    };
}

impl_from! {
    Uri => UriRef, Iri, IriRef
    UriRef => IriRef
    Iri => IriRef
}

macro_rules! impl_try_from {
    ($(#[$doc:meta] $x:ident if $($cond:ident)&&+ => $y:ident)*) => {
        $(
            impl<'a> TryFrom<$x<&'a str>> for $y<&'a str> {
                type Error = ParseError;

                #[$doc]
                fn try_from(value: $x<&'a str>) -> Result<Self, Self::Error> {
                    let r = value.make_ref();
                    $(r.$cond()?;)+
                    Ok((RiMaybeRef::new(value.val, value.meta)))
                }
            }

            impl TryFrom<$x<String>> for $y<String> {
                type Error = ParseError<$x<String>>;

                #[$doc]
                fn try_from(value: $x<String>) -> Result<Self, Self::Error> {
                    let r = value.make_ref();
                    $(
                        if let Err(e) = r.$cond() {
                            return Err(e.with_input(value));
                        }
                    )+
                    Ok((RiMaybeRef::new(value.val, value.meta)))
                }
            }
        )*
    };
}

impl_try_from! {
    /// Converts the URI reference to a URI if it has a scheme.
    UriRef if ensure_has_scheme => Uri
    /// Converts the IRI to a URI if it is ASCII.
    Iri if ensure_ascii => Uri
    /// Converts the IRI reference to a URI if it has a scheme and is ASCII.
    IriRef if ensure_has_scheme && ensure_ascii => Uri
    /// Converts the IRI reference to a URI reference if it is ASCII.
    IriRef if ensure_ascii => UriRef
    /// Converts the IRI reference to an IRI if it has a scheme.
    IriRef if ensure_has_scheme => Iri
}

impl<T: Bos<str>> Iri<T> {
    /// Converts the IRI to a URI by percent-encoding non-ASCII characters.
    ///
    /// Punycode encoding is **not** performed during conversion.
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Iri;
    ///
    /// let iri = Iri::parse("http://www.example.org/résumé.html").unwrap();
    /// assert_eq!(iri.to_uri(), "http://www.example.org/r%C3%A9sum%C3%A9.html");
    ///
    /// let iri = Iri::parse("http://résumé.example.org").unwrap();
    /// assert_eq!(iri.to_uri(), "http://r%C3%A9sum%C3%A9.example.org");
    /// ```
    pub fn to_uri(&self) -> Uri<String> {
        RiMaybeRef::from_pair(encode_non_ascii(self.make_ref()))
    }
}

impl<T: Bos<str>> IriRef<T> {
    /// Converts the IRI reference to a URI reference by percent-encoding non-ASCII characters.
    ///
    /// Punycode encoding is **not** performed during conversion.
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::IriRef;
    ///
    /// let iri_ref = IriRef::parse("résumé.html").unwrap();
    /// assert_eq!(iri_ref.to_uri_ref(), "r%C3%A9sum%C3%A9.html");
    ///
    /// let iri_ref = IriRef::parse("//résumé.example.org").unwrap();
    /// assert_eq!(iri_ref.to_uri_ref(), "//r%C3%A9sum%C3%A9.example.org");
    /// ```
    pub fn to_uri_ref(&self) -> UriRef<String> {
        RiMaybeRef::from_pair(encode_non_ascii(self.make_ref()))
    }
}

fn encode_non_ascii(r: RmrRef<'_, '_>) -> (String, Meta) {
    let len = r
        .as_str()
        .chars()
        .map(|c| if c.is_ascii() { 1 } else { c.len_utf8() * 3 })
        .sum();

    let mut buf = String::with_capacity(len);
    let mut meta = Meta::default();

    if let Some(scheme) = r.scheme_opt() {
        buf.push_str(scheme.as_str());
        meta.scheme_end = NonZeroUsize::new(buf.len());
        buf.push(':');
    }

    if let Some(auth) = r.authority() {
        buf.push_str("//");

        if let Some(userinfo) = auth.userinfo() {
            encode_non_ascii_str(&mut buf, userinfo.as_str());
            buf.push('@');
        }

        let mut auth_meta = auth.meta();
        auth_meta.host_bounds.0 = buf.len();
        match auth_meta.host_meta {
            HostMeta::RegName => encode_non_ascii_str(&mut buf, auth.host()),
            _ => buf.push_str(auth.host()),
        }
        auth_meta.host_bounds.1 = buf.len();
        meta.auth_meta = Some(auth_meta);

        if let Some(port) = auth.port() {
            buf.push(':');
            buf.push_str(port.as_str());
        }
    }

    meta.path_bounds.0 = buf.len();
    encode_non_ascii_str(&mut buf, r.path().as_str());
    meta.path_bounds.1 = buf.len();

    if let Some(query) = r.query() {
        buf.push('?');
        encode_non_ascii_str(&mut buf, query.as_str());
        meta.query_end = NonZeroUsize::new(buf.len());
    }

    if let Some(fragment) = r.fragment() {
        buf.push('#');
        encode_non_ascii_str(&mut buf, fragment.as_str());
    }

    debug_assert_eq!(buf.len(), len);

    (buf, meta)
}

fn encode_non_ascii_str(buf: &mut String, s: &str) {
    if s.is_ascii() {
        buf.push_str(s);
    } else {
        for ch in s.chars() {
            if ch.is_ascii() {
                buf.push(ch);
            } else {
                for x in ch.encode_utf8(&mut [0; 4]).bytes() {
                    encode_byte(x, buf);
                }
            }
        }
    }
}
