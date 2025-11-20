use crate::{
    imp::{AuthMeta, Constraints, HostMeta, Meta},
    pct_enc::{self, encoder::*, Encoder, Table},
    utf8,
};
use core::{
    marker::PhantomData,
    num::NonZeroUsize,
    ops::{Deref, DerefMut},
    str,
};

/// Detailed cause of a [`ParseError`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseErrorKind {
    /// Unexpected character or end of input.
    ///
    /// The error index points to the first byte of the character or the end of input.
    UnexpectedCharOrEnd,
    /// Invalid IPv6 address.
    ///
    /// The error index points to the first byte of the address.
    InvalidIpv6Addr,
}

/// An error occurred when parsing a URI/IRI (reference).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseError {
    pub(crate) index: usize,
    pub(crate) kind: ParseErrorKind,
}

impl ParseError {
    /// Returns the index at which the error occurred.
    #[must_use]
    pub fn index(&self) -> usize {
        self.index
    }

    /// Returns the detailed cause of the error.
    #[must_use]
    pub fn kind(&self) -> ParseErrorKind {
        self.kind
    }
}

#[cfg(feature = "impl-error")]
impl crate::Error for ParseError {}

type Result<T> = core::result::Result<T, ParseError>;

/// Returns immediately with an error.
macro_rules! err {
    ($index:expr, $kind:ident) => {
        return Err(ParseError {
            index: $index,
            kind: ParseErrorKind::$kind,
        })
    };
}

pub(crate) fn parse(bytes: &[u8], constraints: Constraints) -> Result<Meta> {
    let mut parser = Parser {
        constraints,
        reader: Reader::new(bytes),
        out: Meta::default(),
    };
    parser.parse_from_scheme()?;
    Ok(parser.out)
}

/// URI/IRI parser.
///
/// # Invariants
///
/// `pos <= len`, `pos` is non-decreasing and on the boundary of a UTF-8 code point.
///
/// # Preconditions and guarantees
///
/// Before parsing, ensure that `pos == 0`, `out` is default initialized
/// and `bytes` is valid UTF-8.
///
/// Start and finish parsing by calling `parse_from_scheme`.
/// The following are guaranteed when parsing succeeds:
///
/// - All output indexes are within bounds, correctly ordered
///   and on the boundary of a UTF-8 code point.
/// - All URI/IRI components defined by output indexes are validated.
struct Parser<'a> {
    constraints: Constraints,
    reader: Reader<'a>,
    out: Meta,
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Deref for Parser<'a> {
    type Target = Reader<'a>;

    fn deref(&self) -> &Self::Target {
        &self.reader
    }
}

impl DerefMut for Parser<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.reader
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PathKind {
    General,
    AbEmpty,
    ContinuedNoScheme,
}

enum Seg {
    // *1":" 1*4HEXDIG
    Normal(u16, bool),
    // "::"
    Ellipsis,
    // *1":" 1*4HEXDIG "."
    MaybeV4(bool),
    // ":"
    SingleColon,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Reader { bytes, pos: 0 }
    }

    fn len(&self) -> usize {
        self.bytes.len()
    }

    fn has_remaining(&self) -> bool {
        self.pos < self.len()
    }

    fn peek(&self, i: usize) -> Option<u8> {
        self.bytes.get(self.pos + i).copied()
    }

    // Any call to this method must keep the invariants.
    fn skip(&mut self, n: usize) {
        // INVARIANT: `pos` is non-decreasing.
        self.pos += n;
        debug_assert!(self.pos <= self.len());
    }

    #[cold]
    fn invalid_pct(&self) -> Result<bool> {
        let mut i = self.pos + 1;
        if let Some(&x) = self.bytes.get(i) {
            if pct_enc::is_hexdig(x) {
                i += 1;
            }
        }
        err!(i, UnexpectedCharOrEnd);
    }

    // FIXME: This makes things faster but causes significant bloat.
    #[inline(always)]
    fn read_generic<const ALLOW_PCT_ENCODED: bool, const ALLOW_NON_ASCII: bool>(
        &mut self,
        table: Table,
    ) -> Result<bool> {
        let start = self.pos;
        let mut i = self.pos;

        while i < self.len() {
            let x = self.bytes[i];
            if ALLOW_PCT_ENCODED && x == b'%' {
                let [hi, lo, ..] = self.bytes[i + 1..] else {
                    return self.invalid_pct();
                };
                if !pct_enc::is_hexdig_pair(hi, lo) {
                    return self.invalid_pct();
                }
                i += 3;
            } else if ALLOW_NON_ASCII {
                let (x, len) = utf8::next_code_point(self.bytes, i);
                if !table.allows_code_point(x) {
                    break;
                }
                i += len;
            } else {
                if !table.allows_ascii(x) {
                    break;
                }
                i += 1;
            }
        }

        // INVARIANT: `i` is non-decreasing.
        self.pos = i;
        Ok(self.pos > start)
    }

    #[inline(always)]
    fn read<E: Encoder>(&mut self) -> Result<bool> {
        struct Helper<E: Encoder> {
            _marker: PhantomData<E>,
        }

        impl<E: Encoder> Helper<E> {
            const ALLOWS_PCT_ENCODED: bool = E::TABLE.allows_pct_encoded();
            const ALLOWS_NON_ASCII: bool = E::TABLE.allows_non_ascii();
        }

        if Helper::<E>::ALLOWS_PCT_ENCODED {
            if Helper::<E>::ALLOWS_NON_ASCII {
                self.read_generic::<true, true>(E::TABLE)
            } else {
                self.read_generic::<true, false>(E::TABLE)
            }
        } else {
            assert!(!Helper::<E>::ALLOWS_NON_ASCII);
            self.read_generic::<false, false>(E::TABLE)
        }
    }

    fn read_str(&mut self, s: &str) -> bool {
        if self.bytes[self.pos..].starts_with(s.as_bytes()) {
            // INVARIANT: The remaining bytes start with `s` so it's fine to skip `s.len()`.
            self.skip(s.len());
            true
        } else {
            false
        }
    }

    fn read_v6(&mut self) -> Option<[u16; 8]> {
        let mut segs = [0; 8];
        let mut ellipsis_idx = 8;

        let mut i = 0;
        while i < 8 {
            match self.read_v6_segment() {
                Some(Seg::Normal(seg, colon)) => {
                    if colon == (i == 0 || i == ellipsis_idx) {
                        // Leading colon, triple colons, or no colon.
                        return None;
                    }
                    segs[i] = seg;
                    i += 1;
                }
                Some(Seg::Ellipsis) => {
                    if ellipsis_idx != 8 {
                        // Multiple ellipses.
                        return None;
                    }
                    ellipsis_idx = i;
                }
                Some(Seg::MaybeV4(colon)) => {
                    if i > 6 || colon == (i == ellipsis_idx) {
                        // Not enough space, triple colons, or no colon.
                        return None;
                    }
                    let octets = self.read_v4()?.to_be_bytes();
                    segs[i] = u16::from_be_bytes([octets[0], octets[1]]);
                    segs[i + 1] = u16::from_be_bytes([octets[2], octets[3]]);
                    i += 2;
                    break;
                }
                Some(Seg::SingleColon) => return None,
                None => break,
            }
        }

        if ellipsis_idx == 8 {
            // No ellipsis.
            if i != 8 {
                // Too short.
                return None;
            }
        } else if i == 8 {
            // Eliding nothing.
            return None;
        } else {
            // Shift the segments after the ellipsis to the right.
            for j in (ellipsis_idx..i).rev() {
                segs[8 - (i - j)] = segs[j];
                segs[j] = 0;
            }
        }

        Some(segs)
    }

    fn read_v6_segment(&mut self) -> Option<Seg> {
        let colon = self.read_str(":");
        if !self.has_remaining() {
            return colon.then_some(Seg::SingleColon);
        }

        let first = self.peek(0).unwrap();
        let mut x = match pct_enc::decode_hexdigit(first) {
            Some(v) => v as u16,
            _ => {
                return colon.then(|| {
                    if first == b':' {
                        // INVARIANT: Skipping ":" is fine.
                        self.skip(1);
                        Seg::Ellipsis
                    } else {
                        Seg::SingleColon
                    }
                });
            }
        };
        let mut i = 1;

        while i < 4 {
            let Some(b) = self.peek(i) else {
                // INVARIANT: Skipping `i` hexadecimal digits is fine.
                self.skip(i);
                return None;
            };
            match pct_enc::decode_hexdigit(b) {
                Some(v) => {
                    x = (x << 4) | v as u16;
                    i += 1;
                }
                _ if b == b'.' => return Some(Seg::MaybeV4(colon)),
                _ => break,
            }
        }
        // INVARIANT: Skipping `i` hexadecimal digits is fine.
        self.skip(i);
        Some(Seg::Normal(x, colon))
    }

    fn read_v4(&mut self) -> Option<u32> {
        let mut addr = self.read_v4_octet()? << 24;
        for i in (0..3).rev() {
            if !self.read_str(".") {
                return None;
            }
            addr |= self.read_v4_octet()? << (i * 8);
        }
        Some(addr)
    }

    fn read_v4_octet(&mut self) -> Option<u32> {
        let mut res = self.peek_digit(0)?;
        if res == 0 {
            // INVARIANT: Skipping "0" is fine.
            self.skip(1);
            return Some(0);
        }

        for i in 1..3 {
            let Some(x) = self.peek_digit(i) else {
                // INVARIANT: Skipping `i` digits is fine.
                self.skip(i);
                return Some(res);
            };
            res = res * 10 + x;
        }
        // INVARIANT: Skipping 3 digits is fine.
        self.skip(3);

        u8::try_from(res).is_ok().then_some(res)
    }

    fn peek_digit(&self, i: usize) -> Option<u32> {
        self.peek(i).and_then(|x| (x as char).to_digit(10))
    }

    fn read_port(&mut self) {
        if self.read_str(":") {
            let mut i = 0;
            while self.peek_digit(i).is_some() {
                i += 1;
            }
            // INVARIANT: Skipping `i` digits is fine.
            self.skip(i);
        }
    }

    fn read_ip_literal(&mut self) -> Result<Option<HostMeta>> {
        if !self.read_str("[") {
            return Ok(None);
        }

        let start = self.pos;

        let meta = if let Some(_addr) = self.read_v6() {
            HostMeta::Ipv6(
                #[cfg(feature = "net")]
                _addr.into(),
            )
        } else if self.pos == start {
            self.read_ipv_future()?;
            HostMeta::IpvFuture
        } else {
            err!(start, InvalidIpv6Addr);
        };

        if !self.read_str("]") {
            err!(self.pos, UnexpectedCharOrEnd);
        }
        Ok(Some(meta))
    }

    fn read_ipv_future(&mut self) -> Result<()> {
        if let Some(b'v' | b'V') = self.peek(0) {
            // INVARIANT: Skipping "v" or "V" is fine.
            self.skip(1);
            if self.read::<Hexdig>()? && self.read_str(".") && self.read::<IpvFuture>()? {
                return Ok(());
            }
        }
        err!(self.pos, UnexpectedCharOrEnd);
    }
}

pub(crate) fn parse_v4_or_reg_name(bytes: &[u8]) -> HostMeta {
    let mut reader = Reader::new(bytes);
    match reader.read_v4() {
        Some(_addr) if !reader.has_remaining() => HostMeta::Ipv4(
            #[cfg(feature = "net")]
            _addr.into(),
        ),
        _ => HostMeta::RegName,
    }
}

#[cfg(not(feature = "net"))]
pub(crate) fn parse_v6(bytes: &[u8]) -> [u16; 8] {
    Reader::new(bytes).read_v6().unwrap()
}

impl Parser<'_> {
    #[inline(always)]
    fn select_read<U: Encoder, I: Encoder>(&mut self) -> Result<bool> {
        if self.constraints.ascii_only {
            self.read::<U>()
        } else {
            self.read::<I>()
        }
    }

    fn read_v4_or_reg_name(&mut self) -> Result<HostMeta> {
        Ok(
            match (self.read_v4(), self.select_read::<RegName, IRegName>()?) {
                (Some(_addr), false) => HostMeta::Ipv4(
                    #[cfg(feature = "net")]
                    _addr.into(),
                ),
                _ => HostMeta::RegName,
            },
        )
    }

    fn read_host(&mut self) -> Result<HostMeta> {
        match self.read_ip_literal()? {
            Some(host) => Ok(host),
            None => self.read_v4_or_reg_name(),
        }
    }

    fn parse_from_scheme(&mut self) -> Result<()> {
        self.read::<Scheme>()?;

        if self.peek(0) == Some(b':') {
            // Scheme starts with a letter.
            if self.pos > 0 && self.bytes[0].is_ascii_alphabetic() {
                self.out.scheme_end = NonZeroUsize::new(self.pos);
            } else {
                err!(0, UnexpectedCharOrEnd);
            }

            // INVARIANT: Skipping ":" is fine.
            self.skip(1);
            return if self.read_str("//") {
                self.parse_from_authority()
            } else {
                self.parse_from_path(PathKind::General)
            };
        } else if self.constraints.scheme_required {
            err!(self.pos, UnexpectedCharOrEnd);
        } else if self.pos == 0 {
            // Nothing read.
            if self.read_str("//") {
                return self.parse_from_authority();
            }
        }
        // Scheme chars are valid for path.
        self.parse_from_path(PathKind::ContinuedNoScheme)
    }

    fn parse_from_authority(&mut self) -> Result<()> {
        // We first try to read host and port, noting that
        // a reg-name or IPv4address can also be part of userinfo.
        let host_start = self.pos;
        let host_meta = self.read_host()?;

        let mut auth_meta = AuthMeta {
            host_bounds: (host_start, self.pos),
            host_meta,
        };

        self.read_port();

        if let HostMeta::Ipv4(..) | HostMeta::RegName = host_meta {
            let userinfo_read = self.select_read::<Userinfo, IUserinfo>()?;

            if self.peek(0) == Some(b'@') {
                // Userinfo present.
                // INVARIANT: Skipping "@" is fine.
                self.skip(1);

                let host_start = self.pos;
                let host_meta = self.read_host()?;

                auth_meta = AuthMeta {
                    host_bounds: (host_start, self.pos),
                    host_meta,
                };

                self.read_port();
            } else if userinfo_read {
                err!(self.pos, UnexpectedCharOrEnd);
            }
        }

        self.out.auth_meta = Some(auth_meta);
        self.parse_from_path(PathKind::AbEmpty)
    }

    fn parse_from_path(&mut self, kind: PathKind) -> Result<()> {
        let path_start;

        match kind {
            PathKind::General | PathKind::AbEmpty => path_start = self.pos,
            PathKind::ContinuedNoScheme => {
                path_start = 0;

                self.select_read::<SegmentNzNc, ISegmentNzNc>()?;

                if self.peek(0) == Some(b':') {
                    // In a relative reference, the first path
                    // segment cannot contain a colon character.
                    err!(self.pos, UnexpectedCharOrEnd);
                }
            }
        };

        if self.select_read::<Path, IPath>()?
            && kind == PathKind::AbEmpty
            && self.bytes[path_start] != b'/'
        {
            err!(path_start, UnexpectedCharOrEnd);
        }

        self.out.path_bounds = (path_start, self.pos);

        if self.read_str("?") {
            self.select_read::<Query, IQuery>()?;
            self.out.query_end = NonZeroUsize::new(self.pos);
        }

        if self.read_str("#") {
            self.select_read::<Fragment, IFragment>()?;
        }

        if self.has_remaining() {
            err!(self.pos, UnexpectedCharOrEnd);
        }
        Ok(())
    }
}
