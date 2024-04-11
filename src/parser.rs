use crate::{
    encoding::{table::*, OCTET_TABLE_LO},
    internal::{AuthMeta, HostMeta, Meta},
};
use core::{
    num::NonZeroU32,
    ops::{Deref, DerefMut},
    str,
};

type Result<T> = core::result::Result<T, crate::error::ParseError>;

/// Returns immediately with an error.
macro_rules! err {
    ($index:expr, $kind:ident) => {
        return Err(crate::error::ParseError {
            index: $index as u32,
            kind: crate::error::ParseErrorKind::$kind,
            input: (),
        })
    };
}

pub(crate) fn parse(bytes: &[u8]) -> Result<Meta> {
    if bytes.len() > u32::MAX as usize {
        err!(0, OverlongInput);
    }

    let mut parser = Parser {
        reader: Reader::new(bytes),
        out: Meta::default(),
    };
    parser.parse_from_scheme()?;
    Ok(parser.out)
}

/// URI parser.
///
/// # Invariants
///
/// `pos <= len`, `pos` is non-decreasing and `bytes[..pos]` is ASCII.
///
/// # Preconditions and guarantees
///
/// Before parsing, ensure that `len` is no larger than `u32::MAX`
/// and that `pos` and `out` are default initialized.
///
/// Start and finish parsing by calling `parse_from_scheme`.
/// The following are guaranteed when parsing succeeds:
///
/// - `bytes` is ASCII.
/// - All output indexes are within bounds and correctly ordered.
/// - All URI components defined by output indexes are validated.
struct Parser<'a> {
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

impl<'a> DerefMut for Parser<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.reader
    }
}

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

    fn get(&self, i: usize) -> u8 {
        self.bytes[i]
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

    // Returns `true` iff any byte is read.
    fn read(&mut self, table: &Table) -> Result<bool> {
        let start = self.pos;
        if table.allows_enc() {
            self.read_enc(table, |_| {})?;
        } else {
            let mut i = self.pos;
            while i < self.len() {
                if !table.allows(self.get(i)) {
                    break;
                }
                // INVARIANT: Since `i < len`, it holds that `i + 1 <= len`.
                i += 1;
            }
            // INVARIANT: `i` is non-decreasing and all bytes read are ASCII.
            self.pos = i;
        }
        Ok(self.pos > start)
    }

    fn read_enc(&mut self, table: &Table, mut f: impl FnMut(u8)) -> Result<()> {
        let mut i = self.pos;

        while i < self.len() {
            let x = self.get(i);
            if x == b'%' {
                // This cannot overflow as the maximum length of `bytes` is `isize::MAX`.
                if i + 2 >= self.len() {
                    err!(i, InvalidOctet);
                }

                let (hi, lo) = (self.get(i + 1), self.get(i + 2));

                if HEXDIG.get(hi) & HEXDIG.get(lo) == 0 {
                    err!(i, InvalidOctet);
                }
                // INVARIANT: Since `i + 2 < len`, it holds that `i + 3 <= len`.
                i += 3;
            } else {
                let v = table.get(x);
                if v == 0 {
                    break;
                }
                f(v);
                // INVARIANT: Since `i < len`, it holds that `i + 1 <= len`.
                i += 1;
            }
        }

        // INVARIANT: `i` is non-decreasing and all bytes read are ASCII.
        self.pos = i;
        Ok(())
    }

    // The string read must be ASCII.
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
        let mut ellipsis_i = 8;

        let mut i = 0;
        while i < 8 {
            match self.read_v6_segment() {
                Some(Seg::Normal(seg, colon)) => {
                    if colon == (i == 0 || i == ellipsis_i) {
                        // Preceding colon, triple colons, or no colon.
                        return None;
                    }
                    segs[i] = seg;
                    i += 1;
                }
                Some(Seg::Ellipsis) => {
                    if ellipsis_i != 8 {
                        // Multiple ellipses.
                        return None;
                    }
                    ellipsis_i = i;
                }
                Some(Seg::MaybeV4(colon)) => {
                    if i > 6 || colon == (i == ellipsis_i) {
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

        if ellipsis_i == 8 {
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
            for j in (ellipsis_i..i).rev() {
                segs[8 - (i - j)] = segs[j];
                segs[j] = 0;
            }
        }

        Some(segs)
    }

    fn read_v6_segment(&mut self) -> Option<Seg> {
        let colon = self.read_str(":");
        if !self.has_remaining() {
            return if colon { Some(Seg::SingleColon) } else { None };
        }

        let first = self.peek(0).unwrap();
        let mut x = match OCTET_TABLE_LO[first as usize] {
            v if v < 128 => v as u16,
            _ => {
                return if colon {
                    if first == b':' {
                        // INVARIANT: Skipping ":" is fine.
                        self.skip(1);
                        Some(Seg::Ellipsis)
                    } else {
                        Some(Seg::SingleColon)
                    }
                } else {
                    None
                };
            }
        };
        let mut i = 1;

        while i < 4 {
            if let Some(b) = self.peek(i) {
                match OCTET_TABLE_LO[b as usize] {
                    v if v < 128 => {
                        x = (x << 4) | v as u16;
                        i += 1;
                        continue;
                    }
                    _ if b == b'.' => return Some(Seg::MaybeV4(colon)),
                    _ => break,
                }
            } else {
                // INVARIANT: Skipping `i` hexadecimal digits is fine.
                self.skip(i);
                return None;
            }
        }
        // INVARIANT: Skipping `i` hexadecimal digits is fine.
        self.skip(i);
        Some(Seg::Normal(x, colon))
    }

    fn read_v4_or_reg_name(&mut self) -> Result<HostMeta> {
        let v4 = self.read_v4();
        let v4_end = self.pos;
        self.read(REG_NAME)?;

        Ok(match v4 {
            Some(_addr) if self.pos == v4_end => HostMeta::Ipv4(
                #[cfg(feature = "net")]
                _addr.into(),
            ),
            _ => HostMeta::RegName,
        })
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
            match self.peek_digit(i) {
                Some(x) => res = res * 10 + x,
                None => {
                    // INVARIANT: Skipping `i` digits is fine.
                    self.skip(i);
                    return Some(res);
                }
            }
        }
        // INVARIANT: Skipping 3 digits is fine.
        self.skip(3);

        (res <= u8::MAX as u32).then_some(res)
    }

    fn peek_digit(&self, i: usize) -> Option<u32> {
        self.peek(i).and_then(|x| (x as char).to_digit(10))
    }

    fn read_port(&mut self) {
        self.read_str(":").then(|| {
            let mut i = 0;
            while self.peek_digit(i).is_some() {
                i += 1;
            }
            // INVARIANT: Skipping `i` digits is fine.
            self.skip(i);
        });
    }

    fn read_host(&mut self) -> Result<HostMeta> {
        match self.read_ip_literal()? {
            Some(host) => Ok(host),
            None => self.read_v4_or_reg_name(),
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
            err!(self.pos, UnexpectedChar);
        }
        Ok(Some(meta))
    }

    fn read_ipv_future(&mut self) -> Result<()> {
        if matches!(self.peek(0), Some(b'v' | b'V')) {
            // INVARIANT: Skipping "v" or "V" is fine.
            self.skip(1);
            if self.read(HEXDIG)? && self.read_str(".") && self.read(IPV_FUTURE)? {
                return Ok(());
            }
        }
        err!(self.pos, UnexpectedChar);
    }
}

pub(crate) fn reparse_reg_name(bytes: &[u8]) -> HostMeta {
    let mut reader = Reader::new(bytes);
    match reader.read_v4() {
        Some(_addr) if !reader.has_remaining() => HostMeta::Ipv4(
            #[cfg(feature = "net")]
            _addr.into(),
        ),
        _ => HostMeta::RegName,
    }
}

impl<'a> Parser<'a> {
    fn parse_from_scheme(&mut self) -> Result<()> {
        self.read(SCHEME)?;

        if self.peek(0) == Some(b':') {
            // Scheme starts with a letter.
            if self.pos > 0 && self.get(0).is_ascii_alphabetic() {
                self.out.scheme_end = NonZeroU32::new(self.pos as _);
            } else {
                err!(0, UnexpectedChar);
            }

            // INVARIANT: Skipping ":" is fine.
            self.skip(1);
            return if self.read_str("//") {
                self.parse_from_authority()
            } else {
                self.parse_from_path(PathKind::General)
            };
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
        let host;
        let start = self.pos;

        // This table contains userinfo, reg-name, ":", and port
        // and is equivalent to `USERINFO`.
        const TABLE: &Table = &USERINFO.shl(1).or(&Table::gen(b":"));

        // The number of colons read.
        let mut colon_cnt = 0;

        let auth_start = self.pos;

        self.read_enc(TABLE, |v| {
            colon_cnt += (v & 1) as u32;
        })?;

        if self.peek(0) == Some(b'@') {
            // Userinfo present.
            // INVARIANT: Skipping "@" is fine.
            self.skip(1);

            let host_start = self.pos;
            let meta = self.read_host()?;
            host = (host_start, self.pos, meta);

            self.read_port();
        } else if self.pos == auth_start {
            // Nothing read. We're now at the start of an IP literal or the path.
            if let Some(meta) = self.read_ip_literal()? {
                host = (auth_start, self.pos, meta);
                self.read_port();
            } else {
                // Empty authority.
                host = (self.pos, self.pos, HostMeta::RegName);
            }
        } else {
            // The whole authority read. Try to parse the host and port.
            let host_end = match colon_cnt {
                // All host.
                0 => self.pos,
                // Host and port.
                1 => {
                    let mut i = self.pos - 1;
                    loop {
                        // There must be a colon in the way.
                        let x = self.get(i);
                        if !x.is_ascii_digit() {
                            if x == b':' {
                                break;
                            } else {
                                err!(i, UnexpectedChar);
                            }
                        }
                        i -= 1;
                    }
                    i
                }
                // Multiple colons.
                _ => {
                    let mut i = auth_start;
                    loop {
                        // There must be a colon in the way.
                        let x = self.get(i);
                        if x == b':' {
                            err!(i, UnexpectedChar)
                        }
                        i += 1;
                    }
                }
            };

            // Save the state.
            let state = (self.bytes, self.pos);

            // The entire host is already read so the index is within bounds.
            self.bytes = &self.bytes[..host_end];
            // INVARIANT: It holds that `auth_start <= pos <= len`.
            // Here `pos` may decrease but will be restored later.
            self.pos = auth_start;

            let v4 = self.read_v4();
            let meta = match v4 {
                Some(_addr) if !self.has_remaining() => HostMeta::Ipv4(
                    #[cfg(feature = "net")]
                    _addr.into(),
                ),
                _ => HostMeta::RegName,
            };

            host = (auth_start, host_end, meta);

            // Restore the state.
            // INVARIANT: Restoring the state would not affect the invariants.
            (self.bytes, self.pos) = state;
        }

        self.out.auth_meta = Some(AuthMeta {
            start: start as _,
            host_bounds: (host.0 as _, host.1 as _),
            host_meta: host.2,
        });
        self.parse_from_path(PathKind::AbEmpty)
    }

    fn parse_from_path(&mut self, kind: PathKind) -> Result<()> {
        self.out.path_bounds = match kind {
            PathKind::General => {
                let start = self.pos;
                self.read(PATH)?;
                (start as _, self.pos as _)
            }
            PathKind::AbEmpty => {
                let start = self.pos;
                // Either empty or starting with '/'.
                if self.read(PATH)? && self.get(start) != b'/' {
                    err!(start, UnexpectedChar);
                }
                (start as _, self.pos as _)
            }
            PathKind::ContinuedNoScheme => {
                self.read(SEGMENT_NZ_NC)?;

                if self.peek(0) == Some(b':') {
                    // In a relative reference, the first path
                    // segment cannot contain a colon character.
                    err!(self.pos, UnexpectedChar);
                }

                self.read(PATH)?;
                (0, self.pos as _)
            }
        };

        if self.read_str("?") {
            self.read(QUERY)?;
            self.out.query_end = NonZeroU32::new(self.pos as _);
        }

        if self.read_str("#") {
            self.read(FRAGMENT)?;
        }

        if self.has_remaining() {
            err!(self.pos, UnexpectedChar);
        }
        Ok(())
    }
}
