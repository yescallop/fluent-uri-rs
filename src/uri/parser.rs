use crate::{
    encoding::{err, table::*, EStr},
    Authority, Host, Result, SyntaxError,
    SyntaxErrorKind::*,
    Uri,
};
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    str,
};

pub(crate) fn parse(s: &[u8]) -> Result<Uri<'_>> {
    let mut parser = Parser {
        buf: s,
        pos: 0,
        mark: 0,
        out: Uri::EMPTY,
    };
    parser.parse_from_scheme()?;
    Ok(parser.out)
}

struct Parser<'a> {
    buf: &'a [u8],
    pos: usize,
    mark: usize,
    out: Uri<'a>,
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
    MaybeV4,
    // ":"
    SingleColon,
}

impl<'a> Parser<'a> {
    fn has_remaining(&self) -> bool {
        self.pos < self.buf.len()
    }

    fn remaining(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    fn peek(&self, i: usize) -> Option<u8> {
        self.buf.get(self.pos + i).copied()
    }

    fn skip(&mut self, n: usize) {
        self.pos += n;
    }

    fn mark(&mut self) {
        self.mark = self.pos;
    }

    fn scan(&mut self, table: &Table, mut f: impl FnMut(u8)) -> Result<()> {
        if !self.has_remaining() {
            return Ok(());
        }
        let s = self.buf;
        let mut i = self.pos;

        if !table.allow_enc() {
            while i < s.len() {
                if !table.contains(s[i]) {
                    break;
                }
                i += 1;
            }

            self.pos = i;
            return Ok(());
        }

        while i < s.len() {
            let x = s[i];
            if x == b'%' {
                match (s.get(i + 1), s.get(i + 2)) {
                    (Some(&hi), Some(&lo)) if HEXDIG.get(hi) & HEXDIG.get(lo) != 0 => (),
                    _ => err!(i, InvalidOctet),
                }
                i += 3;
            } else {
                let v = table.get(x);
                if v == 0 {
                    break;
                }
                f(v);
                i += 1;
            }
        }

        self.pos = i;
        Ok(())
    }

    fn marked_len(&self) -> usize {
        self.pos - self.mark
    }

    fn marked(&mut self) -> &'a str {
        unsafe { str::from_utf8_unchecked(&self.buf[self.mark..self.pos]) }
    }

    fn read(&mut self, table: &Table) -> Result<&'a str> {
        let start = self.pos;
        self.scan(table, |_| ())?;
        Ok(unsafe { str::from_utf8_unchecked(&self.buf[start..self.pos]) })
    }

    fn read_by(&mut self, good: impl Fn(&u8) -> bool) -> &'a str {
        let s = self.remaining();
        let n = s.iter().position(|x| !good(x)).unwrap_or(s.len());
        self.skip(n);
        unsafe { str::from_utf8_unchecked(&s[..n]) }
    }

    fn read_str(&mut self, s: &str) -> bool {
        let res = self.remaining().starts_with(s.as_bytes());
        if res {
            self.skip(s.len());
        }
        res
    }

    fn parse_from_scheme(&mut self) -> Result<()> {
        // Mark initially set to 0.
        self.scan(SCHEME, |_| ())?;

        if self.peek(0) == Some(b':') {
            let scheme = self.marked();
            // Scheme starts with a letter.
            if matches!(scheme.bytes().next(), Some(x) if x.is_ascii_alphabetic()) {
                self.out.scheme = Some(scheme);
            } else {
                err!(0, UnexpectedChar);
            }

            self.skip(1);
            self.parse_from_authority()
        } else if self.marked_len() == 0 {
            // Nothing scanned.
            self.parse_from_authority()
        } else {
            // Scheme chars are valid for path.
            self.parse_from_path(PathKind::ContinuedNoScheme)
        }
    }

    fn parse_from_authority(&mut self) -> Result<()> {
        if !self.read_str("//") {
            return self.parse_from_path(PathKind::General);
        }
        let mut out = Authority::EMPTY;

        // This table contains userinfo, reg-name, ":", and port.
        static TABLE: &Table = &USERINFO.shl(1).or(&Table::gen(b":"));

        // The number of colons scanned.
        let mut colon_cnt = 0;

        self.mark();
        self.scan(TABLE, |v| {
            colon_cnt += (v & 1) as usize;
        })?;

        if self.peek(0) == Some(b'@') {
            // Userinfo present.
            out.userinfo = Some(self.marked());
            self.skip(1);

            out.host = self.read_host()?;
            out.port = self.read_port();
        } else if self.marked_len() == 0 {
            // Nothing scanned. We're now at the start of an IP literal or the path.
            if let Some(host) = self.read_ip_literal()? {
                out.host = host;
                out.port = self.read_port();
            }
        } else {
            // The whole authority scanned. Try to parse the host and port.
            let (host, port) = match colon_cnt {
                // All host.
                0 => (self.marked(), None),
                // Host and port.
                1 => {
                    let s = self.marked();

                    let mut i = s.len() - 1;
                    loop {
                        let x = s.as_bytes()[i];
                        if !x.is_ascii_digit() {
                            if x == b':' {
                                break;
                            } else {
                                err!(self.mark + i, UnexpectedChar);
                            }
                        }
                        i -= 1;
                    }

                    // SAFETY: Splitting at an ASCII char is fine.
                    unsafe { (s.get_unchecked(..i), Some(s.get_unchecked(i + 1..))) }
                }
                // Multiple colons.
                _ => {
                    let mut i = self.mark;
                    loop {
                        let x = self.buf[i];
                        if x == b':' {
                            err!(i, UnexpectedChar)
                        }
                        i += 1;
                    }
                }
            };

            // Save the state.
            let state = (self.buf, self.pos);

            self.buf = &self.buf[..self.mark + host.len()];
            self.pos = self.mark;

            let v4 = self.scan_v4();

            out.host = match v4 {
                Some(addr) if !self.has_remaining() => Host::Ipv4(addr),
                // SAFETY: We have done the validation.
                _ => Host::RegName(unsafe { EStr::new_unchecked(host) }),
            };
            out.port = port;

            // Restore the state.
            (self.buf, self.pos) = state;
        }

        self.out.authority = Some(out);
        self.parse_from_path(PathKind::AbEmpty)
    }

    fn read_host(&mut self) -> Result<Host<'a>> {
        match self.read_ip_literal()? {
            Some(host) => Ok(host),
            None => self.read_v4_or_reg_name(),
        }
    }

    fn read_ip_literal(&mut self) -> Result<Option<Host<'a>>> {
        if !self.read_str("[") {
            return Ok(None);
        }
        self.mark();

        let host = if let Some(addr) = self.scan_v6() {
            Host::Ipv6 {
                addr,
                zone_id: self.read_zone_id()?,
            }
        } else if self.marked_len() == 0 {
            self.read_ipv_future()?
        } else {
            err!(self.mark - 1, InvalidIpLiteral);
        };

        if !self.read_str("]") {
            err!(self.mark - 1, InvalidIpLiteral);
        }
        Ok(Some(host))
    }

    fn scan_v6(&mut self) -> Option<Ipv6Addr> {
        let mut segs = [0; 8];
        let mut ellipsis_i = 8;

        let mut i = 0;
        while i < 8 {
            match self.scan_v6_segment() {
                Some(Seg::Normal(seg, colon)) => {
                    if colon == (i == 0 || i == ellipsis_i) {
                        // Preceding colon, triple colons or no colon.
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
                Some(Seg::MaybeV4) => {
                    if i > 6 {
                        // Not enough space.
                        return None;
                    }
                    let octets = self.scan_v4()?.octets();
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

        Some(segs.into())
    }

    fn scan_v6_segment(&mut self) -> Option<Seg> {
        let colon = self.read_str(":");
        if !self.has_remaining() {
            return if colon { Some(Seg::SingleColon) } else { None };
        }

        use crate::encoding::imp::OCTET_TABLE_LO as HEX_TABLE;

        let first = self.peek(0).unwrap();
        let mut x = match HEX_TABLE[first as usize] {
            v if v < 128 => v as u16,
            _ => {
                return if colon {
                    if first == b':' {
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
                match HEX_TABLE[b as usize] {
                    v if v < 128 => {
                        x = (x << 4) | v as u16;
                        i += 1;
                        continue;
                    }
                    _ if b == b'.' => return Some(Seg::MaybeV4),
                    _ => break,
                }
            } else {
                self.skip(i);
                return None;
            }
        }
        self.skip(i);
        Some(Seg::Normal(x, colon))
    }

    fn read_zone_id(&mut self) -> Result<Option<&'a EStr>> {
        if !self.read_str("%25") {
            return Ok(None);
        }
        let res = self.read(ZONE_ID)?;
        if res.is_empty() {
            err!(self.mark - 1, InvalidIpLiteral);
        } else {
            // SAFETY: We have done the validation.
            Ok(Some(unsafe { EStr::new_unchecked(res) }))
        }
    }

    fn read_v4_or_reg_name(&mut self) -> Result<Host<'a>> {
        self.mark();
        let v4 = self.scan_v4();
        let v4_end = self.pos;
        self.scan(REG_NAME, |_| ())?;

        Ok(match v4 {
            Some(addr) if self.pos == v4_end => Host::Ipv4(addr),
            // SAFETY: We have done the validation.
            _ => Host::RegName(unsafe { EStr::new_unchecked(self.marked()) }),
        })
    }

    fn scan_v4(&mut self) -> Option<Ipv4Addr> {
        let mut res = self.scan_v4_octet()? << 24;
        for i in (0..3).rev() {
            if !self.read_str(".") {
                return None;
            }
            res |= self.scan_v4_octet()? << (i * 8);
        }
        Some(Ipv4Addr::from(res))
    }

    fn scan_v4_octet(&mut self) -> Option<u32> {
        let mut res = self.peek_digit(0)?;
        if res == 0 {
            self.skip(1);
            return Some(0);
        }

        for i in 1..3 {
            match self.peek_digit(i) {
                Some(x) => res = res * 10 + x,
                None => {
                    self.skip(i);
                    return Some(res);
                }
            }
        }
        self.skip(3);

        if res <= u8::MAX as u32 {
            Some(res)
        } else {
            None
        }
    }

    fn peek_digit(&self, i: usize) -> Option<u32> {
        self.peek(i).and_then(|x| (x as char).to_digit(10))
    }

    fn read_port(&mut self) -> Option<&'a str> {
        self.read_str(":").then(|| self.read_by(u8::is_ascii_digit))
    }

    #[cold]
    #[inline(never)]
    fn read_ipv_future(&mut self) -> Result<Host<'a>> {
        if matches!(self.peek(0), Some(b'v' | b'V')) {
            self.skip(1);
            let ver = self.read(HEXDIG)?;
            if !ver.is_empty() && self.read_str(".") {
                let addr = self.read(IPV_FUTURE)?;
                if !addr.is_empty() {
                    return Ok(Host::IpvFuture { ver, addr });
                }
            }
        }
        err!(self.mark - 1, InvalidIpLiteral);
    }

    fn parse_from_path(&mut self, kind: PathKind) -> Result<()> {
        self.out.path = match kind {
            PathKind::General => self.read(PATH)?,
            PathKind::AbEmpty => {
                let s = self.read(PATH)?;
                if s.is_empty() || s.starts_with('/') {
                    s
                } else {
                    err!(self.pos - s.len(), UnexpectedChar);
                }
            }
            PathKind::ContinuedNoScheme => {
                self.scan(SEGMENT_NC, |_| ())?;

                if self.peek(0) == Some(b':') {
                    // In a relative reference, the first path
                    // segment cannot contain a colon character.
                    err!(self.pos, UnexpectedChar);
                }

                self.scan(PATH, |_| ())?;
                self.marked()
            }
        };

        if self.read_str("?") {
            self.out.query = Some(self.read(QUERY_FRAGMENT)?);
        }

        if self.read_str("#") {
            self.out.fragment = Some(self.read(QUERY_FRAGMENT)?);
        }

        if self.has_remaining() {
            err!(self.pos, UnexpectedChar);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_v4(s: &str) -> Option<Ipv4Addr> {
        let s = format!("//{}", s);
        match parse(s.as_bytes()).ok()?.authority()?.host() {
            &Host::Ipv4(addr) => Some(addr),
            _ => None,
        }
    }

    fn parse_v6(s: &str) -> Option<Ipv6Addr> {
        let s = format!("//[{}]", s);
        match parse(s.as_bytes()).ok()?.authority()?.host() {
            &Host::Ipv6 { addr, .. } => Some(addr),
            _ => None,
        }
    }

    #[test]
    fn test_parse_v4() {
        assert_eq!(Some(Ipv4Addr::new(127, 0, 0, 1)), parse_v4("127.0.0.1"));
        assert_eq!(
            Some(Ipv4Addr::new(255, 255, 255, 255)),
            parse_v4("255.255.255.255")
        );
        assert_eq!(Some(Ipv4Addr::new(0, 0, 0, 0)), parse_v4("0.0.0.0"));

        // out of range
        assert!(parse_v4("256.0.0.1").is_none());
        // too short
        assert!(parse_v4("255.0.0").is_none());
        // too long
        assert!(parse_v4("255.0.0.1.2").is_none());
        // no number between dots
        assert!(parse_v4("255.0..1").is_none());
        // octal
        assert!(parse_v4("255.0.0.01").is_none());
        // octal zero
        assert!(parse_v4("255.0.0.00").is_none());
        assert!(parse_v4("255.0.00.0").is_none());
        // preceding dot
        assert!(parse_v4(".0.0.0.0").is_none());
        // trailing dot
        assert!(parse_v4("0.0.0.0.").is_none());
    }

    #[test]
    fn test_parse_v6() {
        assert_eq!(
            Some(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
            parse_v6("0:0:0:0:0:0:0:0")
        );
        assert_eq!(
            Some(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8)),
            parse_v6("1:02:003:0004:0005:006:07:8")
        );

        assert_eq!(Some(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), parse_v6("::1"));
        assert_eq!(Some(Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 0)), parse_v6("1::"));
        assert_eq!(Some(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)), parse_v6("::"));

        assert_eq!(
            Some(Ipv6Addr::new(0x2a02, 0x6b8, 0, 0, 0, 0, 0x11, 0x11)),
            parse_v6("2a02:6b8::11:11")
        );

        assert_eq!(
            Some(Ipv6Addr::new(0, 2, 3, 4, 5, 6, 7, 8)),
            parse_v6("::2:3:4:5:6:7:8")
        );
        assert_eq!(
            Some(Ipv6Addr::new(1, 2, 3, 4, 0, 6, 7, 8)),
            parse_v6("1:2:3:4::6:7:8")
        );
        assert_eq!(
            Some(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 0)),
            parse_v6("1:2:3:4:5:6:7::")
        );

        // only a colon
        assert!(parse_v6(":").is_none());
        // too long group
        assert!(parse_v6("::00000").is_none());
        // too short
        assert!(parse_v6("1:2:3:4:5:6:7").is_none());
        // too long
        assert!(parse_v6("1:2:3:4:5:6:7:8:9").is_none());
        // triple colon
        assert!(parse_v6("1:2:::6:7:8").is_none());
        assert!(parse_v6("1:2:::").is_none());
        assert!(parse_v6(":::6:7:8").is_none());
        assert!(parse_v6(":::").is_none());
        // two double colons
        assert!(parse_v6("1:2::6::8").is_none());
        assert!(parse_v6("::6::8").is_none());
        assert!(parse_v6("1:2::6::").is_none());
        assert!(parse_v6("::2:6::").is_none());
        // `::` indicating zero groups of zeros
        assert!(parse_v6("::1:2:3:4:5:6:7:8").is_none());
        assert!(parse_v6("1:2:3:4::5:6:7:8").is_none());
        assert!(parse_v6("1:2:3:4:5:6:7:8::").is_none());
        // preceding colon
        assert!(parse_v6(":1:2:3:4:5:6:7:8").is_none());
        assert!(parse_v6(":1::1").is_none());
        assert!(parse_v6(":1").is_none());
        // trailing colon
        assert!(parse_v6("1:2:3:4:5:6:7:8:").is_none());
        assert!(parse_v6("1::1:").is_none());
        assert!(parse_v6("1:").is_none());
    }

    #[test]
    fn test_parse_v4_in_v6() {
        assert_eq!(
            Some(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 49152, 545)),
            parse_v6("::192.0.2.33")
        );
        assert_eq!(
            Some(Ipv6Addr::new(0, 0, 0, 0, 0, 0xFFFF, 49152, 545)),
            parse_v6("::FFFF:192.0.2.33")
        );
        assert_eq!(
            Some(Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 49152, 545)),
            parse_v6("64:ff9b::192.0.2.33")
        );
        assert_eq!(
            Some(Ipv6Addr::new(
                0x2001, 0xdb8, 0x122, 0xc000, 0x2, 0x2100, 49152, 545
            )),
            parse_v6("2001:db8:122:c000:2:2100:192.0.2.33")
        );

        // colon after v4
        assert!(parse_v6("::127.0.0.1:").is_none());
        // not enough groups
        assert!(parse_v6("1:2:3:4:5:127.0.0.1").is_none());
        // too many groups
        assert!(parse_v6("1:2:3:4:5:6:7:127.0.0.1").is_none());
    }
}
