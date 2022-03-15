use crate::{
    encoding::{table::*, EStr},
    Authority, Host, SyntaxError,
    SyntaxErrorKind::*,
    Uri,
};
use std::str;

type Result<T> = std::result::Result<T, SyntaxError>;

/// Returns immediately with a syntax error.
macro_rules! err {
    ($index:expr, $kind:expr) => {
        return Err(SyntaxError {
            index: $index,
            kind: $kind,
        })
    };
}

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

impl<'a> Parser<'a> {
    fn has_remaining(&self) -> bool {
        self.pos < self.buf.len()
    }

    fn remaining(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    fn peek(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
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
                if i + 2 >= s.len() {
                    err!(i, InvalidOctet);
                }
                let (hi, lo) = (s[i + 1], s[i + 2]);

                if !HEXDIG.contains(hi) || !HEXDIG.contains(lo) {
                    err!(i, InvalidOctet);
                }
                i += 2;
            } else {
                let v = table.get(x);
                if v == 0 {
                    break;
                }
                f(v);
            }
            i += 1;
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

        if self.peek() == Some(b':') {
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
        static TABLE: &Table = &USERINFO.shl(1).or(&gen(b":"));

        // The number of colons scanned.
        let mut colon_cnt = 0;

        self.mark();
        self.scan(TABLE, |v| {
            colon_cnt += (v & 1) as usize;
        })?;

        if self.peek() == Some(b'@') {
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
            out.host = parse_v4_or_reg_name(host);
            out.port = port;
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
        todo!()
    }

    fn read_v4_or_reg_name(&mut self) -> Result<Host<'a>> {
        self.read(REG_NAME).map(parse_v4_or_reg_name)
    }

    fn read_port(&mut self) -> Option<&'a str> {
        self.read_str(":").then(|| self.read_by(u8::is_ascii_digit))
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

                if self.peek() == Some(b':') {
                    // In a relative reference, the first path
                    // segment cannot contain a colon character.
                    err!(self.pos, UnexpectedChar);
                }

                self.scan(PATH, |_| ())?;
                self.marked()
            },
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

fn parse_v4_or_reg_name(s: &str) -> Host<'_> {
    match crate::ip::parse_v4(s.as_bytes()) {
        Some(addr) => Host::Ipv4(addr),
        // SAFETY: We have done the validation.
        None => Host::RegName(unsafe { EStr::new_unchecked(s) }),
    }
}
