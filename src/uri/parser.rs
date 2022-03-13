use crate::{encoding::table::*, SyntaxError, SyntaxErrorKind::*, Uri};
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
        start: 0,
        pos: 0,
        out: Uri::EMPTY,
    };
    parser.parse_from_scheme()?;
    Ok(parser.out)
}

struct Parser<'a> {
    buf: &'a [u8],
    start: usize,
    pos: usize,
    out: Uri<'a>,
}

impl<'a> Parser<'a> {
    fn has_remaining(&self) -> bool {
        self.pos < self.buf.len()
    }

    fn remaining(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    fn peek(&self) -> Option<u8> {
        self.remaining().first().copied()
    }

    fn skip(&mut self, i: usize) {
        debug_assert_eq!(self.start, self.pos);
        self.pos += i;
        self.start = self.pos;
    }

    fn scan(&mut self, table: &Table) -> Result<()> {
        if !self.has_remaining() {
            return Ok(());
        }
        let s = self.remaining();

        if !table.allow_enc() {
            let i = s
                .iter()
                .position(|&x| !table.contains(x))
                .unwrap_or(s.len());
            self.pos += i;
            return Ok(());
        }

        let mut i = 0;

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
            } else if !table.contains(x) {
                break;
            }
            i += 1;
        }

        self.pos += i;
        Ok(())
    }

    fn read_scanned(&mut self) -> &'a str {
        let res = unsafe { str::from_utf8_unchecked(&self.buf[self.start..self.pos]) };
        self.start = self.pos;
        res
    }

    fn read(&mut self, table: &Table) -> Result<&'a str> {
        self.scan(table)?;
        Ok(self.read_scanned())
    }

    fn scanned_len(&self) -> usize {
        self.pos - self.start
    }

    fn read_str(&mut self, s: &str) -> bool {
        let res = self.remaining().starts_with(s.as_bytes());
        if res {
            self.skip(s.len());
        }
        res
    }

    fn parse_from_scheme(&mut self) -> Result<()> {
        if !self.has_remaining() {
            return Ok(());
        }

        self.scan(SCHEME)?;

        if self.peek() == Some(b':') {
            let scheme = self.read_scanned();
            // Scheme starts with a letter.
            if matches!(scheme.bytes().next(), Some(x) if x.is_ascii_alphabetic()) {
                self.out.scheme = Some(scheme);
            } else {
                err!(0, UnexpectedChar);
            }

            self.skip(1);
            self.parse_from_authority()
        } else if self.scanned_len() == 0 {
            // Nothing scanned.
            self.parse_from_authority()
        } else {
            // Scheme chars are valid for path.
            self.parse_from_path()
        }
    }

    fn parse_from_authority(&mut self) -> Result<()> {
        if !self.read_str("//") {
            return self.parse_from_path();
        }

        todo!()
    }

    fn parse_from_path(&mut self) -> Result<()> {
        self.out.path = self.read(PATH)?;

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
