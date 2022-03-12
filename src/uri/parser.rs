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
        state: s,
        start: 0,
        pos: 0,
        out: Uri::EMPTY,
    };
    parser.parse_from_scheme()?;
    Ok(parser.out)
}

struct Parser<'a> {
    state: &'a [u8],
    start: usize,
    pos: usize,
    out: Uri<'a>,
}

impl<'a> Parser<'a> {
    fn scan(&mut self, table: &Table) -> Result<()> {
        let s = &self.state[self.pos..];
        if s.is_empty() {
            return Ok(());
        }

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
        let res = unsafe { str::from_utf8_unchecked(&self.state[self.start..self.pos]) };
        self.start = self.pos;
        res
    }

    fn scan_and_read(&mut self, table: &Table) -> Result<&'a str> {
        self.scan(table)?;
        Ok(self.read_scanned())
    }

    fn scanned_len(&self) -> usize {
        self.pos - self.start
    }

    fn skip(&mut self, i: usize) {
        debug_assert_eq!(self.start, self.pos);
        self.start += i;
        self.pos = self.start;
    }

    fn remaining(&self) -> &'a [u8] {
        &self.state[self.pos..]
    }

    fn peek(&self) -> Option<u8> {
        self.remaining().get(0).copied()
    }

    fn parse_from_scheme(&mut self) -> Result<()> {
        if self.state.is_empty() {
            return Ok(());
        }

        self.scan(SCHEME)?;

        if self.peek() == Some(b':') {
            let scheme = self.read_scanned();
            // Scheme starts with a letter.
            if matches!(scheme.bytes().next(), Some(x) if !x.is_ascii_alphabetic()) {
                err!(0, UnexpectedChar);
            } else {
                self.out.scheme = Some(scheme);
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
        if !self.remaining().starts_with(b"//") {
            return self.parse_from_path();
        }

        todo!()
    }

    fn parse_from_path(&mut self) -> Result<()> {
        self.out.path = self.scan_and_read(PATH)?;

        match self.peek() {
            Some(b'?') => self.parse_from_query(),
            Some(b'#') => self.parse_from_fragment(),
            None => Ok(()),
            _ => err!(self.pos, UnexpectedChar),
        }
    }

    fn parse_from_query(&mut self) -> Result<()> {
        self.skip(1);
        self.out.query = Some(self.scan_and_read(QUERY_FRAGMENT)?);

        match self.peek() {
            Some(b'#') => self.parse_from_fragment(),
            None => Ok(()),
            _ => err!(self.pos, UnexpectedChar),
        }
    }

    fn parse_from_fragment(&mut self) -> Result<()> {
        self.skip(1);
        self.out.fragment = Some(self.scan_and_read(QUERY_FRAGMENT)?);

        if self.peek().is_some() {
            err!(self.pos, UnexpectedChar);
        }
        Ok(())
    }
}
