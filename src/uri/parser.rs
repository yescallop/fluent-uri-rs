use crate::{
    encoding::{err, table::*, OCTET_TABLE_LO},
    uri::{HostData, HostTag},
    Result, Uri,
};
use std::{
    marker::PhantomData,
    net::{Ipv4Addr, Ipv6Addr},
    num::NonZeroU32,
    ptr::NonNull,
    str, mem,
};

use super::HostInternal;

pub(crate) unsafe fn parse<T>(ptr: *mut u8, len: u32, cap: u32) -> Result<Uri<T>> {
    let mut parser = Parser {
        out: Uri {
            ptr: NonNull::new(ptr).unwrap(),
            cap,
            len,
            scheme_end: None,
            host: None,
            path: (0, 0),
            query_end: None,
            fragment_start: None,
            _marker: PhantomData,
        },
        pos: 0,
        mark: 0,
    };
    parser.parse_from_scheme()?;
    // SAFETY: `Uri` has a fixed layout.
    Ok(unsafe { mem::transmute(parser.out) })
}

/// URI parser.
///
/// The invariant holds that `mark <= pos <= len`,
/// where `pos` is non-decreasing and `bytes[..pos]` is valid UTF-8.
struct Parser {
    // Not generic to avoid code bloat.
    out: Uri<()>,
    pos: u32,
    mark: u32,
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

impl Parser {
    fn has_remaining(&self) -> bool {
        self.pos < self.out.len
    }

    unsafe fn get_unchecked(&self, i: u32) -> u8 {
        debug_assert!(i < self.out.len, "index out of bounds");
        // SAFETY: The caller must ensure that the index is within bounds.
        unsafe { *self.out.ptr.as_ptr().add(i as usize) }
    }

    fn get(&self, i: u32) -> u8 {
        assert!(i < self.out.len, "index out of bounds");
        // SAFETY: We have checked that `i < len`.
        unsafe { self.get_unchecked(i) }
    }

    fn peek(&self, i: u32) -> Option<u8> {
        (self.pos + i < self.out.len).then(|| self.get(self.pos + i))
    }

    // Any call to this function must keep the invariant.
    fn skip(&mut self, n: u32) {
        // INVARIANT: `pos` is non-decreasing.
        self.pos += n;
        debug_assert!(self.pos <= self.out.len);
    }

    fn mark(&mut self) {
        // INVARIANT: It holds that `mark <= pos`.
        self.mark = self.pos;
    }

    fn marked_len(&self) -> u32 {
        self.pos - self.mark
    }

    fn scan(&mut self, table: &Table) -> Result<()> {
        if table.allows_enc() {
            self.scan_enc(table, |_| ())
        } else {
            let mut i = self.pos;
            while i < self.out.len {
                if !table.allows(self.get(i)) {
                    break;
                }
                // INVARIANT: Since `i < len`, it holds that `i + 1 <= len`.
                i += 1;
            }
            // INVARIANT: `i` is non-decreasing and all bytes scanned are ASCII.
            self.pos = i;
            Ok(())
        }
    }

    fn scan_enc(&mut self, table: &Table, mut f: impl FnMut(u8)) -> Result<()> {
        let mut i = self.pos;

        while i < self.out.len {
            let x = self.get(i);
            if x == b'%' {
                if i + 2 >= self.out.len {
                    err!(i, InvalidOctet);
                }
                // SAFETY: We have checked that `i + 2 < len`.
                // Overflow is impossible since `len` is no larger than `i32::MAX`.
                let (hi, lo) = unsafe { (self.get_unchecked(i + 1), self.get_unchecked(i + 2)) };

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

        // INVARIANT: `i` is non-decreasing and all bytes scanned are ASCII.
        self.pos = i;
        Ok(())
    }

    // Returns `true` if any byte is read.
    fn read(&mut self, table: &Table) -> Result<bool> {
        let start = self.pos;
        self.scan(table)?;
        Ok(self.pos != start)
    }

    fn read_str(&mut self, s: &str) -> bool {
        assert!(s.len() <= i32::MAX as usize);
        let len = s.len() as u32;

        // SAFETY: We have checked that `pos + s.len() <= len`.
        // Overflow is impossible since both `len` and `s.len()` are no larger than `i32::MAX`.
        let res = self.pos + len <= self.out.len
            && (0..len)
                .all(|i| unsafe { self.get_unchecked(self.pos + i) } == s.as_bytes()[i as usize]);
        if res {
            // INVARIANT: The remaining bytes start with `s` so it's fine to skip `s.len()`.
            self.skip(len);
        }
        res
    }

    fn parse_from_scheme(&mut self) -> Result<()> {
        // Mark initially set to 0.
        self.scan(SCHEME)?;

        if self.peek(0) == Some(b':') {
            // Scheme starts with a letter.
            if self.pos != 0 && self.get(0).is_ascii_alphabetic() {
                self.out.scheme_end = NonZeroU32::new(self.pos + 1);
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
        } else if self.marked_len() == 0 {
            // Nothing scanned.
            if self.read_str("//") {
                return self.parse_from_authority();
            }
        }
        // Scheme chars are valid for path.
        self.parse_from_path(PathKind::ContinuedNoScheme)
    }

    fn parse_from_authority(&mut self) -> Result<()> {
        let host_out;

        // This table contains userinfo, reg-name, ":", and port.
        static TABLE: &Table = &USERINFO.shl(1).or(&Table::gen(b":"));

        // The number of colons scanned.
        let mut colon_cnt = 0;

        self.mark();
        self.scan_enc(TABLE, |v| {
            colon_cnt += (v & 1) as u32;
        })?;

        if self.peek(0) == Some(b'@') {
            // Userinfo present.
            // INVARIANT: Skipping "@" is fine.
            self.skip(1);

            self.mark();

            let mut host = self.read_host()?;
            host.tag |= HostTag::HAS_USERINFO;

            host_out = (self.mark, self.pos, host);
            self.read_port();
        } else if self.marked_len() == 0 {
            // Nothing scanned. We're now at the start of an IP literal or the path.
            if let Some(host) = self.read_ip_literal()? {
                host_out = (self.mark, self.pos, host);
                self.read_port();
            } else {
                // Empty authority.
                host_out = (
                    self.pos,
                    self.pos,
                    HostInternal {
                        tag: HostTag::REG_NAME,
                        data: HostData { reg_name: () },
                    },
                );
            }
        } else {
            // The whole authority scanned. Try to parse the host and port.
            let host_end = match colon_cnt {
                // All host.
                0 => self.pos,
                // Host and port.
                1 => {
                    let mut i = self.pos - 1;
                    loop {
                        // SAFETY: There must be a colon in the way.
                        let x = unsafe { self.get_unchecked(i) };
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
                    let mut i = self.mark;
                    loop {
                        // SAFETY: There must be a colon in the way.
                        let x = unsafe { self.get_unchecked(i) };
                        if x == b':' {
                            err!(i, UnexpectedChar)
                        }
                        i += 1;
                    }
                }
            };

            // Save the state.
            let state = (self.out.len, self.pos);

            // The entire host is already scanned so the index is within bounds.
            self.out.len = host_end;
            // INVARIANT: It holds that `mark <= pos <= buf.len()`.
            // Here `pos` may decrease but will be restored later.
            self.pos = self.mark;

            let v4 = self.scan_v4();

            host_out = (
                self.mark,
                host_end,
                match v4 {
                    Some(addr) if !self.has_remaining() => HostInternal {
                        tag: HostTag::IPV4,
                        data: HostData { ipv4_addr: addr },
                    },
                    _ => HostInternal {
                        tag: HostTag::REG_NAME,
                        data: HostData { reg_name: () },
                    },
                },
            );

            // Restore the state.
            // INVARIANT: Restoring the state would not affect the invariant.
            (self.out.len, self.pos) = state;
        }

        // SAFETY: Host won't start at index 0.
        let host_start = unsafe { NonZeroU32::new_unchecked(host_out.0) };
        self.out.host = Some((host_start, host_out.1, host_out.2));
        self.parse_from_path(PathKind::AbEmpty)
    }

    // The marked length must be zero when this function is called.
    fn read_host(&mut self) -> Result<HostInternal> {
        match self.read_ip_literal()? {
            Some(host) => Ok(host),
            None => self.read_v4_or_reg_name(),
        }
    }

    // The marked length must be zero when this function is called.
    fn read_ip_literal(&mut self) -> Result<Option<HostInternal>> {
        if !self.read_str("[") {
            return Ok(None);
        }

        let host = if let Some(addr) = self.scan_v6() {
            HostInternal {
                tag: HostTag::IPV6,
                data: HostData { ipv6_addr: addr },
            }
        } else {
            #[cfg(feature = "ipv_future")]
            if self.marked_len() == 1 {
                self.read_ipv_future()?
            } else {
                err!(self.mark, InvalidIpLiteral);
            }
            #[cfg(not(feature = "ipv_future"))]
            err!(self.mark, InvalidIpLiteral);
        };

        if !self.read_str("]") {
            err!(self.mark, InvalidIpLiteral);
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
                Some(Seg::MaybeV4(colon)) => {
                    if i > 6 || colon == (i == ellipsis_i) {
                        // Not enough space, triple colons, or no colon.
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

    #[allow(unused)]
    fn read_zone_id(&mut self) -> Result<()> {
        if self.read_str("%25") && !self.read(ZONE_ID)? {
            err!(self.mark, InvalidIpLiteral);
        }
        Ok(())
    }

    // The marked length must be zero when this function is called.
    fn read_v4_or_reg_name(&mut self) -> Result<HostInternal> {
        let v4 = self.scan_v4();
        let v4_end = self.pos;
        self.scan(REG_NAME)?;

        Ok(match v4 {
            Some(addr) if self.pos == v4_end => HostInternal {
                tag: HostTag::IPV4,
                data: HostData { ipv4_addr: addr },
            },
            _ => HostInternal {
                tag: HostTag::REG_NAME,
                data: HostData { reg_name: () },
            },
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

        if res <= u8::MAX as u32 {
            Some(res)
        } else {
            None
        }
    }

    fn peek_digit(&self, i: u32) -> Option<u32> {
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

    #[cfg(feature = "ipv_future")]
    fn read_ipv_future(&mut self) -> Result<HostInternal> {
        if matches!(self.peek(0), Some(b'v' | b'V')) {
            // INVARIANT: Skipping "v" or "V" is fine.
            self.skip(1);
            let ver_read = self.read(HEXDIG)?;
            let dot_i = self.pos;
            if ver_read && self.read_str(".") && self.read(IPV_FUTURE)? {
                return Ok(HostInternal {
                    tag: HostTag::empty(),
                    data: HostData {
                        ipv_future_dot_i: dot_i,
                    },
                });
            }
        }
        err!(self.mark, InvalidIpLiteral);
    }

    fn parse_from_path(&mut self, kind: PathKind) -> Result<()> {
        self.out.path = match kind {
            PathKind::General => {
                let start = self.pos;
                self.read(PATH)?;
                (start, self.pos)
            }
            PathKind::AbEmpty => {
                let start = self.pos;
                // Either empty or starting with "/".
                if self.read(PATH)? && self.get(start) != b'/' {
                    err!(start, UnexpectedChar);
                }
                (start, self.pos)
            }
            PathKind::ContinuedNoScheme => {
                self.scan(SEGMENT_NC)?;

                if self.peek(0) == Some(b':') {
                    // In a relative reference, the first path
                    // segment cannot contain a colon character.
                    err!(self.pos, UnexpectedChar);
                }

                self.scan(PATH)?;
                (self.mark, self.pos)
            }
        };

        if self.read_str("?") {
            self.read(QUERY_FRAGMENT)?;
            self.out.query_end = NonZeroU32::new(self.pos);
        }

        if self.read_str("#") {
            self.out.fragment_start = NonZeroU32::new(self.pos);
            self.read(QUERY_FRAGMENT)?;
        }

        if self.has_remaining() {
            err!(self.pos, UnexpectedChar);
        }
        Ok(())
    }
}
