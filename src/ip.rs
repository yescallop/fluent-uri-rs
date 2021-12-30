use std::net::{Ipv4Addr, Ipv6Addr};

macro_rules! take_byte {
    ($s:ident) => {
        if $s.is_empty() {
            None
        } else {
            let byte = $s[0];
            $s = &$s[1..];
            Some(byte)
        }
    };
}

// dec-octet = DIGIT             ; 0-9
//           / %x31-39 DIGIT     ; 10-99
//           / "1" 2DIGIT        ; 100-199
//           / "2" %x30-34 DIGIT ; 200-249
//           / "25" %x30-35      ; 250-255
macro_rules! take_dec_octet {
    ($s:ident, $end:pat) => {
        match take_byte!($s) {
            Some(b'0') => match take_byte!($s) {
                $end => Some(0),
                _ => None,
            },
            Some(b'1') => match take_byte!($s) {
                $end => Some(1),
                Some(y @ b'0'..=b'9') => match take_byte!($s) {
                    $end => Some(10 + y - b'0'),
                    Some(z @ b'0'..=b'9') => match take_byte!($s) {
                        $end => Some(100 + (y - b'0') * 10 + z - b'0'),
                        _ => None,
                    },
                    _ => None,
                },
                _ => None,
            },
            Some(b'2') => match take_byte!($s) {
                $end => Some(2),
                Some(y @ b'0'..=b'4') => match take_byte!($s) {
                    $end => Some(20 + y - b'0'),
                    Some(z @ b'0'..=b'9') => match take_byte!($s) {
                        $end => Some(200 + (y - b'0') * 10 + z - b'0'),
                        _ => None,
                    },
                    _ => None,
                },
                Some(b'5') => match take_byte!($s) {
                    $end => Some(25),
                    Some(z @ b'0'..=b'5') => match take_byte!($s) {
                        $end => Some(250 + z - b'0'),
                        _ => None,
                    },
                    _ => None,
                },
                Some(y @ b'6'..=b'9') => match take_byte!($s) {
                    $end => Some(20 + y - b'0'),
                    _ => None,
                },
                _ => None,
            },
            Some(x @ b'3'..=b'9') => match take_byte!($s) {
                $end => Some(x - b'0'),
                Some(y @ b'0'..=b'9') => match take_byte!($s) {
                    $end => Some((x - b'0') * 10 + y - b'0'),
                    _ => None,
                },
                _ => None,
            },
            _ => None,
        }
    };
}

/// Parses an IPv4 address from a string slice.
#[inline]
pub fn parse_v4(s: &[u8]) -> Option<Ipv4Addr> {
    // `Ipv4Addr::from_str` now rejects octal zeros, but still
    // we can't use it here as there are backward compatibility issues.
    // Also it isn't fast enough.
    //
    // See: https://github.com/rust-lang/rust/pull/86984
    parse_v4_bytes(s).map(Ipv4Addr::from)
}

fn parse_v4_bytes(mut s: &[u8]) -> Option<[u8; 4]> {
    if s.len() < 7 {
        None
    } else {
        Some([
            take_dec_octet!(s, Some(b'.'))?,
            take_dec_octet!(s, Some(b'.'))?,
            take_dec_octet!(s, Some(b'.'))?,
            #[allow(unused_assignments)]
            take_dec_octet!(s, None)?,
        ])
    }
}

/// Parses an IPv6 address from a string slice.
pub fn parse_v6(mut s: &[u8]) -> Option<Ipv6Addr> {
    if s.len() < 2 {
        return None;
    }

    let mut segs = [0u16; 8];
    let mut ellipsis_i = 8;

    let mut i = 0;
    while i < 8 {
        match take_segment(&mut s) {
            Some(Seg::Normal(seg)) => {
                if i == 7 {
                    // Trailing colon or too long
                    return None;
                }
                segs[i] = seg;
                i += 1;
            }
            Some(Seg::End(seg)) => {
                segs[i] = seg;
                i += 1;
                break;
            }
            Some(Seg::Colon { double }) => {
                // Multiple ellipses or too many colons in one ellipsis
                if ellipsis_i != 8 || (double && i != 0) {
                    return None;
                }
                ellipsis_i = i;
            }
            Some(Seg::MaybeV4) => {
                if i > 6 {
                    // Not enough space
                    return None;
                }
                let bytes = parse_v4_bytes(s)?;

                segs[i] = u16::from_be_bytes([bytes[0], bytes[1]]);
                segs[i + 1] = u16::from_be_bytes([bytes[2], bytes[3]]);

                i += 2;
                break;
            }
            Some(Seg::Invalid) => return None,
            None => break,
        }
    }

    if ellipsis_i == 8 {
        // No ellipsis
        if i != 8 {
            // Too short
            return None;
        }
    } else if i == 8 {
        // Eliding nothing
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

use crate::encoding::raw::OCTET_LO as HEX_TABLE;

fn take_segment(s: &mut &[u8]) -> Option<Seg> {
    if s.is_empty() {
        return None;
    }

    if s[0] == b':' {
        return Some(match s.get(1) {
            Some(b':') => {
                *s = &s[2..];
                Seg::Colon { double: true }
            }
            // `None` for cases such as "1::".
            _ => {
                *s = &s[1..];
                Seg::Colon { double: false }
            }
        });
    }

    let mut x = match HEX_TABLE[s[0] as usize] {
        n if n < 128 => n as u16,
        _ => return Some(Seg::Invalid),
    };
    let mut i = 1;

    while i < 5 {
        return Some(match s.get(i) {
            Some(b':') => {
                *s = &s[i + 1..];
                Seg::Normal(x)
            }
            Some(b'.') => Seg::MaybeV4,
            Some(&b) => match HEX_TABLE[b as usize] {
                n if n < 128 => {
                    x = (x << 4) | n as u16;
                    i += 1;
                    continue;
                }
                _ => Seg::Invalid,
            },
            None => Seg::End(x),
        });
    }
    // i == 5
    Some(Seg::Invalid)
}

enum Seg {
    // [0-9A-Fa-f]{1,4}:
    Normal(u16),
    // [0-9A-Fa-f]{1,4}$
    End(u16),
    // :{1,2}
    Colon { double: bool },
    // [0-9A-Fa-f]{1,4}\.
    MaybeV4,
    Invalid,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_take_dec_octet() {
        for i in 0..=u8::MAX {
            let s = i.to_string();
            let mut s = s.as_bytes();
            assert_eq!(Some(i), take_dec_octet!(s, None));
            assert!(s.is_empty());
        }

        let mut s: &[u8] = b"255.";
        assert!(take_dec_octet!(s, None).is_none());
        assert!(s.is_empty());
        s = b"255.";
        assert_eq!(Some(255), take_dec_octet!(s, Some(b'.')));
        assert!(s.is_empty());
        s = b"256";
        assert!(take_dec_octet!(s, None).is_none());
        assert!(s.is_empty());
    }

    #[test]
    fn test_parse_v4() {
        assert_eq!(Some(Ipv4Addr::new(127, 0, 0, 1)), parse_v4(b"127.0.0.1"));
        assert_eq!(
            Some(Ipv4Addr::new(255, 255, 255, 255)),
            parse_v4(b"255.255.255.255")
        );
        assert_eq!(Some(Ipv4Addr::new(0, 0, 0, 0)), parse_v4(b"0.0.0.0"));

        // out of range
        assert!(parse_v4(b"256.0.0.1").is_none());
        // too short
        assert!(parse_v4(b"255.0.0").is_none());
        // too long
        assert!(parse_v4(b"255.0.0.1.2").is_none());
        // no number between dots
        assert!(parse_v4(b"255.0..1").is_none());
        // octal
        assert!(parse_v4(b"255.0.0.01").is_none());
        // octal zero
        assert!(parse_v4(b"255.0.0.00").is_none());
        assert!(parse_v4(b"255.0.00.0").is_none());
        // preceding dot
        assert!(parse_v4(b".0.0.0.0").is_none());
        // trailing dot
        assert!(parse_v4(b"0.0.0.0.").is_none());
    }

    #[test]
    fn test_parse_v6() {
        assert_eq!(
            Some(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
            parse_v6(b"0:0:0:0:0:0:0:0")
        );
        assert_eq!(
            Some(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8)),
            parse_v6(b"1:02:003:0004:0005:006:07:8")
        );

        assert_eq!(
            Some(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            parse_v6(b"::1")
        );
        assert_eq!(
            Some(Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0, 0)),
            parse_v6(b"1::")
        );
        assert_eq!(Some(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)), parse_v6(b"::"));

        assert_eq!(
            Some(Ipv6Addr::new(0x2a02, 0x6b8, 0, 0, 0, 0, 0x11, 0x11)),
            parse_v6(b"2a02:6b8::11:11")
        );

        assert_eq!(
            Some(Ipv6Addr::new(0, 2, 3, 4, 5, 6, 7, 8)),
            parse_v6(b"::2:3:4:5:6:7:8")
        );
        assert_eq!(
            Some(Ipv6Addr::new(1, 2, 3, 4, 0, 6, 7, 8)),
            parse_v6(b"1:2:3:4::6:7:8")
        );
        assert_eq!(
            Some(Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 0)),
            parse_v6(b"1:2:3:4:5:6:7::")
        );

        // only a colon
        assert!(parse_v6(b":").is_none());
        // too long group
        assert!(parse_v6(b"::00000").is_none());
        // too short
        assert!(parse_v6(b"1:2:3:4:5:6:7").is_none());
        // too long
        assert!(parse_v6(b"1:2:3:4:5:6:7:8:9").is_none());
        // triple colon
        assert!(parse_v6(b"1:2:::6:7:8").is_none());
        assert!(parse_v6(b"1:2:::").is_none());
        assert!(parse_v6(b":::6:7:8").is_none());
        assert!(parse_v6(b":::").is_none());
        // two double colons
        assert!(parse_v6(b"1:2::6::8").is_none());
        assert!(parse_v6(b"::6::8").is_none());
        assert!(parse_v6(b"1:2::6::").is_none());
        assert!(parse_v6(b"::2:6::").is_none());
        // `::` indicating zero groups of zeros
        assert!(parse_v6(b"::1:2:3:4:5:6:7:8").is_none());
        assert!(parse_v6(b"1:2:3:4::5:6:7:8").is_none());
        assert!(parse_v6(b"1:2:3:4:5:6:7:8::").is_none());
        // preceding colon
        assert!(parse_v6(b":1:2:3:4:5:6:7:8").is_none());
        // trailing colon
        assert!(parse_v6(b"1:2:3:4:5:6:7:8:").is_none());
    }

    #[test]
    fn test_parse_v4_in_v6() {
        assert_eq!(
            Some(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 49152, 545)),
            parse_v6(b"::192.0.2.33")
        );
        assert_eq!(
            Some(Ipv6Addr::new(0, 0, 0, 0, 0, 0xFFFF, 49152, 545)),
            parse_v6(b"::FFFF:192.0.2.33")
        );
        assert_eq!(
            Some(Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 49152, 545)),
            parse_v6(b"64:ff9b::192.0.2.33")
        );
        assert_eq!(
            Some(Ipv6Addr::new(
                0x2001, 0xdb8, 0x122, 0xc000, 0x2, 0x2100, 49152, 545
            )),
            parse_v6(b"2001:db8:122:c000:2:2100:192.0.2.33")
        );

        // colon after v4
        assert!(parse_v6(b"::127.0.0.1:").is_none());
        // not enough groups
        assert!(parse_v6(b"1:2:3:4:5:127.0.0.1").is_none());
        // too many groups
        assert!(parse_v6(b"1:2:3:4:5:6:7:127.0.0.1").is_none());
    }
}
