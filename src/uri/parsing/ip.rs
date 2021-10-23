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
    ($s:ident, $end:pat) => {{
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
    }};
}

// `Ipv4Addr::from_str` allows leading zeros, which doesn't adhere to RFC 3986.
// See: https://github.com/rust-lang/rust/pull/86984
pub(crate) fn parse_v4(mut s: &[u8]) -> Option<Ipv4Addr> {
    if !matches!(s.len(), 7..=15) {
        return None;
    }
    Some(Ipv4Addr::new(
        take_dec_octet!(s, Some(b'.'))?,
        take_dec_octet!(s, Some(b'.'))?,
        take_dec_octet!(s, Some(b'.'))?,
        #[allow(unused_assignments)]
        take_dec_octet!(s, None)?,
    ))
}

pub(crate) fn parse_v6(s: &[u8]) -> Option<Ipv6Addr> {
    if !matches!(s.len(), 2..=45) {
        return None;
    }
    todo!()
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
    }

    #[test]
    fn test_parse_v6() {
        assert_eq!(
            Some(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
            parse_v6(b"0:0:0:0:0:0:0:0")
        );
        assert_eq!(
            Some(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            parse_v6(b"0:0:0:0:0:0:0:1")
        );

        assert_eq!(
            Some(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            parse_v6(b"::1")
        );
        assert_eq!(Some(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)), parse_v6(b"::"));

        assert_eq!(
            Some(Ipv6Addr::new(0x2a02, 0x6b8, 0, 0, 0, 0, 0x11, 0x11)),
            parse_v6(b"2a02:6b8::11:11")
        );

        // too long group
        assert!(parse_v6(b"::00000").is_none());
        // too short
        assert!(parse_v6(b"1:2:3:4:5:6:7").is_none());
        // too long
        assert!(parse_v6(b"1:2:3:4:5:6:7:8:9").is_none());
        // triple colon
        assert!(parse_v6(b"1:2:::6:7:8").is_none());
        // two double colons
        assert!(parse_v6(b"1:2::6::8").is_none());
        // `::` indicating zero groups of zeros
        assert!(parse_v6(b"1:2:3:4::5:6:7:8").is_none());
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
        assert!(parse_v6(b"1.2.3.4.5:127.0.0.1").is_none());
        // too many groups
        assert!(parse_v6(b"1.2.3.4.5:6:7:127.0.0.1").is_none());
    }
}
