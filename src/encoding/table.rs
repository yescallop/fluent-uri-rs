/// A table determining which bytes are allowed.
#[derive(Clone, Copy)]
pub struct Table([bool; 256]);

impl Table {
    const fn enc(mut self) -> Table {
        self.0[0] = true;
        self
    }

    const fn or(mut self, t: &Table) -> Table {
        let mut i = 0;
        while i < 256 {
            self.0[i] = self.0[i] || t.0[i];
            i += 1;
        }
        self
    }

    /// Returns `true` if the byte is allowed by the table.
    #[inline]
    pub fn contains(&self, x: u8) -> bool {
        self.0[x as usize]
    }

    /// Returns `true` if percent-encoded octets are allowed by the table.
    #[inline]
    pub fn allow_enc(&self) -> bool {
        self.0[0]
    }
}

const fn gen(mut chars: &[u8]) -> Table {
    let mut out = [false; 256];
    while let [cur, rem @ ..] = chars {
        out[*cur as usize] = true;
        chars = rem;
    }
    Table(out)
}

/// ALPHA = A-Z / a-z
pub static ALPHA: &Table = &gen(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");

/// DIGIT = 0-9
pub static DIGIT: &Table = &gen(b"0123456789");

/// HEXDIG = DIGIT / "A" / "B" / "C" / "D" / "E" / "F"
///                / "a" / "b" / "c" / "d" / "e" / "f"
pub static HEXDIG: &Table = &DIGIT.or(&gen(b"ABCDEFabcdef"));

/// reserved = gen-delims / sub-delims
pub static RESERVED: &Table = &GEN_DELIMS.or(SUB_DELIMS);

/// gen-delims = ":" / "/" / "?" / "#" / "[" / "]" / "@"
pub static GEN_DELIMS: &Table = &gen(b":/?#[]@");

/// sub-delims = "!" / "$" / "&" / "'" / "(" / ")"
///            / "*" / "+" / "," / ";" / "="
pub static SUB_DELIMS: &Table = &gen(b"!$&'()*+,;=");

/// unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
pub static UNRESERVED: &Table = &ALPHA.or(DIGIT).or(&gen(b"-._~"));

/// pchar = unreserved / pct-encoded / sub-delims / ":" / "@"
pub static PCHAR: &Table = &UNRESERVED.or(SUB_DELIMS).or(&gen(b":@")).enc();

/// scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
pub static SCHEME: &Table = &ALPHA.or(DIGIT).or(&gen(b"+-.")).enc();

/// userinfo = *( unreserved / pct-encoded / sub-delims / ":" )
pub static USERINFO: &Table = &UNRESERVED.or(SUB_DELIMS).or(&gen(b":")).enc();

/// IPvFuture = "v" 1\*HEXDIG "." 1\*( unreserved / sub-delims / ":" )
pub static IPV_FUTURE: &Table = &UNRESERVED.or(SUB_DELIMS).or(&gen(b":")).enc();

/// reg-name = *( unreserved / pct-encoded / sub-delims )
pub static REG_NAME: &Table = &UNRESERVED.or(SUB_DELIMS).enc();

/// path = *( pchar / "/" )
pub static PATH: &Table = &PCHAR.or(&gen(b"/"));

/// query = fragment = *( pchar / "/" / "?" )
pub static QUERY_FRAGMENT: &Table = &PCHAR.or(&gen(b"/?"));

/// RFC 6874: ZoneID = 1*( unreserved / pct-encoded )
pub static ZONE_ID: &Table = &UNRESERVED.enc();
