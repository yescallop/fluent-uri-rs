/// A table determining which bytes are allowed in a string.
#[derive(Clone, Copy)]
pub struct Table {
    arr: [bool; 256],
    allow_enc: bool,
}

impl Table {
    /// Marks this table as allowing percent-encoded octets.
    pub const fn enc(mut self) -> Table {
        self.allow_enc = true;
        self
    }

    /// Combines two tables into one.
    pub const fn or(mut self, t: &Table) -> Table {
        let mut i = 0;
        while i < 128 {
            self.arr[i] |= t.arr[i];
            i += 1;
        }
        self.allow_enc |= t.allow_enc;
        self
    }

    /// Returns `true` if a byte is allowed by the table.
    #[inline]
    pub const fn contains(&self, x: u8) -> bool {
        self.arr[x as usize]
    }

    /// Returns `true` if percent-encoded octets are allowed by the table.
    #[inline]
    pub const fn allow_enc(&self) -> bool {
        self.allow_enc
    }
}

/// Generates a table that only allows the given bytes.
///
/// # Panics
///
/// Panics if any of the bytes is not ASCII.
pub const fn gen(mut bytes: &[u8]) -> Table {
    let mut arr = [false; 256];
    while let [cur, rem @ ..] = bytes {
        assert!(cur.is_ascii(), "non-ASCII byte");
        arr[*cur as usize] = true;
        bytes = rem;
    }
    Table {
        arr,
        allow_enc: false,
    }
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
pub static SCHEME: &Table = &ALPHA.or(DIGIT).or(&gen(b"+-."));

/// userinfo = *( unreserved / pct-encoded / sub-delims / ":" )
pub static USERINFO: &Table = &UNRESERVED.or(SUB_DELIMS).or(&gen(b":")).enc();

/// IPvFuture = "v" 1\*HEXDIG "." 1\*( unreserved / sub-delims / ":" )
pub static IPV_FUTURE: &Table = &UNRESERVED.or(SUB_DELIMS).or(&gen(b":"));

/// reg-name = *( unreserved / pct-encoded / sub-delims )
pub static REG_NAME: &Table = &UNRESERVED.or(SUB_DELIMS).enc();

/// path = *( pchar / "/" )
pub static PATH: &Table = &PCHAR.or(&gen(b"/"));

/// query = fragment = *( pchar / "/" / "?" )
pub static QUERY_FRAGMENT: &Table = &PCHAR.or(&gen(b"/?"));

/// RFC 6874: ZoneID = 1*( unreserved / pct-encoded )
pub static ZONE_ID: &Table = &UNRESERVED.enc();
