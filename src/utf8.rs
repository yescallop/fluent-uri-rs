//! UTF-8 utilities taken from `core::str`, Rust 1.81.

use core::str;

#[inline]
const fn utf8_first_byte(byte: u8, width: u32) -> u32 {
    (byte & (0x7F >> width)) as u32
}

#[inline]
const fn utf8_acc_cont_byte(ch: u32, byte: u8) -> u32 {
    (ch << 6) | (byte & CONT_MASK) as u32
}

// Make sure it's inlined into `Parser::read_with`.
#[inline(always)]
pub const fn next_code_point(bytes: &[u8], i: usize) -> (u32, usize) {
    let x = bytes[i];
    if x < 128 {
        return (x as u32, 1);
    }

    let init = utf8_first_byte(x, 2);
    let y = bytes[i + 1];
    if x < 0xE0 {
        (utf8_acc_cont_byte(init, y), 2)
    } else {
        let z = bytes[i + 2];
        let y_z = utf8_acc_cont_byte((y & CONT_MASK) as u32, z);
        if x < 0xF0 {
            ((init << 12) | y_z, 3)
        } else {
            let w = bytes[i + 3];
            (((init & 7) << 18) | utf8_acc_cont_byte(y_z, w), 4)
        }
    }
}

const CONT_MASK: u8 = 0b0011_1111;

pub(crate) const fn is_char_boundary(b: u8) -> bool {
    // This is bit magic equivalent to: b < 128 || b >= 192
    (b as i8) >= -0x40
}

pub struct Utf8Chunk<'a> {
    valid: &'a str,
    invalid: &'a [u8],
}

impl<'a> Utf8Chunk<'a> {
    pub fn valid(&self) -> &'a str {
        self.valid
    }

    pub fn invalid(&self) -> &'a [u8] {
        self.invalid
    }
}

pub struct Utf8Chunks<'a> {
    source: &'a [u8],
}

impl<'a> Utf8Chunks<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { source: bytes }
    }
}

impl<'a> Iterator for Utf8Chunks<'a> {
    type Item = Utf8Chunk<'a>;

    fn next(&mut self) -> Option<Utf8Chunk<'a>> {
        if self.source.is_empty() {
            return None;
        }

        match str::from_utf8(self.source) {
            Ok(valid) => {
                self.source = &[];

                Some(Utf8Chunk {
                    valid,
                    invalid: &[],
                })
            }
            Err(e) => {
                let (valid, after_valid) = self.source.split_at(e.valid_up_to());

                let (invalid, rem) = if let Some(len) = e.error_len() {
                    let (invalid, rem) = after_valid.split_at(len);
                    (invalid, rem)
                } else {
                    (after_valid, &[][..])
                };
                self.source = rem;

                Some(Utf8Chunk {
                    valid: str::from_utf8(valid).unwrap(),
                    invalid,
                })
            }
        }
    }
}
