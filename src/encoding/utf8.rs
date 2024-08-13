// Taken from `core::str::validations`.

const CONT_MASK: u8 = 0b0011_1111;

#[inline]
const fn utf8_first_byte(byte: u8, width: u32) -> u32 {
    (byte & (0x7F >> width)) as u32
}

#[inline]
const fn utf8_acc_cont_byte(ch: u32, byte: u8) -> u32 {
    (ch << 6) | (byte & CONT_MASK) as u32
}

#[inline]
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
            (init << 12 | y_z, 3)
        } else {
            let w = bytes[i + 3];
            ((init & 7) << 18 | utf8_acc_cont_byte(y_z, w), 4)
        }
    }
}
