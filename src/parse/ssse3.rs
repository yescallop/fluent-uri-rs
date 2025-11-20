use crate::pct_enc::{self, table::HEXDIG, Table};
use core::arch::x86_64::*;

#[target_feature(enable = "ssse3")]
pub unsafe fn read(src: &[u8], table: Table) -> Result<usize, usize> {
    let len = src.len();
    let ptr = src.as_ptr();

    let mut i = 0;
    if len >= 16 + 2 {
        if src[0] == b'%' {
            if !pct_enc::is_hexdig(src[1]) {
                return Err(1);
            }
        } else if !table.allows_maybe_pct_ascii(src[0]) {
            return Ok(0);
        } else if !table.allows_maybe_pct_ascii(src[1]) {
            return Ok(1);
        }

        // the corresponding bits for % and hexdig are set in this table
        let allowed = table.ascii_bits();
        let allowed = _mm_set_epi64x(allowed.1 as _, allowed.0 as _);

        let hexdig = HEXDIG.ascii_bits();
        let hexdig = _mm_set_epi64x(hexdig.1 as _, hexdig.0 as _);

        let pct = _mm_set1_epi8(b'%' as _);
        let byte_lo_4_mask = _mm_set1_epi8(0xf);
        let mask_table = _mm_set1_epi64x(0x8040201008040201u64 as _);
        let zero = _mm_setzero_si128();

        i = 2;
        while i <= len - 16 {
            let chunk = _mm_loadu_si128(ptr.add(i).cast());
            let chunk_left_1 = _mm_loadu_si128(ptr.add(i - 1).cast());
            let chunk_left_2 = _mm_loadu_si128(ptr.add(i - 2).cast());

            // for non-ASCII, this is 0
            let mask_per_byte = _mm_shuffle_epi8(mask_table, chunk);

            let after_pct_1 = _mm_cmpeq_epi8(chunk_left_1, pct);
            let after_pct_2 = _mm_cmpeq_epi8(chunk_left_2, pct);
            let after_pct = _mm_or_si128(after_pct_1, after_pct_2);

            let word_shr_3 = _mm_srli_epi16::<3>(chunk);

            let table_idx_per_byte = _mm_and_si128(word_shr_3, byte_lo_4_mask);

            let allowed_per_byte = _mm_shuffle_epi8(allowed, table_idx_per_byte);
            let hexdig_per_byte = _mm_shuffle_epi8(hexdig, table_idx_per_byte);

            let table_per_byte = _mm_andnot_si128(after_pct, allowed_per_byte);
            let table_per_byte = _mm_or_si128(table_per_byte, hexdig_per_byte);

            let nz_if_valid = _mm_and_si128(table_per_byte, mask_per_byte);

            let invalid = _mm_cmpeq_epi8(nz_if_valid, zero);
            let invalid = _mm_movemask_epi8(invalid);

            if invalid != 0 {
                let after_pct = _mm_movemask_epi8(after_pct);
                let offset = invalid.trailing_zeros();
                let offset_i = i + offset as usize;

                return if after_pct & (1 << offset) == 0 {
                    Ok(offset_i)
                } else {
                    Err(offset_i)
                };
            }
            i += 16;
        }
        i -= 2;
    }

    while i < len {
        let x = src[i];
        if x == b'%' {
            let [hi, lo, ..] = src[i + 1..] else {
                return invalid_pct(src, i);
            };
            if !pct_enc::is_hexdig_pair(hi, lo) {
                return invalid_pct(src, i);
            }
            i += 3;
        } else {
            if !table.allows_maybe_pct_ascii(x) {
                break;
            }
            i += 1;
        }
    }
    Ok(i)
}

#[cold]
fn invalid_pct(src: &[u8], i: usize) -> Result<usize, usize> {
    let mut i = i + 1;
    if let Some(&x) = src.get(i) {
        if pct_enc::is_hexdig(x) {
            i += 1;
        }
    }
    Err(i)
}
