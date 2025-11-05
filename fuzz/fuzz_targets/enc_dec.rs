#![no_main]
use fluent_uri::pct_enc::{encoder::Query, EStr, EString};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut buf = EString::<Query>::new();
    let mut lossy = String::new();

    for chunk in data.utf8_chunks() {
        buf.encode::<Query>(chunk.valid());
        lossy.push_str(chunk.valid());

        for &x in chunk.invalid() {
            buf.push_estr(EStr::force_encode_byte(x));
        }
        if !chunk.invalid().is_empty() {
            lossy.push(char::REPLACEMENT_CHARACTER);
        }
    }

    assert_eq!(data, &*buf.decode().to_bytes());
    assert_eq!(lossy, buf.decode().to_string_lossy());
});
