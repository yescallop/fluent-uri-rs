#![no_main]
use fluent_uri::enc::*;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let enc = encode(data, table::QUERY_FRAGMENT);
    let mut dec = decode(enc.as_bytes()).unwrap().into_owned();
    assert_eq!(data, dec);
    dec.clear();
    unsafe {
        let mut enc = enc.into_owned().into_bytes();
        if let Some(x) = decode_with_unchecked(&enc, &mut dec) {
            assert_eq!(data, x);
        }
        let len = decode_in_place_unchecked(&mut enc);
        assert_eq!(data, &enc[..len]);
    }
});
