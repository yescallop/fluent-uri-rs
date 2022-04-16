#![no_main]
use fluent_uri::encoding::*;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let enc = encode(data, table::QUERY_FRAGMENT);
    let _ = decode(enc.as_bytes()).unwrap();
});
