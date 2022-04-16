#![no_main]
use fluent_uri::encoding::*;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = decode(data);
});
