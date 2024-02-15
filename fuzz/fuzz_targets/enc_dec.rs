#![no_main]
use fluent_uri::encoding::{encoder::Query, EString};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut buf = EString::<Query>::new();
    buf.encode::<Query>(data);
    assert_eq!(data, buf.decode().as_bytes());
});
