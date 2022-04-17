#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    assert_eq!(
        fluent_uri::Uri::parse(data).is_ok(),
        uriparse::URIReference::try_from(data).is_ok()
    );
});
