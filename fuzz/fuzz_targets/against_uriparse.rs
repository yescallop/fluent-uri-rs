#![no_main]
use fluent_uri::Uri;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    assert_eq!(
        Uri::parse(data).is_ok(),
        uriparse::URIReference::try_from(data).is_ok()
    );
});
