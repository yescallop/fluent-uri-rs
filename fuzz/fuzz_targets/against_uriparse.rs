#![no_main]
use fluent_uri::UriRef;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    assert_eq!(
        UriRef::parse(data).is_ok(),
        uriparse::URIReference::try_from(data).is_ok()
    );
});
