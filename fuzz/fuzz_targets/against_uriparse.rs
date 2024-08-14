#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    assert_eq!(
        fluent_uri::UriRef::parse(data).is_ok(),
        uriparse::URIReference::try_from(data).is_ok()
    );
});
