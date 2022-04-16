#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    assert_eq!(
        fluent_uri::Uri::parse(data).is_ok(),
        <&iri_string::types::UriReferenceStr>::try_from(data).is_ok()
    );
});
