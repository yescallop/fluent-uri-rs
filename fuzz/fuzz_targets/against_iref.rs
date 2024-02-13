#![no_main]
use fluent_uri_fuzz::parse_strict;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    assert_eq!(
        parse_strict(data).is_some(),
        iref::UriRef::new(data).is_ok()
    );
});