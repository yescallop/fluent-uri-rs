#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    if fluent_uri::Uri::parse(data).is_ok() {
        assert!(oxiri::IriRef::parse(data).is_ok());
    }
});
