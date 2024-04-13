#![no_main]
use fluent_uri::Uri;
use iri_string::{format::ToDedicatedString, types::UriStr};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let Ok(u1) = Uri::parse(data) else { return };

    if u1.is_relative_reference() || u1.path().is_rootless() {
        return;
    }

    let u2 = UriStr::new(data).unwrap();

    let u1 = u1.normalize();

    // if u1.path() == "/.//" {
    //     return;
    // }

    assert_eq!(u1.as_str(), u2.normalize().to_dedicated_string().as_str());
});
