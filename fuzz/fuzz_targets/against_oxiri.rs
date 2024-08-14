#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let Ok(r1) = fluent_uri::UriRef::parse(data) else {
        return;
    };
    let r2 = oxiri::IriRef::parse(data).unwrap();
    assert_eq!(r1.scheme().map(|s| s.as_str()), r2.scheme());
    assert_eq!(r1.authority().map(|a| a.as_str()), r2.authority());
    assert_eq!(r1.path().as_str(), r2.path());
    assert_eq!(r1.query().map(|s| s.as_str()), r2.query());
    assert_eq!(r1.fragment().map(|s| s.as_str()), r2.fragment());
});
