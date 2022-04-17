#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    if let Ok(u1) = fluent_uri::Uri::parse(data) {
        let u2 = oxiri::IriRef::parse(data).unwrap();
        assert_eq!(u1.scheme().map(|s| s.as_str()), u2.scheme());
        assert_eq!(u1.authority().map(|a| a.as_str()), u2.authority());
        assert_eq!(u1.path().as_str(), u2.path());
        assert_eq!(u1.query().map(|s| s.as_str()), u2.query());
        assert_eq!(u1.fragment().map(|s| s.as_str()), u2.fragment());
    }
});
