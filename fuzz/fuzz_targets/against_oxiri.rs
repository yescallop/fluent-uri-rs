#![no_main]
use fluent_uri::{component::Host, Uri};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let Ok(u1) = Uri::parse(data) else { return };
    if let Some(auth) = u1.authority() {
        if let Host::IpvFuture { .. } = auth.host_parsed() {
            return;
        }
    }
    let u2 = oxiri::IriRef::parse(data).unwrap();
    assert_eq!(u1.scheme().map(|s| s.as_str()), u2.scheme());
    assert_eq!(u1.authority().map(|a| a.as_str()), u2.authority());
    assert_eq!(u1.path().as_str(), u2.path());
    assert_eq!(u1.query().map(|s| s.as_str()), u2.query());
    assert_eq!(u1.fragment().map(|s| s.as_str()), u2.fragment());
});
