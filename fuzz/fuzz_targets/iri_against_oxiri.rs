#![no_main]
use fluent_uri::{component::Host, IriRef};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let r1 = IriRef::parse(data);
    let r2 = oxiri::IriRef::parse(data);
    assert_eq!(r1.is_ok(), r2.is_ok());

    let Ok(r1) = r1 else { return };
    let r2 = r2.unwrap();

    if let Some(auth) = r1.authority() {
        if let Host::IpvFuture { .. } = auth.host_parsed() {
            return;
        }
    }

    assert_eq!(r1.scheme().map(|s| s.as_str()), r2.scheme());
    assert_eq!(r1.authority().map(|a| a.as_str()), r2.authority());
    assert_eq!(r1.path().as_str(), r2.path());
    assert_eq!(r1.query().map(|s| s.as_str()), r2.query());
    assert_eq!(r1.fragment().map(|s| s.as_str()), r2.fragment());
});
