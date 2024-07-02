#![no_main]
use fluent_uri::UriRef;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let Ok(r) = UriRef::parse(data) else {
        return;
    };

    let r1 = r.normalize();
    let r2 = UriRef::parse(r1.as_str()).unwrap();

    assert_eq!(
        r1.scheme().map(|s| s.as_str()),
        r2.scheme().map(|s| s.as_str())
    );
    assert_eq!(r1.authority().is_some(), r2.authority().is_some());

    if let Some(a1) = r1.authority() {
        let a2 = r2.authority().unwrap();
        assert_eq!(a1.as_str(), a2.as_str());
        assert_eq!(a1.userinfo(), a2.userinfo());
        assert_eq!(a1.host(), a2.host());
        assert_eq!(a1.host_parsed(), a2.host_parsed());
        assert_eq!(a1.port(), a2.port());
    }

    assert_eq!(r1.path(), r2.path());
    assert_eq!(r1.query(), r2.query());
    assert_eq!(r1.fragment(), r2.fragment());

    // `normalize` is idempotent: we cannot normalize beyond a normalized `UriRef`.
    assert_eq!(r1.normalize(), r1);
});
