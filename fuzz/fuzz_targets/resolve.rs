#![no_main]
use fluent_uri::Uri;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: (&str, &str)| {
    let (Ok(base), Ok(r)) = (Uri::parse(data.0), Uri::parse(data.1)) else {
        return;
    };

    let Ok(u1) = r.resolve(&base) else { return };
    let u2 = Uri::parse(u1.as_str()).unwrap();

    assert_eq!(
        u1.scheme().map(|s| s.as_str()),
        u2.scheme().map(|s| s.as_str())
    );
    assert_eq!(u1.authority().is_some(), u2.authority().is_some());

    if let Some(a1) = u1.authority() {
        let a2 = u2.authority().unwrap();
        assert_eq!(a1.as_str(), a2.as_str());
        assert_eq!(a1.userinfo(), a2.userinfo());
        assert_eq!(a1.host(), a2.host());
        assert_eq!(a1.host_parsed(), a2.host_parsed());
        assert_eq!(a1.port(), a2.port());
    }

    assert_eq!(u1.path(), u2.path());
    assert_eq!(u1.query(), u2.query());
    assert_eq!(u1.fragment(), u2.fragment());

    // Swapping the order of resolution and normalization does not change the result.
    let resolve_then_normalize = u1.normalize();
    let normalize_then_resolve = r.normalize().resolve(&base.normalize()).unwrap();
    assert_eq!(resolve_then_normalize, normalize_then_resolve);
});
