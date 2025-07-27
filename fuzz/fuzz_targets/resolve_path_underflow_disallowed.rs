#![no_main]
use fluent_uri::{resolve::Resolver, Uri, UriRef};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: (&str, &str)| {
    let (Ok(base), Ok(r)) = (Uri::parse(data.0), UriRef::parse(data.1)) else {
        return;
    };

    let resolver = Resolver::with_base(base).allow_path_underflow(false);
    let Ok(r1) = resolver.resolve(&r) else {
        return;
    };
    let r2 = Uri::parse(r1.as_str()).unwrap();

    assert_eq!(r1.scheme().as_str(), r2.scheme().as_str());
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

    // Swapping the order of resolution and normalization does not change the result.
    let resolve_then_normalize = r1.normalize();
    let resolver = Resolver::with_base(base.normalize()).allow_path_underflow(false);
    let normalize_then_resolve = resolver.resolve(&r.normalize()).unwrap();
    assert_eq!(resolve_then_normalize, normalize_then_resolve);
});
