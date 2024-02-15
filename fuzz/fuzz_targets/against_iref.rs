#![no_main]
use fluent_uri_fuzz::parse_strict;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let u1 = parse_strict(data);
    let u2 = iref::UriRef::new(data);
    assert_eq!(u1.is_some(), u2.is_ok());

    if let Some(u1) = u1 {
        let u2 = u2.unwrap();
        assert_eq!(
            u1.scheme().map(|s| s.as_str()),
            u2.scheme().map(|s| s.as_str())
        );
        assert_eq!(
            u1.authority()
                .map(|a| (a.userinfo().map(|s| s.as_str()), a.host(), a.port())),
            u2.authority().map(|a| (
                a.user_info().map(|s| s.as_str()),
                a.host().as_str(),
                a.port().map(|s| s.as_str())
            ))
        );
        assert_eq!(u1.path().as_str(), u2.path().as_str());
        assert_eq!(
            u1.query().map(|s| s.as_str()),
            u2.query().map(|s| s.as_str())
        );
        assert_eq!(
            u1.fragment().map(|s| s.as_str()),
            u2.fragment().map(|s| s.as_str())
        );
    }
});
