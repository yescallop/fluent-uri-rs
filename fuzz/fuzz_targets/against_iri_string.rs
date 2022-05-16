#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let u1 = fluent_uri::Uri::parse(data);
    let u2 = <&iri_string::types::UriReferenceStr>::try_from(data);
    assert_eq!(u1.is_ok(), u2.is_ok());

    if let Ok(u1) = u1 {
        let u2 = u2.unwrap();
        assert_eq!(u1.scheme().map(|s| s.as_str()), u2.scheme_str());
        assert_eq!(
            u1.authority().map(|a| (
                a.userinfo().map(|s| s.as_str()),
                a.host().as_str(),
                a.port()
            )),
            u2.authority_components()
                .map(|a| (a.userinfo(), a.host(), a.port()))
        );
        assert_eq!(u1.path().as_str(), u2.path_str());
        assert_eq!(u1.query().map(|s| s.as_str()), u2.query_str());
        assert_eq!(
            u1.fragment().map(|s| s.as_str()),
            u2.fragment().map(|s| s.as_str())
        );
    }
});
