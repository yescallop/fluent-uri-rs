#![no_main]
use fluent_uri::{component::Host, Iri};
use iri_string::{format::ToDedicatedString, types::IriStr};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let Ok(r1) = Iri::parse(data) else {
        return;
    };

    if r1.path().is_rootless() {
        return;
    }

    let r2 = IriStr::new(data).unwrap();

    let r1 = r1.normalize();
    let r2 = r2.normalize().to_dedicated_string();

    if r1.as_str() == r2.as_str() {
        return;
    }

    if let Some(auth1) = r1.authority() {
        let auth2 = r2.authority_components().unwrap();
        assert_eq!(auth1.userinfo().map(|s| s.as_str()), auth2.userinfo());
        assert_eq!(auth1.port().map(|s| s.as_str()), auth2.port());

        match auth1.host_parsed() {
            Host::RegName(name1) => {
                let name2 = r2.authority_components().unwrap().host();
                if name1.as_str().eq_ignore_ascii_case(name2) {
                    return;
                }
            }
            Host::Ipv6(_) => return,
            _ => {}
        }
    }

    panic!("{:?} != {:?}", r1.as_str(), r2.as_str());
});
