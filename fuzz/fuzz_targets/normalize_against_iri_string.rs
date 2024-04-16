#![no_main]
use fluent_uri::{component::Host, Uri};
use iri_string::{format::ToDedicatedString, types::UriStr};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let Ok(u1) = Uri::parse(data) else { return };

    if u1.is_relative_reference() || u1.path().is_rootless() {
        return;
    }

    let u2 = UriStr::new(data).unwrap();

    let u1 = u1.normalize();
    let u2 = u2.normalize().to_dedicated_string();

    if u1.as_str() == u2.as_str() {
        return;
    }

    if let Some(auth) = u1.authority() {
        match auth.host_parsed() {
            Host::RegName(name1) => {
                let name2 = u2.authority_components().unwrap().host();
                if name1.as_str().eq_ignore_ascii_case(name2) {
                    return;
                }
            }
            Host::Ipv6(_) => return,
            _ => {}
        }
    }

    panic!("{} != {}", u1.as_str(), u2.as_str());
});
