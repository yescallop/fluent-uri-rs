#![no_main]
use fluent_uri::{component::Host, UriRef};
use iri_string::{format::ToDedicatedString, types::UriStr};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let Ok(r1) = UriRef::parse(data) else {
        return;
    };

    if !r1.is_uri() || r1.path().is_rootless() {
        return;
    }

    let r2 = UriStr::new(data).unwrap();

    let r1 = r1.normalize();
    let r2 = r2.normalize().to_dedicated_string();

    if r1.as_str() == r2.as_str() {
        return;
    }

    if let Some(auth) = r1.authority() {
        match auth.host_parsed() {
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

    panic!("{} != {}", r1.as_str(), r2.as_str());
});
