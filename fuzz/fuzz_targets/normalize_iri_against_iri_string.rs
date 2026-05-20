#![no_main]
use fluent_uri::{
    component::Host,
    pct_enc::{encoder::Query, EStr},
    Iri,
};
use iri_string::{format::ToDedicatedString, types::IriStr};
use libfuzzer_sys::fuzz_target;

fn is_iprivate(x: u32) -> bool {
    (x >= 0xe000 && x <= 0xf8ff) || (x >= 0xf0000 && (x & 0xffff) <= 0xfffd)
}

fn encode_iprivate(s: &str) -> String {
    let mut buf = String::with_capacity(s.len());
    for ch in s.chars() {
        if is_iprivate(ch as u32) {
            for x in ch.encode_utf8(&mut [0; 4]).bytes() {
                buf.push_str(EStr::<Query>::force_encode_byte(x).as_str());
            }
        } else {
            buf.push(ch);
        }
    }
    buf
}

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

    if let Some(q1) = r1.query() {
        let q2 = r2.query().unwrap();
        if encode_iprivate(q1.as_str()) == encode_iprivate(q2.as_str()) {
            return;
        }
    }

    panic!("{:?} != {:?}", r1.as_str(), r2.as_str());
});
