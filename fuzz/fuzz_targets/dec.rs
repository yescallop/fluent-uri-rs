#![no_main]
use fluent_uri::{component::Host, UriRef};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let Ok(r) = UriRef::parse(data) else {
        return;
    };
    if let Some(auth) = r.authority() {
        if let Host::RegName(name) = auth.host_parsed() {
            let _ = name.decode();
        }
    }
    let _ = r.path().decode();
    if let Some(query) = r.query() {
        let _ = query.decode();
    }
    if let Some(fragment) = r.fragment() {
        let _ = fragment.decode();
    }
});
