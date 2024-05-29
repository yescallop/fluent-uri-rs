#![no_main]
use fluent_uri::{component::Host, Uri};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let Ok(uri) = Uri::parse(data) else { return };
    if let Some(auth) = uri.authority() {
        if let Host::RegName(name) = auth.host_parsed() {
            let _ = name.decode();
        }
    }
    let _ = uri.path().decode();
    if let Some(query) = uri.query() {
        let _ = query.decode();
    }
    if let Some(fragment) = uri.fragment() {
        let _ = fragment.decode();
    }
});
