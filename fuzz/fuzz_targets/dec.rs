#![no_main]
use fluent_uri::{component::Host, Uri};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    if let Ok(uri) = Uri::parse(data) {
        if let Some(auth) = uri.authority() {
            if let Host::RegName(name) = auth.host_parsed() {
                name.decode();
            }
        }
        uri.path().decode();
        if let Some(query) = uri.query() {
            query.decode();
        }
        if let Some(fragment) = uri.fragment() {
            fragment.decode();
        }
    }
});
