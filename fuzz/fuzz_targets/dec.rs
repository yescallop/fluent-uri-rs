#![no_main]
use fluent_uri::{component::Host, pct_enc::Decode, UriRef};
use libfuzzer_sys::fuzz_target;

fn test_dec(dec: Decode<'_>) {
    let bytes = dec.clone().to_bytes();
    let string = dec.clone().to_string();
    let string_lossy = dec.to_string_lossy();

    assert_eq!(String::from_utf8_lossy(&bytes), string_lossy);
    assert_eq!(
        core::str::from_utf8(&bytes).map_err(|_| &*bytes),
        string.as_ref().map(|s| &**s).map_err(|e| &**e)
    );
}

fuzz_target!(|data: &str| {
    let Ok(r) = UriRef::parse(data) else {
        return;
    };
    if let Some(auth) = r.authority() {
        if let Host::RegName(name) = auth.host_parsed() {
            test_dec(name.decode());
        }
    }
    test_dec(r.path().decode());

    if let Some(query) = r.query() {
        test_dec(query.decode());
    }
    if let Some(fragment) = r.fragment() {
        test_dec(fragment.decode());
    }
});
