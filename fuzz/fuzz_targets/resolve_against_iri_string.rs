#![no_main]
use fluent_uri::Uri;
use iri_string::{
    format::ToDedicatedString,
    types::{UriAbsoluteStr, UriReferenceStr},
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: (&str, &str)| {
    let (Ok(base), Ok(r)) = (Uri::parse(data.0), Uri::parse(data.1)) else {
        return;
    };

    let Ok(u1) = r.resolve(&base) else { return };

    if r.scheme().is_some() && r.authority().is_none() && r.path().is_rootless() {
        return;
    }

    // if u1.path() == "/.//" {
    //     return;
    // }

    let base = UriAbsoluteStr::new(data.0).unwrap();
    let r = UriReferenceStr::new(data.1).unwrap();

    let u2 = r.resolve_against(base).to_dedicated_string();

    assert_eq!(u1.as_str(), u2.as_str());
});
