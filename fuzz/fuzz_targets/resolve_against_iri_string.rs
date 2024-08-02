#![no_main]
use fluent_uri::{Uri, UriRef};
use iri_string::{
    format::ToDedicatedString,
    types::{UriAbsoluteStr, UriReferenceStr},
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: (&str, &str)| {
    let (Ok(base1), Ok(r1)) = (Uri::parse(data.0), UriRef::parse(data.1)) else {
        return;
    };

    let Ok(r1) = r1.resolve_against(&base1) else {
        return;
    };

    if r1.authority().is_none() && r1.path().is_rootless() {
        return;
    }

    let base2 = UriAbsoluteStr::new(data.0).unwrap();
    let r2 = UriReferenceStr::new(data.1).unwrap();

    let r2 = r2.resolve_against(base2).to_dedicated_string();

    if r1.as_str() == r2.as_str() {
        return;
    }

    if let Some((_, last_seg)) = base1.path().as_str().rsplit_once('/') {
        if is_double_dot(last_seg) {
            return;
        }
    }

    panic!("{} != {}", r1.as_str(), r2.as_str());
});

fn is_double_dot(mut seg: &str) -> bool {
    if seg.is_empty() {
        return false;
    }
    if let Some(rem) = seg.strip_prefix('.') {
        seg = rem;
    } else if let Some(rem) = seg.strip_prefix("%2E") {
        seg = rem;
    } else if let Some(rem) = seg.strip_prefix("%2e") {
        seg = rem;
    }
    seg == "." || seg == "%2E" || seg == "%2e"
}
