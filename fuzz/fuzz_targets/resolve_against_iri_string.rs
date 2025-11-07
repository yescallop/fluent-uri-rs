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

    let Ok(t1) = r1.resolve_against(&base1) else {
        return;
    };

    if t1.authority().is_none() && t1.path().is_rootless() {
        return;
    }

    let base2 = UriAbsoluteStr::new(data.0).unwrap();
    let r2 = UriReferenceStr::new(data.1).unwrap();

    let t2 = r2.resolve_against(base2).to_dedicated_string();

    if t1.as_str() == t2.as_str() {
        return;
    }

    if let Some((_, last_seg)) = base1.path().as_str().rsplit_once('/') {
        if classify_segment(last_seg) == SegKind::DoubleDot {
            return;
        }
    }

    if let Some(mut segs) = base1.path().segments_if_absolute() {
        if !r1.has_scheme()
            && !r1.has_authority()
            && r1.path().is_empty()
            && segs.any(|seg| classify_segment(seg.as_str()) != SegKind::Normal)
        {
            return;
        }
    }

    panic!("{} != {}", t1.as_str(), t2.as_str());
});

#[derive(Eq, PartialEq)]
enum SegKind {
    Dot,
    DoubleDot,
    Normal,
}

fn classify_segment(seg: &str) -> SegKind {
    match seg.as_bytes() {
        [b'.', rem @ ..] | [b'%', b'2', b'E' | b'e', rem @ ..] => match rem {
            [] => SegKind::Dot,
            b"." | [b'%', b'2', b'E' | b'e'] => SegKind::DoubleDot,
            _ => SegKind::Normal,
        },
        _ => SegKind::Normal,
    }
}
