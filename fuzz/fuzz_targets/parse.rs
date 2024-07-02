#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &str| {
    let Ok(r) = fluent_uri::UriRef::parse(data) else {
        return;
    };
    let mut buf = String::with_capacity(data.len());
    if let Some(s) = r.scheme() {
        buf.push_str(s.as_str());
        buf.push(':');
    }
    if let Some(a) = r.authority() {
        buf.push_str("//");
        let start = buf.len();
        if let Some(ui) = a.userinfo() {
            buf.push_str(ui.as_str());
            buf.push('@');
        }
        buf.push_str(a.host());
        if let Some(p) = a.port() {
            buf.push(':');
            buf.push_str(p.as_str());
        }
        assert_eq!(&buf[start..], a.as_str());
    }
    buf.push_str(r.path().as_str());
    if let Some(q) = r.query() {
        buf.push('?');
        buf.push_str(q.as_str());
    }
    if let Some(f) = r.fragment() {
        buf.push('#');
        buf.push_str(f.as_str());
    }
    assert_eq!(data, buf);
});
