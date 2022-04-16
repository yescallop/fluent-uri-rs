#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(u) = fluent_uri::Uri::parse(data) {
        let mut buf = String::with_capacity(data.len());
        if let Some(s) = u.scheme() {
            buf.push_str(s.as_str());
            buf.push(':');
        }
        if let Some(a) = u.authority() {
            buf.push_str("//");
            if let Some(ui) = a.userinfo() {
                buf.push_str(ui.as_str());
                buf.push('@');
            }
            buf.push_str(a.host_raw());
            if let Some(p) = a.port_raw() {
                buf.push(':');
                buf.push_str(p);
            }
        }
        buf.push_str(u.path().as_str());
        if let Some(q) = u.query() {
            buf.push('?');
            buf.push_str(q.as_str());
        }
        if let Some(f) = u.fragment() {
            buf.push('#');
            buf.push_str(f.as_str());
        }
        assert_eq!(data, buf.as_bytes());
    }
});
