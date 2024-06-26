#![no_main]
use fluent_uri::{component::Host, UriRef};
use libfuzzer_sys::fuzz_target;
use std::net::Ipv4Addr;
use std::str::FromStr;

fuzz_target!(|data: &str| {
    if data.contains(['/', '?', '#', '@', ':']) {
        return;
    }
    assert_eq!(parse_v4(data), Ipv4Addr::from_str(data).ok());
});

fn parse_v4(s: &str) -> Option<Ipv4Addr> {
    let s = format!("//{s}/");
    match UriRef::parse(s).ok()?.authority()?.host_parsed() {
        Host::Ipv4(addr) => Some(addr),
        _ => None,
    }
}
