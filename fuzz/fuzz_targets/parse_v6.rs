#![no_main]
use fluent_uri::{Host, Uri};
use libfuzzer_sys::fuzz_target;
use std::net::Ipv6Addr;
use std::str::FromStr;

fuzz_target!(|data: &str| {
    if data.contains(']') {
        return;
    }
    assert_eq!(parse_v6(data), Ipv6Addr::from_str(data).ok());
});

fn parse_v6(s: &str) -> Option<Ipv6Addr> {
    let s = format!("//[{s}]");
    match Uri::parse(s.as_bytes()).ok()?.authority()?.host() {
        Host::Ipv6 { addr } => Some(addr),
        _ => None,
    }
}
