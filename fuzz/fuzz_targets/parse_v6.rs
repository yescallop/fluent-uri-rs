#![no_main]
use fluent_uri::{component::Host, Uri};
use libfuzzer_sys::fuzz_target;
use std::net::Ipv6Addr;
use std::str::FromStr;

fuzz_target!(|data: &str| {
    assert_eq!(parse_v6(data), Ipv6Addr::from_str(data).ok());
});

fn parse_v6(s: &str) -> Option<Ipv6Addr> {
    let s = format!("//[{s}]");
    match Uri::parse(&s).ok()?.authority()?.host_parsed() {
        Host::Ipv6(addr) => Some(addr),
        _ => None,
    }
}
