#![cfg(all(feature = "net", feature = "std"))]

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use fluent_uri::Uri;

#[test]
fn test_to_socket_addrs() {
    let u = Uri::parse("//127.0.0.1:81").unwrap();
    assert!(u
        .authority()
        .unwrap()
        .to_socket_addrs(80)
        .unwrap()
        .eq([SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 81).into()]));

    let u = Uri::parse("//127.0.0.1").unwrap();
    assert!(u
        .authority()
        .unwrap()
        .to_socket_addrs(80)
        .unwrap()
        .eq([SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 80).into()]));

    let u = Uri::parse("//127.0.0.1:").unwrap();
    assert!(u
        .authority()
        .unwrap()
        .to_socket_addrs(80)
        .unwrap()
        .eq([SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 80).into()]));

    let u = Uri::parse("//[::1]").unwrap();
    assert!(u
        .authority()
        .unwrap()
        .to_socket_addrs(80)
        .unwrap()
        .eq([SocketAddrV6::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 80, 0, 0).into()]));

    let u = Uri::parse("//127.0.0.1:65537").unwrap();
    assert_eq!(
        u.authority()
            .unwrap()
            .to_socket_addrs(80)
            .err()
            .unwrap()
            .to_string(),
        "invalid port value"
    );

    let u = Uri::parse("//[vF.whatever]").unwrap();
    assert_eq!(
        u.authority()
            .unwrap()
            .to_socket_addrs(80)
            .err()
            .unwrap()
            .to_string(),
        "address mechanism not supported"
    );
}
