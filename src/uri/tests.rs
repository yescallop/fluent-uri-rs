use super::{ParseErrorKind::*, *};

#[test]
fn parse_absolute() {
    assert_eq!(
        UriRef::parse("file:///etc/hosts"),
        Ok(UriRef {
            scheme: Some("file"),
            authority: Some(Authority::EMPTY),
            path: "/etc/hosts",
            ..UriRef::EMPTY
        })
    );

    assert_eq!(
        UriRef::parse("ftp://ftp.is.co.za/rfc/rfc1808.txt"),
        Ok(UriRef {
            scheme: Some("ftp"),
            authority: Some(Authority {
                host: Host::RegName(EStr::new("ftp.is.co.za")),
                ..Authority::EMPTY
            }),
            path: "/rfc/rfc1808.txt",
            ..UriRef::EMPTY
        })
    );

    assert_eq!(
        UriRef::parse("http://www.ietf.org/rfc/rfc2396.txt"),
        Ok(UriRef {
            scheme: Some("http"),
            authority: Some(Authority {
                host: Host::RegName(EStr::new("www.ietf.org")),
                ..Authority::EMPTY
            }),
            path: "/rfc/rfc2396.txt",
            ..UriRef::EMPTY
        })
    );

    assert_eq!(
        UriRef::parse("ldap://[2001:db8::7]/c=GB?objectClass?one"),
        Ok(UriRef {
            scheme: Some("ldap"),
            authority: Some(Authority {
                host: Host::Ipv6 {
                    addr: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x7),
                    zone_id: None,
                },
                ..Authority::EMPTY
            }),
            path: "/c=GB",
            query: Some("objectClass?one"),
            fragment: None,
        })
    );

    assert_eq!(
        UriRef::parse("mailto:John.Doe@example.com"),
        Ok(UriRef {
            scheme: Some("mailto"),
            path: "John.Doe@example.com",
            ..UriRef::EMPTY
        })
    );

    assert_eq!(
        UriRef::parse("news:comp.infosystems.www.servers.unix"),
        Ok(UriRef {
            scheme: Some("news"),
            path: "comp.infosystems.www.servers.unix",
            ..UriRef::EMPTY
        })
    );

    assert_eq!(
        UriRef::parse("tel:+1-816-555-1212"),
        Ok(UriRef {
            scheme: Some("tel"),
            path: "+1-816-555-1212",
            ..UriRef::EMPTY
        })
    );

    assert_eq!(
        UriRef::parse("telnet://192.0.2.16:80/"),
        Ok(UriRef {
            scheme: Some("telnet"),
            authority: Some(Authority {
                host: Host::Ipv4(Ipv4Addr::new(192, 0, 2, 16)),
                port: Some("80"),
                userinfo: None,
            }),
            path: "/",
            ..UriRef::EMPTY
        })
    );

    assert_eq!(
        UriRef::parse("urn:oasis:names:specification:docbook:dtd:xml:4.1.2"),
        Ok(UriRef {
            scheme: Some("urn"),
            path: "oasis:names:specification:docbook:dtd:xml:4.1.2",
            ..UriRef::EMPTY
        })
    );

    assert_eq!(
        UriRef::parse("foo://example.com:8042/over/there?name=ferret#nose"),
        Ok(UriRef {
            scheme: Some("foo"),
            authority: Some(Authority {
                host: Host::RegName(EStr::new("example.com")),
                port: Some("8042"),
                userinfo: None,
            }),
            path: "/over/there",
            query: Some("name=ferret"),
            fragment: Some("nose"),
        })
    );

    assert_eq!(
        UriRef::parse("ftp://cnn.example.com&story=breaking_news@10.0.0.1/top_story.htm"),
        Ok(UriRef {
            scheme: Some("ftp"),
            authority: Some(Authority {
                host: Host::Ipv4(Ipv4Addr::new(10, 0, 0, 1)),
                port: None,
                userinfo: Some("cnn.example.com&story=breaking_news"),
            }),
            path: "/top_story.htm",
            ..UriRef::EMPTY
        })
    );

    assert_eq!(
        UriRef::parse("http://[vFe.foo.bar]"),
        Ok(UriRef {
            scheme: Some("http"),
            authority: Some(Authority {
                host: Host::IpvFuture {
                    ver: "Fe",
                    addr: "foo.bar",
                },
                ..Authority::EMPTY
            }),
            ..UriRef::EMPTY
        })
    );

    assert_eq!(
        UriRef::parse("http://[fe80::520f:f5ff:fe51:cf0%2517]"),
        Ok(UriRef {
            scheme: Some("http"),
            authority: Some(Authority {
                host: Host::Ipv6 {
                    addr: Ipv6Addr::new(0xfe80, 0, 0, 0, 0x520f, 0xf5ff, 0xfe51, 0xcf0),
                    zone_id: Some(EStr::new("17")),
                },
                ..Authority::EMPTY
            }),
            ..UriRef::EMPTY
        })
    );

    let u = UriRef::parse("http://127.0.0.1:/").unwrap();
    let auth = u.authority().unwrap();
    assert_eq!(auth.port_raw(), Some(""));
    assert_eq!(auth.port(), None);

    let u = UriRef::parse("http://127.0.0.1:8080/").unwrap();
    let auth = u.authority().unwrap();
    assert_eq!(auth.port(), Some(Ok(8080)));

    let u = UriRef::parse("http://127.0.0.1:80808/").unwrap();
    let auth = u.authority().unwrap();
    assert_eq!(auth.port(), Some(Err("80808")));
}

#[test]
fn parse_relative() {
    assert_eq!(UriRef::parse(""), Ok(UriRef::EMPTY));

    assert_eq!(
        UriRef::parse("foo.txt"),
        Ok(UriRef {
            path: "foo.txt",
            ..UriRef::EMPTY
        })
    );

    assert_eq!(
        UriRef::parse("."),
        Ok(UriRef {
            path: ".",
            ..UriRef::EMPTY
        })
    );

    assert_eq!(
        UriRef::parse("./this:that"),
        Ok(UriRef {
            path: "./this:that",
            ..UriRef::EMPTY
        })
    );

    assert_eq!(
        UriRef::parse("//example.com"),
        Ok(UriRef {
            authority: Some(Authority {
                host: Host::RegName(EStr::new("example.com")),
                ..Authority::EMPTY
            }),
            ..UriRef::EMPTY
        })
    );

    assert_eq!(
        UriRef::parse("?query"),
        Ok(UriRef {
            query: Some("query"),
            ..UriRef::EMPTY
        })
    );

    assert_eq!(
        UriRef::parse("#fragment"),
        Ok(UriRef {
            fragment: Some("fragment"),
            ..UriRef::EMPTY
        })
    );
}

#[test]
fn parse_error() {
    // Empty scheme
    let e = UriRef::parse(":hello").unwrap_err();
    assert_eq!(e.index(), 0);
    assert_eq!(e.kind(), UnexpectedChar);

    // Scheme starts with non-letter
    let e = UriRef::parse("3ttp://a.com").unwrap_err();
    assert_eq!(e.index(), 0);
    assert_eq!(e.kind(), UnexpectedChar);

    // Unexpected char in scheme
    let e = UriRef::parse("exam=ple:foo").unwrap_err();
    assert_eq!(e.index(), 4);
    assert_eq!(e.kind(), UnexpectedChar);

    // Percent-encoded scheme
    let e = UriRef::parse("a%20:foo").unwrap_err();
    assert_eq!(e.index(), 1);
    assert_eq!(e.kind(), UnexpectedChar);

    // Unexpected char in path
    let e = UriRef::parse("foo\\bar").unwrap_err();
    assert_eq!(e.index(), 3);
    assert_eq!(e.kind(), UnexpectedChar);

    // Non-hexadecimal percent-encoded octet
    let e = UriRef::parse("foo%xxd").unwrap_err();
    assert_eq!(e.index(), 3);
    assert_eq!(e.kind(), InvalidOctet);

    // Incomplete percent-encoded octet
    let e = UriRef::parse("text%a").unwrap_err();
    assert_eq!(e.index(), 4);
    assert_eq!(e.kind(), InvalidOctet);

    // Unclosed bracket
    let e = UriRef::parse("https://[::1/").unwrap_err();
    assert_eq!(e.index(), 8);
    assert_eq!(e.kind(), UnclosedBracket);

    // Not port after IP literal
    let e = UriRef::parse("https://[::1]wrong").unwrap_err();
    assert_eq!(e.index(), 13);
    assert_eq!(e.kind(), UnexpectedChar);

    // Non-decimal port
    let e = UriRef::parse("http://127.0.0.1:abcd").unwrap_err();
    assert_eq!(e.index(), 17);
    assert_eq!(e.kind(), UnexpectedChar);

    // IP literal too short
    let e = UriRef::parse("http://[:]").unwrap_err();
    assert_eq!(e.index(), 8);
    assert_eq!(e.kind(), UnexpectedChar);
    let e = UriRef::parse("http://[]").unwrap_err();
    assert_eq!(e.index(), 8);
    assert_eq!(e.kind(), UnexpectedChar);

    // Non-hexadecimal version in IPvFuture
    let e = UriRef::parse("http://[vG.addr]").unwrap_err();
    assert_eq!(e.index(), 9);
    assert_eq!(e.kind(), UnexpectedChar);

    // Empty version in IPvFuture
    let e = UriRef::parse("http://[v.addr]").unwrap_err();
    assert_eq!(e.index(), 8);
    assert_eq!(e.kind(), InvalidIpvFuture);

    // Empty address in IPvFuture
    let e = UriRef::parse("ftp://[vF.]").unwrap_err();
    assert_eq!(e.index(), 7);
    assert_eq!(e.kind(), InvalidIpvFuture);

    // Percent-encoded address in IPvFuture
    let e = UriRef::parse("ftp://[vF.%20]").unwrap_err();
    assert_eq!(e.index(), 10);
    assert_eq!(e.kind(), UnexpectedChar);

    // Ill-preceded Zone ID
    let e = UriRef::parse("ftp://[::1%240]").unwrap_err();
    assert_eq!(e.index(), 10);
    assert_eq!(e.kind(), IllPrecededOrEmptyZoneID);

    // Empty Zone ID
    let e = UriRef::parse("ftp://[::1%25]").unwrap_err();
    assert_eq!(e.index(), 10);
    assert_eq!(e.kind(), IllPrecededOrEmptyZoneID);

    // Invalid IPv6 address
    let e = UriRef::parse("example://[44:55::66::77]").unwrap_err();
    assert_eq!(e.index(), 11);
    assert_eq!(e.kind(), InvalidIpv6);
}

#[test]
fn strict_ip_addr() {
    let u = UriRef::parse("//127.0.0.001").unwrap();
    let host = u.authority().unwrap().host();
    assert!(matches!(host, Host::RegName(_)));

    let u = UriRef::parse("//127.1").unwrap();
    let host = u.authority().unwrap().host();
    assert!(matches!(host, Host::RegName(_)));

    let u = UriRef::parse("//127.00.00.1").unwrap();
    let host = u.authority().unwrap().host();
    assert!(matches!(host, Host::RegName(_)));

    assert!(UriRef::parse("//[::1.1.1.1]").is_ok());
    assert!(UriRef::parse("//[::ffff:1.1.1.1]").is_ok());
    assert!(UriRef::parse("//[0000:0000:0000:0000:0000:0000:255.255.255.255]").is_ok());

    assert_eq!(
        UriRef::parse("//[::01.1.1.1]").unwrap_err().kind(),
        InvalidIpv6
    );
    assert_eq!(
        UriRef::parse("//[::00.1.1.1]").unwrap_err().kind(),
        InvalidIpv6
    );
}
