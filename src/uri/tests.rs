use super::{SyntaxErrorKind::*, *};

#[test]
fn parse_absolute() {
    assert_eq!(
        Uri::parse("file:///etc/hosts"),
        Ok(Uri {
            scheme: Some("file"),
            authority: Some(Authority::EMPTY),
            path: "/etc/hosts",
            ..Uri::EMPTY
        })
    );

    assert_eq!(
        Uri::parse("ftp://ftp.is.co.za/rfc/rfc1808.txt"),
        Ok(Uri {
            scheme: Some("ftp"),
            authority: Some(Authority {
                host: Host::RegName(EStr::new("ftp.is.co.za")),
                ..Authority::EMPTY
            }),
            path: "/rfc/rfc1808.txt",
            ..Uri::EMPTY
        })
    );

    assert_eq!(
        Uri::parse("http://www.ietf.org/rfc/rfc2396.txt"),
        Ok(Uri {
            scheme: Some("http"),
            authority: Some(Authority {
                host: Host::RegName(EStr::new("www.ietf.org")),
                ..Authority::EMPTY
            }),
            path: "/rfc/rfc2396.txt",
            ..Uri::EMPTY
        })
    );

    assert_eq!(
        Uri::parse("ldap://[2001:db8::7]/c=GB?objectClass?one"),
        Ok(Uri {
            scheme: Some("ldap"),
            authority: Some(Authority {
                host: Host::Ipv6 {
                    addr: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x7),
                    // zone_id: None,
                },
                ..Authority::EMPTY
            }),
            path: "/c=GB",
            query: Some("objectClass?one"),
            fragment: None,
        })
    );

    assert_eq!(
        Uri::parse("mailto:John.Doe@example.com"),
        Ok(Uri {
            scheme: Some("mailto"),
            path: "John.Doe@example.com",
            ..Uri::EMPTY
        })
    );

    assert_eq!(
        Uri::parse("news:comp.infosystems.www.servers.unix"),
        Ok(Uri {
            scheme: Some("news"),
            path: "comp.infosystems.www.servers.unix",
            ..Uri::EMPTY
        })
    );

    assert_eq!(
        Uri::parse("tel:+1-816-555-1212"),
        Ok(Uri {
            scheme: Some("tel"),
            path: "+1-816-555-1212",
            ..Uri::EMPTY
        })
    );

    assert_eq!(
        Uri::parse("telnet://192.0.2.16:80/"),
        Ok(Uri {
            scheme: Some("telnet"),
            authority: Some(Authority {
                host: Host::Ipv4(Ipv4Addr::new(192, 0, 2, 16)),
                port: Some("80"),
                userinfo: None,
            }),
            path: "/",
            ..Uri::EMPTY
        })
    );

    assert_eq!(
        Uri::parse("urn:oasis:names:specification:docbook:dtd:xml:4.1.2"),
        Ok(Uri {
            scheme: Some("urn"),
            path: "oasis:names:specification:docbook:dtd:xml:4.1.2",
            ..Uri::EMPTY
        })
    );

    assert_eq!(
        Uri::parse("foo://example.com:8042/over/there?name=ferret#nose"),
        Ok(Uri {
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
        Uri::parse("ftp://cnn.example.com&story=breaking_news@10.0.0.1/top_story.htm"),
        Ok(Uri {
            scheme: Some("ftp"),
            authority: Some(Authority {
                host: Host::Ipv4(Ipv4Addr::new(10, 0, 0, 1)),
                port: None,
                userinfo: Some("cnn.example.com&story=breaking_news"),
            }),
            path: "/top_story.htm",
            ..Uri::EMPTY
        })
    );

    assert_eq!(
        Uri::parse("http://[vFe.foo.bar]"),
        Ok(Uri {
            scheme: Some("http"),
            authority: Some(Authority {
                host: Host::IpvFuture {
                    ver: "Fe",
                    addr: "foo.bar",
                },
                ..Authority::EMPTY
            }),
            ..Uri::EMPTY
        })
    );

    // assert_eq!(
    //     Uri::parse("http://[fe80::520f:f5ff:fe51:cf0%2517]"),
    //     Ok(Uri {
    //         scheme: Some("http"),
    //         authority: Some(Authority {
    //             host: Host::Ipv6 {
    //                 addr: Ipv6Addr::new(0xfe80, 0, 0, 0, 0x520f, 0xf5ff, 0xfe51, 0xcf0),
    //                 zone_id: Some(EStr::new("17")),
    //             },
    //             ..Authority::EMPTY
    //         }),
    //         ..Uri::EMPTY
    //     })
    // );

    let u = Uri::parse("http://127.0.0.1:/").unwrap();
    let auth = u.authority().unwrap();
    assert_eq!(auth.port_raw(), Some(""));
    assert_eq!(auth.port(), None);

    let u = Uri::parse("http://127.0.0.1:8080/").unwrap();
    let auth = u.authority().unwrap();
    assert_eq!(auth.port(), Some(Ok(8080)));

    let u = Uri::parse("http://127.0.0.1:80808/").unwrap();
    let auth = u.authority().unwrap();
    assert_eq!(auth.port(), Some(Err("80808")));
}

#[test]
fn parse_relative() {
    assert_eq!(Uri::parse(""), Ok(Uri::EMPTY));

    assert_eq!(
        Uri::parse("foo.txt"),
        Ok(Uri {
            path: "foo.txt",
            ..Uri::EMPTY
        })
    );

    assert_eq!(
        Uri::parse("."),
        Ok(Uri {
            path: ".",
            ..Uri::EMPTY
        })
    );

    assert_eq!(
        Uri::parse("./this:that"),
        Ok(Uri {
            path: "./this:that",
            ..Uri::EMPTY
        })
    );

    assert_eq!(
        Uri::parse("//example.com"),
        Ok(Uri {
            authority: Some(Authority {
                host: Host::RegName(EStr::new("example.com")),
                ..Authority::EMPTY
            }),
            ..Uri::EMPTY
        })
    );

    assert_eq!(
        Uri::parse("?query"),
        Ok(Uri {
            query: Some("query"),
            ..Uri::EMPTY
        })
    );

    assert_eq!(
        Uri::parse("#fragment"),
        Ok(Uri {
            fragment: Some("fragment"),
            ..Uri::EMPTY
        })
    );
}

#[test]
fn parse_error() {
    // Empty scheme
    let e = Uri::parse(":hello").unwrap_err();
    assert_eq!(e.index(), 0);
    assert_eq!(e.kind(), UnexpectedChar);

    // Scheme starts with non-letter
    let e = Uri::parse("3ttp://a.com").unwrap_err();
    assert_eq!(e.index(), 0);
    assert_eq!(e.kind(), UnexpectedChar);

    // After rewriting the parser, the following two cases are interpreted as
    // containing colon in the first path segment of a relative reference.

    // Unexpected char in scheme
    let e = Uri::parse("exam=ple:foo").unwrap_err();
    assert_eq!(e.index(), 8);
    assert_eq!(e.kind(), UnexpectedChar);

    // Percent-encoded scheme
    let e = Uri::parse("a%20:foo").unwrap_err();
    assert_eq!(e.index(), 4);
    assert_eq!(e.kind(), UnexpectedChar);

    // Unexpected char in path
    let e = Uri::parse("foo\\bar").unwrap_err();
    assert_eq!(e.index(), 3);
    assert_eq!(e.kind(), UnexpectedChar);

    // Non-hexadecimal percent-encoded octet
    let e = Uri::parse("foo%xxd").unwrap_err();
    assert_eq!(e.index(), 3);
    assert_eq!(e.kind(), InvalidOctet);

    // Incomplete percent-encoded octet
    let e = Uri::parse("text%a").unwrap_err();
    assert_eq!(e.index(), 4);
    assert_eq!(e.kind(), InvalidOctet);

    // Non-decimal port
    // In this case the port is validated in reverse.
    let e = Uri::parse("http://example.com:80ab").unwrap_err();
    assert_eq!(e.index(), 22);
    assert_eq!(e.kind(), UnexpectedChar);

    let e = Uri::parse("http://user@example.com:80ab").unwrap_err();
    assert_eq!(e.index(), 26);
    assert_eq!(e.kind(), UnexpectedChar);

    // Unclosed bracket
    let e = Uri::parse("https://[::1/").unwrap_err();
    assert_eq!(e.index(), 8);
    assert_eq!(e.kind(), InvalidIpLiteral);

    // Not port after IP literal
    let e = Uri::parse("https://[::1]wrong").unwrap_err();
    assert_eq!(e.index(), 13);
    assert_eq!(e.kind(), UnexpectedChar);

    // IP literal too short
    let e = Uri::parse("http://[:]").unwrap_err();
    assert_eq!(e.index(), 7);
    assert_eq!(e.kind(), InvalidIpLiteral);
    let e = Uri::parse("http://[]").unwrap_err();
    assert_eq!(e.index(), 7);
    assert_eq!(e.kind(), InvalidIpLiteral);

    // Non-hexadecimal version in IPvFuture
    let e = Uri::parse("http://[vG.addr]").unwrap_err();
    assert_eq!(e.index(), 7);
    assert_eq!(e.kind(), InvalidIpLiteral);

    // Empty version in IPvFuture
    let e = Uri::parse("http://[v.addr]").unwrap_err();
    assert_eq!(e.index(), 7);
    assert_eq!(e.kind(), InvalidIpLiteral);

    // Empty address in IPvFuture
    let e = Uri::parse("ftp://[vF.]").unwrap_err();
    assert_eq!(e.index(), 6);
    assert_eq!(e.kind(), InvalidIpLiteral);

    // Percent-encoded address in IPvFuture
    let e = Uri::parse("ftp://[vF.%20]").unwrap_err();
    assert_eq!(e.index(), 6);
    assert_eq!(e.kind(), InvalidIpLiteral);

    // Ill-preceded Zone ID
    let e = Uri::parse("ftp://[::1%240]").unwrap_err();
    assert_eq!(e.index(), 6);
    assert_eq!(e.kind(), InvalidIpLiteral);

    // Empty Zone ID
    let e = Uri::parse("ftp://[::1%25]").unwrap_err();
    assert_eq!(e.index(), 6);
    assert_eq!(e.kind(), InvalidIpLiteral);

    // Invalid IPv6 address
    let e = Uri::parse("example://[44:55::66::77]").unwrap_err();
    assert_eq!(e.index(), 10);
    assert_eq!(e.kind(), InvalidIpLiteral);
}

#[test]
fn strict_ip_addr() {
    let u = Uri::parse("//127.0.0.001").unwrap();
    let host = u.authority().unwrap().host();
    assert!(matches!(host, Host::RegName(_)));

    let u = Uri::parse("//127.1").unwrap();
    let host = u.authority().unwrap().host();
    assert!(matches!(host, Host::RegName(_)));

    let u = Uri::parse("//127.00.00.1").unwrap();
    let host = u.authority().unwrap().host();
    assert!(matches!(host, Host::RegName(_)));

    assert!(Uri::parse("//[::1.1.1.1]").is_ok());
    assert!(Uri::parse("//[::ffff:1.1.1.1]").is_ok());
    assert!(Uri::parse("//[0000:0000:0000:0000:0000:0000:255.255.255.255]").is_ok());

    assert_eq!(
        Uri::parse("//[::01.1.1.1]").unwrap_err().kind(),
        InvalidIpLiteral
    );
    assert_eq!(
        Uri::parse("//[::00.1.1.1]").unwrap_err().kind(),
        InvalidIpLiteral
    );
}
