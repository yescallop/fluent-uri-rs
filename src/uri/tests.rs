use super::*;

#[test]
fn parse() {
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
                host: Host::RegName("ftp.is.co.za"),
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
                host: Host::RegName("www.ietf.org"),
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
                host: Host::RegName("example.com"),
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
                    zone_id: Some(unsafe { EStr::new_unchecked("17") }),
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

    assert!(UriRef::parse("//[::01.1.1.1]").is_err());
    assert!(UriRef::parse("//[::00.1.1.1]").is_err());
}
