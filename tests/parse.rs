#[cfg(feature = "net")]
use core::net::{Ipv4Addr, Ipv6Addr};

use fluent_uri::{component::Host, encoding::EStr, Uri};

#[test]
fn parse_absolute() {
    let u = Uri::parse("file:///etc/hosts").unwrap();
    assert_eq!(u.as_str(), "file:///etc/hosts");
    assert_eq!(u.scheme().unwrap().as_str(), "file");
    let a = u.authority().unwrap();
    assert_eq!(a.as_str(), "");
    assert_eq!(a.userinfo(), None);
    assert_eq!(a.host(), "");
    assert!(matches!(a.host_parsed(), Host::RegName(n) if n == ""));
    assert_eq!(a.port(), None);
    assert_eq!(u.path(), "/etc/hosts");
    assert_eq!(u.query(), None);
    assert_eq!(u.fragment(), None);

    let u = Uri::parse("ftp://ftp.is.co.za/rfc/rfc1808.txt").unwrap();
    assert_eq!(u.scheme().unwrap().as_str(), "ftp");
    let a = u.authority().unwrap();
    assert_eq!(a.as_str(), "ftp.is.co.za");
    assert_eq!(a.userinfo(), None);
    assert_eq!(a.host(), "ftp.is.co.za");
    assert!(matches!(a.host_parsed(), Host::RegName(name) if name == "ftp.is.co.za"));
    assert_eq!(a.port(), None);
    assert_eq!(u.path(), "/rfc/rfc1808.txt");
    assert_eq!(u.query(), None);
    assert_eq!(u.fragment(), None);

    let u = Uri::parse("http://www.ietf.org/rfc/rfc2396.txt").unwrap();
    assert_eq!(u.scheme().unwrap().as_str(), "http");
    let a = u.authority().unwrap();
    assert_eq!(a.as_str(), "www.ietf.org");
    assert_eq!(a.userinfo(), None);
    assert_eq!(a.host(), "www.ietf.org");
    assert!(matches!(a.host_parsed(), Host::RegName(name) if name == "www.ietf.org"));
    assert_eq!(a.port(), None);
    assert_eq!(u.path(), "/rfc/rfc2396.txt");
    assert_eq!(u.query(), None);
    assert_eq!(u.fragment(), None);

    let u = Uri::parse("ldap://[2001:db8::7]/c=GB?objectClass?one").unwrap();
    assert_eq!(u.scheme().unwrap().as_str(), "ldap");
    let a = u.authority().unwrap();
    assert_eq!(a.as_str(), "[2001:db8::7]");
    assert_eq!(a.userinfo(), None);
    assert_eq!(a.host(), "[2001:db8::7]");
    #[cfg(feature = "net")]
    assert!(matches!(
        a.host_parsed(),
        Host::Ipv6(addr) if addr == Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x7)
    ));
    assert_eq!(a.port(), None);
    assert_eq!(u.path(), "/c=GB");
    assert_eq!(u.query(), Some(EStr::new("objectClass?one")));
    assert_eq!(u.fragment(), None);

    let u = Uri::parse("mailto:John.Doe@example.com").unwrap();
    assert_eq!(u.scheme().unwrap().as_str(), "mailto");
    assert!(u.authority().is_none());
    assert_eq!(u.path(), "John.Doe@example.com");
    assert_eq!(u.query(), None);
    assert_eq!(u.fragment(), None);

    let u = Uri::parse("news:comp.infosystems.www.servers.unix").unwrap();
    assert_eq!(u.scheme().unwrap().as_str(), "news");
    assert!(u.authority().is_none());
    assert_eq!(u.path(), "comp.infosystems.www.servers.unix");
    assert_eq!(u.query(), None);
    assert_eq!(u.fragment(), None);

    let u = Uri::parse("tel:+1-816-555-1212").unwrap();
    assert_eq!(u.scheme().unwrap().as_str(), "tel");
    assert!(u.authority().is_none());
    assert_eq!(u.path(), "+1-816-555-1212");
    assert_eq!(u.query(), None);
    assert_eq!(u.fragment(), None);

    let u = Uri::parse("telnet://192.0.2.16:80/").unwrap();
    assert_eq!(u.scheme().unwrap().as_str(), "telnet");
    let a = u.authority().unwrap();
    assert_eq!(a.as_str(), "192.0.2.16:80");
    assert_eq!(a.userinfo(), None);
    assert_eq!(a.host(), "192.0.2.16");
    #[cfg(feature = "net")]
    assert!(matches!(a.host_parsed(), Host::Ipv4(addr) if addr == Ipv4Addr::new(192, 0, 2, 16)));
    assert_eq!(a.port(), Some("80"));
    assert_eq!(u.path(), "/");
    assert_eq!(u.query(), None);
    assert_eq!(u.fragment(), None);

    let u = Uri::parse("urn:oasis:names:specification:docbook:dtd:xml:4.1.2").unwrap();
    assert_eq!(u.scheme().unwrap().as_str(), "urn");
    assert!(u.authority().is_none());
    assert_eq!(u.path(), "oasis:names:specification:docbook:dtd:xml:4.1.2");
    assert_eq!(u.query(), None);
    assert_eq!(u.fragment(), None);

    let u = Uri::parse("foo://example.com:8042/over/there?name=ferret#nose").unwrap();
    assert_eq!(u.scheme().unwrap().as_str(), "foo");
    let a = u.authority().unwrap();
    assert_eq!(a.as_str(), "example.com:8042");
    assert_eq!(a.userinfo(), None);
    assert_eq!(a.host(), "example.com");
    assert!(matches!(a.host_parsed(), Host::RegName(name) if name == "example.com"));
    assert_eq!(a.port(), Some("8042"));
    assert_eq!(u.path(), "/over/there");
    assert_eq!(u.query(), Some(EStr::new("name=ferret")));
    assert_eq!(u.fragment(), Some(EStr::new("nose")));

    let u = Uri::parse("ftp://cnn.example.com&story=breaking_news@10.0.0.1/top_story.htm").unwrap();
    assert_eq!(u.scheme().unwrap().as_str(), "ftp");
    let a = u.authority().unwrap();
    assert_eq!(a.as_str(), "cnn.example.com&story=breaking_news@10.0.0.1");
    assert_eq!(
        a.userinfo(),
        Some(EStr::new("cnn.example.com&story=breaking_news"))
    );
    assert_eq!(a.host(), "10.0.0.1");
    #[cfg(feature = "net")]
    assert!(matches!(a.host_parsed(), Host::Ipv4(addr) if addr == Ipv4Addr::new(10, 0, 0, 1)));
    assert_eq!(a.port(), None);
    assert_eq!(u.path(), "/top_story.htm");
    assert_eq!(u.query(), None);
    assert_eq!(u.fragment(), None);

    let u = Uri::parse("http://[vFe.foo.bar]").unwrap();
    assert_eq!(u.scheme().unwrap().as_str(), "http");
    let a = u.authority().unwrap();
    assert_eq!(a.as_str(), "[vFe.foo.bar]");
    assert_eq!(a.userinfo(), None);
    assert_eq!(a.host(), "[vFe.foo.bar]");
    assert!(matches!(a.host_parsed(), Host::IpvFuture { .. }));
    assert_eq!(a.port(), None);
    assert_eq!(u.path(), "");
    assert_eq!(u.query(), None);
    assert_eq!(u.fragment(), None);

    let u = Uri::parse("http://127.0.0.1:/").unwrap();
    assert_eq!(u.scheme().unwrap().as_str(), "http");
    let a = u.authority().unwrap();
    assert_eq!(a.as_str(), "127.0.0.1:");
    assert_eq!(a.userinfo(), None);
    assert_eq!(a.host(), "127.0.0.1");
    #[cfg(feature = "net")]
    assert!(matches!(a.host_parsed(), Host::Ipv4(addr) if addr == Ipv4Addr::new(127, 0, 0, 1)));
    assert_eq!(a.port(), Some(""));
    assert_eq!(u.path(), "/");
    assert_eq!(u.query(), None);
    assert_eq!(u.fragment(), None);

    let u = Uri::parse("http://127.0.0.1:8080/").unwrap();
    assert_eq!(u.scheme().unwrap().as_str(), "http");
    let a = u.authority().unwrap();
    assert_eq!(a.as_str(), "127.0.0.1:8080");
    assert_eq!(a.userinfo(), None);
    assert_eq!(a.host(), "127.0.0.1");
    #[cfg(feature = "net")]
    assert!(matches!(a.host_parsed(), Host::Ipv4(addr) if addr == Ipv4Addr::new(127, 0, 0, 1)));
    assert_eq!(a.port(), Some("8080"));
    assert_eq!(u.path(), "/");
    assert_eq!(u.query(), None);
    assert_eq!(u.fragment(), None);

    let u = Uri::parse("http://127.0.0.1:80808/").unwrap();
    assert_eq!(u.scheme().unwrap().as_str(), "http");
    let a = u.authority().unwrap();
    assert_eq!(a.as_str(), "127.0.0.1:80808");
    assert_eq!(a.userinfo(), None);
    assert_eq!(a.host(), "127.0.0.1");
    #[cfg(feature = "net")]
    assert!(matches!(a.host_parsed(), Host::Ipv4(addr) if addr == Ipv4Addr::new(127, 0, 0, 1)));
    assert_eq!(a.port(), Some("80808"));
    assert_eq!(u.path(), "/");
    assert_eq!(u.query(), None);
    assert_eq!(u.fragment(), None);
}

#[test]
fn parse_relative() {
    let u = Uri::parse("").unwrap();
    assert!(u.scheme().is_none());
    assert!(u.authority().is_none());
    assert_eq!(u.path(), "");
    assert_eq!(u.query(), None);
    assert_eq!(u.fragment(), None);

    let u = Uri::parse("foo.txt").unwrap();
    assert!(u.scheme().is_none());
    assert!(u.authority().is_none());
    assert_eq!(u.path(), "foo.txt");
    assert_eq!(u.query(), None);
    assert_eq!(u.fragment(), None);

    let u = Uri::parse(".").unwrap();
    assert!(u.scheme().is_none());
    assert!(u.authority().is_none());
    assert_eq!(u.path(), ".");
    assert_eq!(u.query(), None);
    assert_eq!(u.fragment(), None);

    let u = Uri::parse("./this:that").unwrap();
    assert!(u.scheme().is_none());
    assert!(u.authority().is_none());
    assert_eq!(u.path(), "./this:that");
    assert_eq!(u.query(), None);
    assert_eq!(u.fragment(), None);

    let u = Uri::parse("//example.com").unwrap();
    assert!(u.scheme().is_none());
    let a = u.authority().unwrap();
    assert_eq!(a.as_str(), "example.com");
    assert_eq!(a.userinfo(), None);
    assert_eq!(a.host(), "example.com");
    assert!(matches!(a.host_parsed(), Host::RegName(name) if name == "example.com"));
    assert_eq!(a.port(), None);
    assert_eq!(u.path(), "");
    assert_eq!(u.query(), None);
    assert_eq!(u.fragment(), None);

    let u = Uri::parse("?query").unwrap();
    assert!(u.scheme().is_none());
    assert!(u.authority().is_none());
    assert_eq!(u.path(), "");
    assert_eq!(u.query(), Some(EStr::new("query")));
    assert_eq!(u.fragment(), None);

    let u = Uri::parse("#fragment").unwrap();
    assert!(u.scheme().is_none());
    assert!(u.authority().is_none());
    assert_eq!(u.path(), "");
    assert_eq!(u.query(), None);
    assert_eq!(u.fragment(), Some(EStr::new("fragment")));
}

#[test]
fn parse_error() {
    // Empty scheme
    let e = Uri::parse(":hello").unwrap_err();
    assert_eq!(e.to_string(), "unexpected character at index 0");

    // Scheme starts with non-letter
    let e = Uri::parse("3ttp://a.com").unwrap_err();
    assert_eq!(e.to_string(), "unexpected character at index 0");

    // After rewriting the parser, the following two cases are interpreted as
    // containing colon in the first path segment of a relative reference.

    // Unexpected char in scheme
    let e = Uri::parse("exam=ple:foo").unwrap_err();
    assert_eq!(e.to_string(), "unexpected character at index 8");

    let e = Uri::parse("(:").unwrap_err();
    assert_eq!(e.to_string(), "unexpected character at index 1");

    // Percent-encoded scheme
    let e = Uri::parse("a%20:foo").unwrap_err();
    assert_eq!(e.to_string(), "unexpected character at index 4");

    // Unexpected char in path
    let e = Uri::parse("foo\\bar").unwrap_err();
    assert_eq!(e.to_string(), "unexpected character at index 3");

    // Non-hexadecimal percent-encoded octet
    let e = Uri::parse("foo%xxd").unwrap_err();
    assert_eq!(e.to_string(), "invalid percent-encoded octet at index 3");

    // Incomplete percent-encoded octet
    let e = Uri::parse("text%a").unwrap_err();
    assert_eq!(e.to_string(), "invalid percent-encoded octet at index 4");

    // A single percent
    let e = Uri::parse("%").unwrap_err();
    assert_eq!(e.to_string(), "invalid percent-encoded octet at index 0");

    // Non-decimal port
    let e = Uri::parse("http://example.com:80ab").unwrap_err();
    assert_eq!(e.to_string(), "unexpected character at index 21");

    let e = Uri::parse("http://user@example.com:80ab").unwrap_err();
    assert_eq!(e.to_string(), "unexpected character at index 26");

    // Multiple colons in authority
    let e = Uri::parse("http://user:pass:example.com/").unwrap_err();
    assert_eq!(e.to_string(), "unexpected character at index 16");

    // Unclosed bracket
    let e = Uri::parse("https://[::1/").unwrap_err();
    assert_eq!(e.to_string(), "unexpected character at index 12");

    // Not port after IP literal
    let e = Uri::parse("https://[::1]wrong").unwrap_err();
    assert_eq!(e.to_string(), "unexpected character at index 13");

    // IP literal too short
    let e = Uri::parse("http://[:]").unwrap_err();
    assert_eq!(e.to_string(), "invalid IPv6 address at index 8");
    let e = Uri::parse("http://[]").unwrap_err();
    assert_eq!(e.to_string(), "unexpected character at index 8");

    // Non-hexadecimal version in IPvFuture
    let e = Uri::parse("http://[vG.addr]").unwrap_err();
    assert_eq!(e.to_string(), "unexpected character at index 9");

    // Empty version in IPvFuture
    let e = Uri::parse("http://[v.addr]").unwrap_err();
    assert_eq!(e.to_string(), "unexpected character at index 9");

    // Empty address in IPvFuture
    let e = Uri::parse("ftp://[vF.]").unwrap_err();
    assert_eq!(e.to_string(), "unexpected character at index 10");

    // Percent-encoded address in IPvFuture
    let e = Uri::parse("ftp://[vF.%20]").unwrap_err();
    assert_eq!(e.to_string(), "unexpected character at index 10");

    // With zone identifier
    let e = Uri::parse("ftp://[fe80::abcd%eth0]").unwrap_err();
    assert_eq!(e.to_string(), "unexpected character at index 17");

    // Invalid IPv6 address
    let e = Uri::parse("example://[44:55::66::77]").unwrap_err();
    assert_eq!(e.to_string(), "invalid IPv6 address at index 11");
}

#[test]
fn strict_ip_addr() {
    let u = Uri::parse("//127.0.0.001").unwrap();
    let a = u.authority().unwrap();
    assert!(matches!(a.host_parsed(), Host::RegName(_)));

    let u = Uri::parse("//127.1").unwrap();
    let a = u.authority().unwrap();
    assert!(matches!(a.host_parsed(), Host::RegName(_)));

    let u = Uri::parse("//127.00.00.1").unwrap();
    let a = u.authority().unwrap();
    assert!(matches!(a.host_parsed(), Host::RegName(_)));

    assert!(Uri::parse("//[::1.1.1.1]").is_ok());
    assert!(Uri::parse("//[::ffff:1.1.1.1]").is_ok());
    assert!(Uri::parse("//[0000:0000:0000:0000:0000:0000:255.255.255.255]").is_ok());

    assert_eq!(
        Uri::parse("//[::01.1.1.1]").unwrap_err().to_string(),
        "invalid IPv6 address at index 3"
    );
    assert_eq!(
        Uri::parse("//[::00.1.1.1]").unwrap_err().to_string(),
        "invalid IPv6 address at index 3"
    );
}
