#[cfg(feature = "net")]
use core::net::{Ipv4Addr, Ipv6Addr};

#[cfg(feature = "net")]
use fluent_uri::component::Host;

use fluent_uri::Uri;
use fluent_uri::error::ResolveErrorKind;


#[test]
fn normalize() {
    // Example from Section 6.2 of RFC 3986.
    let u = Uri::parse("eXAMPLE://a/./b/../b/%63/%7bfoo%7d").unwrap();
    assert_eq!(u.checked_normalize().unwrap(), "example://a/b/c/%7Bfoo%7D");

    // Lowercase percent-encoded octet.
    let u = Uri::parse("%3a").unwrap();
    assert_eq!(u.checked_normalize().unwrap(), "%3A");

    // Uppercase letters in scheme and registered name.
    let u = Uri::parse("HTTP://www.EXAMPLE.com/").unwrap();
    assert_eq!(u.checked_normalize().unwrap(), "http://www.example.com/");

    // Empty port.
    let u = Uri::parse("http://example.com:/").unwrap();
    assert_eq!(u.checked_normalize().unwrap(), "http://example.com/");

    // Underflow in path resolution.
    let u = Uri::parse("http://a/../../../g").unwrap();
    assert!(matches!(u.checked_normalize().unwrap_err().0, ResolveErrorKind::PathUnderflow));

    // Percent-encoded dot segments.
    let u = Uri::parse("http://a/b/c/%2E/%2E./%2e%2E/d").unwrap();
    assert_eq!(u.checked_normalize().unwrap(), "http://a/d");

    // Don't remove dot segments from relative reference or rootless path.
    let u = Uri::parse("foo/../bar").unwrap();
    assert_eq!(u.checked_normalize().unwrap(), "foo/../bar");

    let u = Uri::parse("/foo/../bar").unwrap();
    assert_eq!(u.checked_normalize().unwrap(), "/foo/../bar");

    let u = Uri::parse("foo:bar/../baz").unwrap();
    assert_eq!(u.checked_normalize().unwrap(), "foo:bar/../baz");

    // Do remove dot segments for a URI with absolute path.
    let u = Uri::parse("foo:/bar/./../baz").unwrap();
    assert_eq!(u.checked_normalize().unwrap(), "foo:/baz");

    // However, make sure that the output is a valid URI reference.
    let u = Uri::parse("foo:/.//@@").unwrap();
    assert_eq!(u.checked_normalize().unwrap(), "foo:/.//@@");

    // Percent-encoded uppercase letters in registered name.
    let u = Uri::parse("HTTP://%45XAMPLE.%43Om").unwrap();
    assert_eq!(u.checked_normalize().unwrap(), "http://example.com");

    // Percent-encoded unreserved characters.
    let u = Uri::parse("%41%42%43%44%45%46%47%48%49%4A%4B%4C%4D%4E%4F%50%51%52%53%54%55%56%57%58%59%5A%61%62%63%64%65%66%67%68%69%6A%6B%6C%6D%6E%6F%70%71%72%73%74%75%76%77%78%79%7A%30%31%32%33%34%35%36%37%38%39%2D%2E%5F%7E").unwrap();
    assert_eq!(
        u.checked_normalize().unwrap(),
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    );

    // Percent-encoded reserved characters.
    let u = Uri::parse("%3A%2F%3F%23%5B%5D%40%21%24%26%27%28%29%2A%2B%2C%3B%3D%25").unwrap();
    assert_eq!(u.checked_normalize().unwrap(), u);

    // Builder example.
    let u = Uri::parse("foo://user@example.com:8042/over/there?name=ferret#nose").unwrap();
    assert_eq!(u.checked_normalize().unwrap(), u);

    // Normalization in all components.
    let u = Uri::parse("FOO://%55se%72@EXamp%4ce%2ecom:8042/%4b%2f?%4c%2b#%24%4d").unwrap();
    assert_eq!(u.checked_normalize().unwrap(), "foo://User@example.com:8042/K%2F?L%2B#%24M");

    // Normal IPv4 address.
    let u = Uri::parse("//127.0.0.1").unwrap();
    assert_eq!(u.checked_normalize().unwrap(), "//127.0.0.1");
    #[cfg(feature = "net")]
    assert!(matches!(
        u.checked_normalize().unwrap().authority().unwrap().host_parsed(),
        Host::Ipv4(Ipv4Addr::LOCALHOST)
    ));

    // Percent-encoded IPv4 address.
    let u = Uri::parse("//127.0.0.%31").unwrap();
    assert_eq!(u.checked_normalize().unwrap(), "//127.0.0.1");
    #[cfg(feature = "net")]
    assert!(matches!(
        u.checked_normalize().unwrap().authority().unwrap().host_parsed(),
        Host::Ipv4(Ipv4Addr::LOCALHOST)
    ));

    // Normal IPv6 address.
    let u = Uri::parse("//[::1]").unwrap();
    assert_eq!(u.checked_normalize().unwrap(), "//[::1]");
    #[cfg(feature = "net")]
    assert!(matches!(
        u.checked_normalize().unwrap().authority().unwrap().host_parsed(),
        Host::Ipv6(Ipv6Addr::LOCALHOST)
    ));

    // Verbose IPv6 address.
    let u = Uri::parse("//[0000:0000:0000::1]").unwrap();
    assert_eq!(u.checked_normalize().unwrap(), "//[::1]");
    #[cfg(feature = "net")]
    assert!(matches!(
        u.checked_normalize().unwrap().authority().unwrap().host_parsed(),
        Host::Ipv6(Ipv6Addr::LOCALHOST)
    ));

    // IPv4-mapped IPv6 address.
    let u = Uri::parse("//[0:0:0:0:0:ffff:192.0.2.1]").unwrap();
    assert_eq!(u.checked_normalize().unwrap(), "//[::ffff:192.0.2.1]");

    // Deprecated IPv4-compatible IPv6 address.
    let u = Uri::parse("//[::192.0.2.1]").unwrap();
    assert_eq!(u.checked_normalize().unwrap(), "//[::c000:201]");

    // IPvFuture address.
    let u = Uri::parse("//[v1FdE.AddR]").unwrap();
    assert_eq!(u.checked_normalize().unwrap(), "//[v1fde.addr]");
}
