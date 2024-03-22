# fluent-uri

A fast, easy generic URI parser and builder compliant with [RFC 3986].

[![crates.io](https://img.shields.io/crates/v/fluent-uri.svg)](https://crates.io/crates/fluent-uri)
[![CI](https://github.com/yescallop/fluent-uri-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/yescallop/fluent-uri-rs/actions/workflows/ci.yml)
[![license](https://img.shields.io/github/license/yescallop/fluent-uri-rs?color=blue)](/LICENSE)

- **Fast:** Zero-copy parsing. Faster than several common URI parsers in Rust[^bench-res].
- **Easy:** Carefully designed and documented APIs. Handy percent-encoding utilities.
- **Strict:** Parses every possible URI defined in RFC 3986 and denies anything else.

[API Docs](https://docs.rs/fluent-uri) | [Discussions](https://github.com/yescallop/fluent-uri-rs/discussions)

[RFC 3986]: https://datatracker.ietf.org/doc/html/rfc3986/
[^bench-res]: It took 59ns for `fluent-uri`, 89ns for `iref`, and 130ns for `iri-string` to
    parse the same URI in [a benchmark](https://github.com/yescallop/fluent-uri-rs/blob/main/bench/benches/bench.rs)
    on an Intel Core i5-11300H processor.

## Features & Examples

- `Uri<&str>` and `Uri<String>` (borrowed and owned variants of URI reference):

    You can parse into a `Uri<&str>` from a string slice.
    `Uri<&'a str>` outputs references with lifetime `'a` where possible
    (thanks to [`borrow-or-share`](https://github.com/yescallop/borrow-or-share)):

    ```rust
    // Keep a reference to the path after dropping the `Uri`.
    let path = Uri::parse("foo:bar")?.path();
    assert_eq!(path, "bar");
    ```

    You can build a `Uri<String>` using the builder pattern:

    ```rust
    let uri: Uri<String> = Uri::builder()
        .scheme(Scheme::new("foo"))
        .authority(|b| {
            b.userinfo(EStr::new("user"))
                .host(Host::RegName(EStr::new("example.com")))
                .port(8042)
        })
        .path(EStr::new("/over/there"))
        .query(EStr::new("name=ferret"))
        .fragment(EStr::new("nose"))
        .build();

    assert_eq!(
        uri.as_str(),
        "foo://user@example.com:8042/over/there?name=ferret#nose"
    );
    ```

- `EStr` (Percent-encoded string slices):

    All components in a URI that may be percent-encoded are parsed as `EStr`s,
    which allows easy splitting and fast decoding:

    ```rust
    let query = "name=%E5%BC%A0%E4%B8%89&speech=%C2%A1Ol%C3%A9%21";
    let map: HashMap<_, _> = EStr::<Query>::new(query)
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(k, v)| (k.decode().into_string_lossy(), v.decode().into_string_lossy()))
        .collect();
    assert_eq!(map["name"], "张三");
    assert_eq!(map["speech"], "¡Olé!");
    ```

- `EString` (A percent-encoded, growable string):

    You can encode key-value pairs to a query string and use it to build a `Uri`:

    ```rust
    struct Data;

    impl Encoder for Data {
        const TABLE: &'static Table = &table::UNRESERVED.enc();
    }

    let pairs = [("name", "张三"), ("speech", "¡Olé!")];
    let mut buf = EString::<Query>::new();
    for (k, v) in pairs {
        if !buf.is_empty() {
            buf.push_byte(b'&');
        }
        buf.encode::<Data>(k);
        buf.push_byte(b'=');
        buf.encode::<Data>(v);
    }

    assert_eq!(buf, "name=%E5%BC%A0%E4%B8%89&speech=%C2%A1Ol%C3%A9%21");

    let uri = Uri::builder()
        .path(EStr::new(""))
        .query(&buf)
        .build();
    assert_eq!(uri.as_str(), "?name=%E5%BC%A0%E4%B8%89&speech=%C2%A1Ol%C3%A9%21");
    ```

## Roadmap

- [ ] Reference resolution.
- [ ] Normalization.
- [ ] Host: IDNA encoding and DNS syntax checking.
