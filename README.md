# fluent-uri

A URI parser in Rust that strictly adheres to IETF [RFC 3986].

[![build](https://img.shields.io/github/workflow/status/yescallop/fluent-uri-rs/Rust)](https://github.com/yescallop/fluent-uri-rs/actions/workflows/rust.yml)
[![license](https://img.shields.io/github/license/yescallop/fluent-uri-rs?color=blue)](/LICENSE)
[![docs](https://img.shields.io/badge/docs-GitHub%20Pages-red)](https://yescallop.cn/fluent-uri-rs/fluent_uri/)

- **Fast:** Zero-copy parsing. Observed to be 2x ~ 25x faster than common URI parsers in Rust.
- **Easy:** Carefully designed and documented APIs. Handy percent-encoding utilities.
- **Strict:** Parses every possible URI defined in the RFC and denies anything else.

This project is still under development. Contributions are welcome!

[RFC 3986]: https://datatracker.ietf.org/doc/html/rfc3986/

## Features & Examples

- `EStr` (Percent-encoded string slices):

    All components in a URI that may be percent-encoded are parsed as `EStr`s, which allows easy splitting and fast decoding.

    ```rust
    let s = "name=%E5%BC%A0%E4%B8%89&speech=%C2%A1Ol%C3%A9%21";
    let map: HashMap<_, _> = EStr::new(s)
        .split('&')
        .filter_map(|s| s.split_once('='))
        .map(|(k, v)| (k.decode(), v.decode()))
        .filter_map(|(k, v)| k.into_string().ok().zip(v.into_string().ok()))
        .collect();
    assert_eq!(map["name"], "张三");
    assert_eq!(map["speech"], "¡Olé!");
    ```

## Roadmap

- [ ] More tests.
- [ ] URI building.
- [ ] Reference resolution.
- [ ] Normalization and comparison.
- [ ] Host: IDNA encoding and DNS syntax checking.
