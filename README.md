# fluent-uri

A URI parser in Rust that strictly adheres to IETF [RFC 3986].

[![crates.io](https://img.shields.io/crates/v/fluent-uri.svg)](https://crates.io/crates/fluent-uri)
[![CI](https://github.com/yescallop/fluent-uri-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/yescallop/fluent-uri-rs/actions/workflows/ci.yml)
[![license](https://img.shields.io/github/license/yescallop/fluent-uri-rs?color=blue)](/LICENSE)

- **Fast:** Zero-copy parsing. Observed to be 2x ~ 25x faster than common URI parsers in Rust.
- **Easy:** Carefully designed and documented APIs. Handy percent-encoding utilities.
- **Strict:** Parses every possible URI defined in the RFC and denies anything else.

API Docs: [docs.rs](https://docs.rs/fluent-uri) | [dev](https://yescallop.cn/fluent-uri-rs/fluent_uri)

[RFC 3986]: https://datatracker.ietf.org/doc/html/rfc3986/

## Features & Examples

- `EStr` (Percent-encoded string slices):

    All components in a URI that may be percent-encoded are parsed as `EStr`s, which allows easy splitting and fast decoding:

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

- Three variants of `Uri` for different use cases:
  - `Uri<&str>`: borrowed; immutable.
  - `Uri<&mut [u8]>`: borrowed; in-place mutable.
  - `Uri<String>`: owned; immutable.

  Decode and extract query parameters in-place from a URI reference:

  ```rust
  fn decode_and_extract_query(
      bytes: &mut [u8],
  ) -> Result<(Uri<&mut [u8]>, HashMap<&str, &str>), ParseError> {
      let mut uri = Uri::parse_mut(bytes)?;
      let map = if let Some(query) = uri.take_query() {
          query
              .split_view('&')
              .flat_map(|pair| pair.split_once_view('='))
              .map(|(k, v)| (k.decode_in_place(), v.decode_in_place()))
              .flat_map(|(k, v)| k.into_str().ok().zip(v.into_str().ok()))
              .collect()
      } else {
          HashMap::new()
      };
      Ok((uri, map))
  }

  let mut bytes = *b"?name=Ferris%20the%20crab&color=%F0%9F%9F%A0";
  let (uri, query) = decode_and_extract_query(&mut bytes)?;

  assert_eq!(query["name"], "Ferris the crab");
  assert_eq!(query["color"], "🟠");

  // The query is taken from the `Uri`.
  assert!(uri.query().is_none());
  // In-place decoding is like this if you're interested:
  assert_eq!(&bytes, b"?name=Ferris the crabcrab&color=\xF0\x9F\x9F\xA09F%9F%A0");
  ```

## Roadmap

- [ ] URI building.
- [ ] Reference resolution.
- [ ] Normalization and comparison.
- [ ] Host: IDNA encoding and DNS syntax checking.
