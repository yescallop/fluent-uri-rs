# fluent-uri

A URI parser in Rust that strictly adheres to IETF [RFC 3986].

[![crates.io](https://img.shields.io/crates/v/fluent-uri.svg)](https://crates.io/crates/fluent-uri)
[![CI](https://github.com/yescallop/fluent-uri-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/yescallop/fluent-uri-rs/actions/workflows/ci.yml)
[![license](https://img.shields.io/github/license/yescallop/fluent-uri-rs?color=blue)](/LICENSE)

- **Fast:** Zero-copy parsing. Observed to be 2x ~ 25x faster than common URI parsers in Rust.
- **Easy:** Carefully designed and documented APIs. Handy percent-encoding utilities.
- **Strict:** Parses every possible URI defined in the RFC and denies anything else.

[Latest API Docs](https://yescallop.cn/fluent-uri-rs/fluent_uri)

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

- Three variants of `Uri` for different use cases:
  - `Uri<&str>`: borrowed; immutable.
  - `Uri<&mut [u8]>`: borrowed; in-place mutable.
  - `Uri<String>`: owned; immutable.
  
  Lifetimes are correctly handled in a way that `Uri<&'a str>` and `Uri<&'a mut [u8]>` both
  output references with lifetime `'a`. This allows you to drop a temporary `Uri` while keeping
  the output references.

  ```rust
  let uri = Uri::parse("foo:bar").expect("invalid URI reference");
  let path = uri.path();
  drop(uri);
  assert_eq!(path.as_str(), "bar");
  ```

  Decode path segments in-place and collect them into a `Vec`.

  ```rust
  fn decode_path_segments(uri: &mut [u8]) -> Option<Vec<&str>> {
      let mut uri = Uri::parse_mut(uri).ok()?;
      let segs = uri.take_path_mut().segments_mut();
      let mut out = Vec::new();
      for seg in segs {
          out.push(seg.decode_in_place().into_str().ok()?);
      }
      Some(out)
  }
     
  let mut uri = b"/path/to/my%20music".to_vec();
  assert_eq!(decode_path_segments(&mut uri).unwrap(), ["path", "to", "my music"]);
  ```

## Roadmap

- [ ] URI building.
- [ ] Reference resolution.
- [ ] Normalization and comparison.
- [ ] Host: IDNA encoding and DNS syntax checking.
