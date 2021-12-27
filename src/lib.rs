#![warn(rust_2018_idioms, unreachable_pub, missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]
//! A URI parser and producer that strictly adheres to IETF [RFC 3986] and [RFC 6874].
//!
//! [RFC 3986]: https://datatracker.ietf.org/doc/html/rfc3986/
//! [RFC 6874]: https://datatracker.ietf.org/doc/html/rfc6874/

/// Utilities for percent-encoding.
pub mod encoding;

/// IP address parser as per RFC 3986.
pub mod ip;

mod uri;
pub use uri::*;
