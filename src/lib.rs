#![warn(rust_2018_idioms, missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]

//! A URI parser that strictly adheres to IETF [RFC 3986].
//!
//! [RFC 3986]: https://datatracker.ietf.org/doc/html/rfc3986/

/// Utilities for percent-encoding.
pub mod encoding;

mod uri;
pub use uri::*;
