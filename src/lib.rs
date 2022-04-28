#![warn(missing_debug_implementations, missing_docs, rust_2018_idioms)]
#![deny(unsafe_op_in_unsafe_fn)]

//! A URI parser that strictly adheres to IETF [RFC 3986].
//!
//! [RFC 3986]: https://datatracker.ietf.org/doc/html/rfc3986/
//!
//! See the documentation of [`Uri`] struct for more details.

/// Utilities for percent-encoding.
pub mod encoding;

mod uri;
pub use uri::*;
