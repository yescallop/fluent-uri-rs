#![warn(missing_debug_implementations, missing_docs, rust_2018_idioms)]
#![deny(unsafe_op_in_unsafe_fn)]

//! A URI parser that strictly adheres to IETF [RFC 3986].
//!
//! [RFC 3986]: https://datatracker.ietf.org/doc/html/rfc3986/
//!
//! See the documentation of [`Uri`] for more details.
//!
//! # Feature flags
//! 
//! All the features are disabled by default.
//!
//! - `ipv_future`: Enables the parsing of [IPvFuture] literals,
//!   which fails with [`InvalidIpLiteral`] when disabled.
//!
//! - `rfc6874bis`: Enables the parsing of IPv6 zone identifiers,
//!   such as in <https://[fe80::abcd%en1]>.
//!
//!     This feature is based on the homonymous [draft] and is thus subject to change.
//!
//! [IPvFuture]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.2.2
//! [`InvalidIpLiteral`]: UriParseErrorKind::InvalidIpLiteral
//! [draft]: https://datatracker.ietf.org/doc/html/draft-ietf-6man-rfc6874bis-01

/// Utilities for percent-encoding.
pub mod encoding;

mod uri;
pub use uri::*;
