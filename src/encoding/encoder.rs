#![allow(missing_debug_implementations)]

//! Percent-encoders for URI components.

use super::table::*;

/// A trait used by [`EStr`] and [`EString`] to specify the table used for encoding.
///
/// [`EStr`]: super::EStr
/// [`EString`]: super::EString
pub trait Encoder: 'static {
    /// The table used for encoding.
    const TABLE: &'static Table;
}

/// An encoder for userinfo.
pub struct Userinfo(());

impl Encoder for Userinfo {
    const TABLE: &'static Table = USERINFO;
}

/// An encoder for registered name.
pub struct RegName(());

impl Encoder for RegName {
    const TABLE: &'static Table = REG_NAME;
}

/// An encoder for path.
pub struct Path(());

impl Encoder for Path {
    const TABLE: &'static Table = PATH;
}

/// An encoder for path segment.
pub struct PathSegment(());

impl Encoder for PathSegment {
    const TABLE: &'static Table = PCHAR;
}

/// An encoder for query.
pub struct Query(());

impl Encoder for Query {
    const TABLE: &'static Table = QUERY;
}

/// An encoder for fragment.
pub struct Fragment(());

impl Encoder for Fragment {
    const TABLE: &'static Table = FRAGMENT;
}
