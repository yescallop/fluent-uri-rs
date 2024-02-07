#![allow(missing_debug_implementations)]

//! Percent-encoders for URI components.

use super::table::*;

/// A trait used by [`EString`] to specify the table used for encoding.
///
/// [`EString`]: super::EString
pub trait Encoder {
    /// The table used for encoding.
    const TABLE: &'static Table;
}

/// An encoder for userinfo.
pub struct UserinfoEncoder(());

impl Encoder for UserinfoEncoder {
    const TABLE: &'static Table = USERINFO;
}

/// An encoder for registered name.
pub struct RegNameEncoder(());

impl Encoder for RegNameEncoder {
    const TABLE: &'static Table = REG_NAME;
}

/// An encoder for path.
pub struct PathEncoder(());

impl Encoder for PathEncoder {
    const TABLE: &'static Table = PATH;
}

/// An encoder for query.
pub struct QueryEncoder(());

impl Encoder for QueryEncoder {
    const TABLE: &'static Table = QUERY_FRAGMENT;
}

/// An encoder for fragment.
pub struct FragmentEncoder(());

impl Encoder for FragmentEncoder {
    const TABLE: &'static Table = QUERY_FRAGMENT;
}
