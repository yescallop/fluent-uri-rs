#![allow(missing_debug_implementations)]

//! Percent-encoders for URI components.

use super::table::*;

/// A trait used by [`EStr`] and [`EString`] to specify the table used for encoding.
///
/// [`EStr`]: super::EStr
/// [`EString`]: super::EString
///
/// # Sub-encoders
///
/// A sub-encoder `SubE` of `E` is an encoder such that `SubE::TABLE` is a [subset] of `E::TABLE`.
///
/// [subset]: Table::is_subset
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
///
/// [`EStr`] has [extension methods] for the path component.
///
/// [`EStr`]: super::EStr
/// [extension methods]: super::EStr#impl-EStr<Path>
pub struct Path(());

impl Encoder for Path {
    const TABLE: &'static Table = PATH;
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
