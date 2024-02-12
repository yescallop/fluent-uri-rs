//! Builder typestates.

/// Start of URI reference.
pub struct UriStart(());
/// End of scheme.
pub struct SchemeEnd(());
/// Start of authority.
pub struct AuthorityStart(());
/// End of userinfo.
pub struct UserinfoEnd(());
/// End of host.
pub struct HostEnd(());
/// End of port.
pub struct PortEnd(());
/// End of authority.
pub struct AuthorityEnd(());
/// End of path.
pub struct PathEnd(());
/// End of query.
pub struct QueryEnd(());
/// End of fragment
pub struct FragmentEnd(());
/// End of URI reference.
pub struct UriEnd(());

/// Indicates the next possible state.
pub trait To<T> {}

macro_rules! impl_to {
    ($x:ty => $($y:ty),*) => {
        $(
            impl To<$y> for $x {}
        )*
    };
}

impl_to!(UriStart => SchemeEnd, AuthorityStart, AuthorityEnd, PathEnd);
impl_to!(SchemeEnd => AuthorityStart, AuthorityEnd, PathEnd);
impl_to!(AuthorityStart => UserinfoEnd, HostEnd);
impl_to!(UserinfoEnd => HostEnd);
impl_to!(HostEnd => PortEnd, AuthorityEnd);
impl_to!(PortEnd => AuthorityEnd);
impl_to!(AuthorityEnd => PathEnd);
impl_to!(PathEnd => QueryEnd, FragmentEnd, UriEnd);
impl_to!(QueryEnd => FragmentEnd, UriEnd);
impl_to!(FragmentEnd => UriEnd);

/// Indicates that we may advance to this state.
pub trait AdvanceDst {}

impl AdvanceDst for SchemeEnd {}
impl AdvanceDst for UserinfoEnd {}
impl AdvanceDst for PortEnd {}
impl AdvanceDst for AuthorityEnd {}
impl AdvanceDst for QueryEnd {}
impl AdvanceDst for FragmentEnd {}
