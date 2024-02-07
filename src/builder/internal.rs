use super::state::*;

/// Indicates the next possible state.
pub trait To<T> {}

macro_rules! impl_to {
    ($x:ty => $($y:ty),*) => {
        $(
            impl To<$y> for $x {}
        )*
    };
}

impl_to!(UriStart => SchemeEnd, AuthorityStart, PathEnd);
impl_to!(SchemeEnd => AuthorityStart, PathEnd);
impl_to!(AuthorityStart => UserinfoEnd, HostEnd);
impl_to!(UserinfoEnd => HostEnd);
impl_to!(HostEnd => PortEnd, AuthorityEnd);
impl_to!(PortEnd => AuthorityEnd);
impl_to!(AuthorityEnd => PathEnd);
impl_to!(PathEnd => QueryEnd, FragmentEnd, UriEnd);
impl_to!(QueryEnd => FragmentEnd, UriEnd);
impl_to!(FragmentEnd => UriEnd);

pub trait ToPathEnd: To<PathEnd> {
    fn validate_path_extra(path: &str) -> bool;
}

#[inline]
fn first_segment_contains_colon(path: &str) -> bool {
    path.split_once('/')
        .map(|x| x.0)
        .unwrap_or(path)
        .contains(':')
}

impl ToPathEnd for UriStart {
    #[inline]
    fn validate_path_extra(path: &str) -> bool {
        !path.starts_with("//") && !first_segment_contains_colon(path)
    }
}

impl ToPathEnd for SchemeEnd {
    #[inline]
    fn validate_path_extra(path: &str) -> bool {
        !path.starts_with("//")
    }
}

impl ToPathEnd for AuthorityEnd {
    #[inline]
    fn validate_path_extra(path: &str) -> bool {
        path.is_empty() || path.starts_with('/')
    }
}
