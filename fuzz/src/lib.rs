use fluent_uri::{component::Host, Uri};

pub fn parse_strict(s: &str) -> Option<Uri<&str>> {
    let res = Uri::parse(s);
    if let Ok(uri) = res {
        if let Some(auth) = uri.authority() {
            if let Host::Ipv6 {
                zone_id: Some(_), ..
            } = auth.host()
            {
                return None;
            }
        }
        return Some(uri);
    }
    None
}
