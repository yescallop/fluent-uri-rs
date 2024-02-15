use fluent_uri::Uri;

pub fn parse_strict(s: &str) -> Option<Uri<&str>> {
    Uri::parse(s)
        .ok()
        .filter(Uri::is_strictly_rfc3986_compliant)
}
