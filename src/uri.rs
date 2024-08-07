use crate::common::*;

ri_maybe_ref! {
    Type = UriRef,
    type_name = "UriRef",
    variable_name = "uri_ref",
    name = "URI reference",
    indefinite_article = "a",
    description = "A URI reference, i.e., either a URI or a relative reference.",
    must_be_ascii = true,
    must_have_scheme = false,
    rfc = 3986,
    abnf_rule = ("URI-reference", "https://datatracker.ietf.org/doc/html/rfc3986#section-4.1"),
    NonRefType = Uri,
    non_ref_name = "URI",
    non_ref_link = "https://datatracker.ietf.org/doc/html/rfc3986#section-3",
    abnf_rule_absolute = ("absolute-URI", "https://datatracker.ietf.org/doc/html/rfc3986#section-4.3"),
    has_scheme_equivalent = is_uri,
    as_method = as_uri,
    into_method = into_uri,
}

ri_maybe_ref! {
    Type = Uri,
    type_name = "Uri",
    variable_name = "uri",
    name = "URI",
    indefinite_article = "a",
    description = "A URI.",
    must_be_ascii = true,
    must_have_scheme = true,
    rfc = 3986,
    abnf_rule = ("URI", "https://datatracker.ietf.org/doc/html/rfc3986#section-3"),
    RefType = UriRef,
    ref_name = "URI reference",
    as_method = as_uri_ref,
    into_method = into_uri_ref,
}
