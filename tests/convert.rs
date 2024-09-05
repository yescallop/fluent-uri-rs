use fluent_uri::{Iri, Uri};

#[test]
fn iri_to_uri() {
    let iri = Iri::parse("http://résumé.example.org").unwrap();
    assert_eq!(iri.to_uri(), "http://r%C3%A9sum%C3%A9.example.org");

    let iri = Iri::parse("http://www.example.org/red%09rosé#red").unwrap();
    assert_eq!(iri.to_uri(), "http://www.example.org/red%09ros%C3%A9#red");

    let iri = Iri::parse("http://example.com/\u{10300}\u{10301}\u{10302}").unwrap();
    assert_eq!(
        iri.to_uri(),
        "http://example.com/%F0%90%8C%80%F0%90%8C%81%F0%90%8C%82"
    );
}

#[test]
fn uri_to_iri() {
    let uri = Uri::parse("http://www.example.org/r%E9sum%E9.html").unwrap();
    assert_eq!(
        uri.into_iri().normalize(),
        "http://www.example.org/r%E9sum%E9.html"
    );

    let uri = Uri::parse("http://www.example.org/D%C3%BCrst").unwrap();
    assert_eq!(uri.into_iri().normalize(), "http://www.example.org/Dürst");

    let uri = Uri::parse("http://www.example.org/D%FCrst").unwrap();
    assert_eq!(uri.into_iri().normalize(), "http://www.example.org/D%FCrst");

    let uri = Uri::parse("http://xn--99zt52a.example.org/%e2%80%ae").unwrap();
    // TODO: Determine if we should implement the MUST in Section 4.1 of RFC 3987.
    // assert_eq!(
    //     uri.as_iri().normalize(),
    //     "http://xn--99zt52a.example.org/%E2%80%AE"
    // );
    assert_eq!(
        uri.into_iri().normalize(),
        "http://xn--99zt52a.example.org/\u{202e}"
    );
}
