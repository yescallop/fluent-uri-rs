use fluent_uri::{encoding::EStr, ParsedHost, Uri};

fn main() {
    let uri = Uri::builder()
        .scheme("http")
        .start_authority()
        .userinfo("hello")
        .host(ParsedHost::RegName(
            EStr::from_encoded("example.com").unwrap(),
        ))
        .port("2333")
        .end_authority()
        .path("/what")
        .query("k=v")
        .fragment("title1")
        .build();
    println!("{uri}");
    println!("{uri:#?}");

    let uri = Uri::builder().path("").fragment("fragment").build();

    println!("{uri}");
    println!("{uri:#?}");
}
