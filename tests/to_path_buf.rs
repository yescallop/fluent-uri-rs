#[cfg(unix)]
#[test]
fn test_path_roundtrip_conversion() {
    use fluent_uri::Uri;
    use std::path::Path;
    let src = std::fs::canonicalize(Path::new(".")).unwrap();
    let conv: Uri<String> = Uri::from_file_path(&src).unwrap();

    let roundtrip = conv.to_file_path().unwrap();
    assert_eq!(src, roundtrip, "conv={conv:?}",);

    let url = Uri::from_file_path("/tmp/foo.txt").unwrap();

    assert_eq!(url.as_str(), "file:///tmp/foo.txt");
}
