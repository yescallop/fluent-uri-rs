use fluent_uri::encoding::{table::*, *};

const RAW: &str = "te😃a 测1`~!@试#$%st^&+=";
const ENCODED: &str = "te%F0%9F%98%83a%20%E6%B5%8B1%60~!@%E8%AF%95%23$%25st%5E&+=";

#[test]
fn enc_dec_validate() {
    // TODO: Fuzz test
    let s = encode(RAW, QUERY_FRAGMENT);
    assert_eq!(ENCODED, s);

    let mut buf = String::new();
    encode_to(RAW, QUERY_FRAGMENT, &mut buf);
    assert_eq!(ENCODED, buf);

    assert!(validate(&*s, QUERY_FRAGMENT).is_ok());

    assert_eq!(Ok(RAW.as_bytes()), decode(ENCODED).as_deref());
    assert_eq!(RAW.as_bytes(), unsafe {
        decode_unchecked(ENCODED.as_bytes())
    });

    let mut buf = Vec::new();
    assert_eq!(Ok(Some(RAW.as_bytes())), decode_with(ENCODED, &mut buf));
    assert_eq!(buf, RAW.as_bytes());
    buf.clear();

    assert_eq!(Some(RAW.as_bytes()), unsafe {
        decode_with_unchecked(ENCODED.as_bytes(), &mut buf)
    });
    assert_eq!(buf, RAW.as_bytes());

    assert_eq!(Ok(b"\x2d\xe6\xb5" as _), decode("%2D%E6%B5").as_deref());

    let s = "%2d%";
    assert_eq!(3, decode(s).unwrap_err().index());

    let s = "%2d%fg";
    assert_eq!(3, decode(s).unwrap_err().index());

    // We used to use slot 0 to indicate that percent-encoded octets are allowed,
    // which was totally wrong since it just allows zero bytes. Glad we fixed it.
    assert!(validate("\0", QUERY_FRAGMENT).is_err());
}

#[test]
fn split() {
    let s = EStr::new("id=3&name=%E5%BC%A0%E4%B8%89");
    let mut split = s.split('&');

    let it = split.next().unwrap();
    assert_eq!(it, "id=3");
    assert_eq!(it.decode().as_bytes(), b"id=3");
    assert_eq!(it.decode().into_string().as_deref(), Ok("id=3"));

    let (k, v) = it.split_once('=').unwrap();
    assert_eq!(k, "id");
    assert_eq!(v, "3");

    let it = split.next().unwrap();
    assert_eq!(it, "name=%E5%BC%A0%E4%B8%89");
    assert_eq!(it.decode().into_string().unwrap(), "name=张三");

    let (k, v) = it.split_once('=').unwrap();
    assert_eq!(k.decode().into_string().unwrap(), "name");
    assert_eq!(v.decode().into_string().unwrap(), "张三");
}
