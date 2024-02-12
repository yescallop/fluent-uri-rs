#![no_main]
use fluent_uri::component::Host;
use fluent_uri_fuzz::parse_strict;
use libfuzzer_sys::fuzz_target;
use std::{ffi::CStr, mem::MaybeUninit, ptr, slice};
use uriparser_sys::{uriFreeUriMembersA, uriParseSingleUriA, UriTextRangeA, UriUriA, URI_SUCCESS};

fuzz_target!(|data: &str| {
    if let Ok(text) = CStr::from_bytes_with_nul(data.as_bytes()) {
        unsafe { check(&data[..data.len() - 1], text) }
    }
});

unsafe fn check(data: &str, cstr: &CStr) {
    let mut uri1 = MaybeUninit::<UriUriA>::uninit();
    let ret = uriParseSingleUriA(uri1.as_mut_ptr(), cstr.as_ptr(), ptr::null_mut());
    let success = ret == URI_SUCCESS as _;

    let uri2 = parse_strict(data);
    assert_eq!(success, uri2.is_some());

    if success {
        let uri1 = uri1.assume_init_ref();
        let uri2 = uri2.unwrap();

        assert_text_eq(uri2.scheme().map(|s| s.as_str()), uri1.scheme);
        assert_text_eq(
            uri2.authority().map(|a| a.host_as_str()).map(|s| {
                if s.starts_with('[') {
                    &s[1..s.len() - 1]
                } else {
                    s
                }
            }),
            uri1.hostText,
        );
        if let Some(a) = uri2.authority() {
            assert_text_eq(a.userinfo().map(|u| u.as_str()), uri1.userInfo);
            assert_text_eq(a.port(), uri1.portText);
            match a.host() {
                Host::Ipv4(addr) => {
                    let ptr = uri1.hostData.ip4;
                    assert!(!ptr.is_null());
                    assert_eq!((*ptr).data, addr.octets());
                }
                Host::Ipv6 { addr, .. } => {
                    let ptr = uri1.hostData.ip6;
                    assert!(!ptr.is_null());
                    assert_eq!((*ptr).data, addr.octets());
                }
                _ => (),
            }
        }
        assert_text_eq(uri2.query().map(|q| q.as_str()), uri1.query);
        assert_text_eq(uri2.fragment().map(|f| f.as_str()), uri1.fragment);
    }
    if success {
        uriFreeUriMembersA(uri1.as_mut_ptr());
    }
}

unsafe fn assert_text_eq(a: Option<&str>, b: UriTextRangeA) {
    assert_eq!(a.is_some(), !b.first.is_null() && !b.afterLast.is_null());
    if let Some(a) = a {
        let b = slice::from_raw_parts(b.first.cast(), b.afterLast.offset_from(b.first) as usize);
        assert_eq!(a.as_bytes(), b);
    }
}
