#![no_main]
use fluent_uri::{component::Host, UriRef};
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

    let uri2 = UriRef::parse(data);
    assert_eq!(success, uri2.is_ok());

    if success {
        let uri1 = uri1.assume_init_ref();
        let uri2 = uri2.unwrap();

        assert_text_eq(uri2.scheme().map(|s| s.as_str()), uri1.scheme);

        if let Some(a) = uri2.authority() {
            assert_text_eq(a.userinfo().map(|r| r.as_str()), uri1.userInfo);

            let mut host = a.host();
            if host.starts_with('[') {
                host = &host[1..host.len() - 1];
            }
            assert_text_eq(Some(host), uri1.hostText);

            match a.host_parsed() {
                Host::Ipv4(addr) => {
                    let ptr = uri1.hostData.ip4;
                    assert!(!ptr.is_null());
                    assert_eq!((*ptr).data, addr.octets());

                    assert!(uri1.hostData.ip6.is_null());
                    assert_text_eq(None, uri1.hostData.ipFuture);
                }
                Host::Ipv6(addr) => {
                    let ptr = uri1.hostData.ip6;
                    assert!(!ptr.is_null());
                    assert_eq!((*ptr).data, addr.octets());

                    assert!(uri1.hostData.ip4.is_null());
                    assert_text_eq(None, uri1.hostData.ipFuture);
                }
                Host::IpvFuture { .. } => {
                    assert_text_eq(Some(host), uri1.hostData.ipFuture);

                    assert!(uri1.hostData.ip4.is_null() && uri1.hostData.ip6.is_null());
                }
                Host::RegName(_) => {
                    assert!(uri1.hostData.ip4.is_null() && uri1.hostData.ip6.is_null());
                    assert_text_eq(None, uri1.hostData.ipFuture);
                }
            }

            assert_text_eq(a.port().map(|s| s.as_str()), uri1.portText);
        } else {
            assert_text_eq(None, uri1.userInfo);
            assert_text_eq(None, uri1.hostText);
            assert!(uri1.hostData.ip4.is_null() && uri1.hostData.ip6.is_null());
            assert_text_eq(None, uri1.hostData.ipFuture);
            assert_text_eq(None, uri1.portText);
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
