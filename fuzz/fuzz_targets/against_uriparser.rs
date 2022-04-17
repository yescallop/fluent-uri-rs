#![no_main]
use libfuzzer_sys::fuzz_target;
use std::{ffi::CStr, mem::MaybeUninit, ptr};
use uriparser_sys::{uriFreeUriMembersA, uriParseSingleUriA, UriUriA, URI_SUCCESS};

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = CStr::from_bytes_with_nul(data) {
        let mut uri = MaybeUninit::<UriUriA>::uninit();
        let mut error_pos = ptr::null();
        let ret = unsafe { uriParseSingleUriA(uri.as_mut_ptr(), text.as_ptr(), &mut error_pos) };
        let success = ret == URI_SUCCESS as _;
        if success {
            unsafe { uriFreeUriMembersA(uri.as_mut_ptr()) }
        }

        assert_eq!(
            success,
            fluent_uri::Uri::parse(&data[..data.len() - 1]).is_ok()
        );
    }
});
