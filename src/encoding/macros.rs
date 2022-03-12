/// Returns immediately with a raw error.
macro_rules! err {
    ($ptr:ident, $kind:expr) => {
        return Err(($ptr, $kind))
    };
    ($str:ident[$offset:expr], $kind:expr) => {
        return Err(($str.as_ptr().wrapping_add($offset), $kind))
    };
}

/// Splits the slice at a position (exclusive), takes head and leaves tail.
macro_rules! head {
    ($s:expr, $i:expr) => {{
        let res = &$s[..$i];
        $s = &$s[$i + 1..];
        res
    }};
}

/// Splits the slice at a position (exclusive), takes tail and leaves head.
macro_rules! tail {
    ($s:expr, $i:expr) => {{
        let res = &$s[$i + 1..];
        $s = &$s[..$i];
        res
    }};
}

/// Splits the slice at the first occurrence of a byte（exclusive),
/// takes head or tail, and leaves the other.
macro_rules! take {
    ($n:ident, $s:expr, $b:expr) => {
        crate::encoding::chr($s, $b).map(|i| $n!($s, i))
    };
    ($n:ident, $s:expr, $b:literal until $end:literal) => {
        crate::encoding::chr_until($s, $b, $end).map(|i| $n!($s, i))
    };
    (rev, $n:ident, $s:expr, $b:expr) => {
        crate::encoding::rchr($s, $b).map(|i| $n!($s, i))
    };
}

/// Validates the slice with a validator and converts it to a string.
///
/// # Safety
///
/// Make sure that the validator doesn't allow invalid UTF-8 and that the bytes
/// before the offset are validated, otherwise there'd be undefined behavior.
macro_rules! validate {
    ($s:expr, $v:expr) => {{
        let s = $s;
        Validator::validate($v, s)?;
        // SAFETY: The caller must ensure that the validator doesn't allow invalid UTF-8.
        unsafe { std::str::from_utf8_unchecked(s) }
    }};
    ($s:expr, $v:expr, offset = $offset:expr) => {{
        let s = $s;
        Validator::validate($v, &s[$offset..])?;
        // SAFETY: The caller must ensure that the validator doesn't allow invalid UTF-8
        // and that the bytes before the offset are valid UTF-8.
        unsafe { std::str::from_utf8_unchecked(s) }
    }};
}

pub(crate) use {err, head, tail, take, validate};
