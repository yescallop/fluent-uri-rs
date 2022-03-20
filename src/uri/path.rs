use crate::encoding::EStr;

/// The [path] component of URI reference.
///
/// [path]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.3
#[derive(Debug, Clone, Copy)]
pub struct Path<'a>(pub(crate) &'a str);

impl<'a> Path<'a> {
    /// Returns the path as an `EStr`.
    #[inline]
    pub fn as_estr(self) -> &'a EStr {
        // SAFETY: We have done the validation.
        unsafe { EStr::new_unchecked(self.0) }
    }

    /// Returns the path as a string slice.
    #[inline]
    pub fn as_str(self) -> &'a str {
        self.0
    }

    /// Returns `true` if the path is absolute, i.e., beginning with "/".
    #[inline]
    pub fn is_absolute(self) -> bool {
        self.0.starts_with('/')
    }

    /// Returns `true` if the path is rootless, i.e., not beginning with "/".
    #[inline]
    pub fn is_rootless(self) -> bool {
        !self.is_absolute()
    }
}
