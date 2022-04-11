use std::fmt;

use crate::encoding::{EStr, Split};

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

    /// Returns an iterator over the [segments] of the path.
    ///
    /// [segments]: https://datatracker.ietf.org/doc/html/rfc3986/#section-3.3
    ///
    /// # Examples
    ///
    /// ```
    /// use fluent_uri::Uri;
    ///
    /// // An empty path has no segments.
    /// let uri = Uri::parse("")?;
    /// assert_eq!(uri.path().segments().next(), None);
    ///
    /// let uri = Uri::parse("a/b/c")?;
    /// assert!(uri.path().segments().eq(["a", "b", "c"]));
    ///
    /// // The empty string before a preceding "/" is not a segment.
    /// // However, segments can be empty in the other cases.
    /// let uri = Uri::parse("/path/to//dir/")?;
    /// assert!(uri.path().segments().eq(["path", "to", "", "dir", ""]));
    /// # Ok::<_, fluent_uri::SyntaxError>(())
    /// ```
    #[inline]
    pub fn segments(self) -> Split<'a> {
        let mut path = self.0;
        if self.is_absolute() {
            // SAFETY: Skipping "/" is fine.
            path = unsafe { path.get_unchecked(1..) };
        }
        // SAFETY: We have done the validation.
        let path = unsafe { EStr::new_unchecked(path) };

        let mut split = path.split('/');
        split.finished = self.0.is_empty();
        split
    }
}

impl<'a> fmt::Display for Path<'a> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.as_str(), f)
    }
}
