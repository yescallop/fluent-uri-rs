//! Error types.

use crate::internal::ToUri;

/// Detailed cause of a [`ParseError`].
#[derive(Clone, Copy, Debug)]
pub(crate) enum ParseErrorKind {
    /// Invalid percent-encoded octet that is either non-hexadecimal or incomplete.
    ///
    /// The error index points to the percent character "%" of the octet.
    InvalidOctet,
    /// Unexpected character that is not allowed by the URI syntax.
    ///
    /// The error index points to the first byte of the character.
    UnexpectedChar,
    /// Invalid IPv6 address.
    ///
    /// The error index points to the first byte of the address.
    InvalidIpv6Addr,
    /// Input length greater than [`u32::MAX`].
    ///
    /// The error index equals `0`.
    OverlongInput,
}

/// An error occurred when parsing URI references.
#[derive(Clone, Copy)]
pub struct ParseError<I = ()> {
    pub(crate) index: u32,
    pub(crate) kind: ParseErrorKind,
    pub(crate) input: I,
}

impl ParseError {
    pub(crate) fn with_input<I>(self, input: I) -> ParseError<I> {
        ParseError {
            index: self.index,
            kind: self.kind,
            input,
        }
    }
}

impl<I: ToUri> ParseError<I> {
    /// Recovers the input that was attempted to parse into a [`Uri`].
    ///
    /// [`Uri`]: crate::Uri
    pub fn into_input(self) -> I {
        self.input
    }

    /// Returns the error with input erased.
    pub fn plain(&self) -> ParseError {
        ParseError {
            index: self.index,
            kind: self.kind,
            input: (),
        }
    }
}

#[cfg(feature = "std")]
impl<I> std::error::Error for ParseError<I> {}

/// Detailed cause of a [`ResolveError`].
#[derive(Clone, Copy, Debug)]
pub(crate) enum ResolveErrorKind {
    NonAbsoluteBase,
    NonHierarchicalBase,
    OverlongOutput,
    // PathUnderflow,
}

/// An error occurred when resolving URI references.
#[derive(Clone, Copy, Debug)]
pub struct ResolveError(pub(crate) ResolveErrorKind);

#[cfg(feature = "std")]
impl std::error::Error for ResolveError {}
