use crate::internal::ToUri;
use core::fmt::Debug;

/// Detailed cause of a [`ParseError`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ParseErrorKind {
    /// Invalid percent-encoded octet that is either non-hexadecimal or incomplete.
    ///
    /// The error index points to the percent character "%" of the octet.
    InvalidOctet,
    /// Unexpected character that is not allowed by the URI syntax.
    ///
    /// The error index points to the character.
    UnexpectedChar,
    /// Invalid IP literal address.
    ///
    /// The error index points to the preceding left square bracket "[".
    InvalidIpLiteral,
}

/// An error occurred when parsing URI references.
#[derive(Clone, Copy)]
pub struct ParseError<I = ()> {
    pub(crate) index: u32,
    pub(crate) kind: ParseErrorKind,
    pub(crate) input: I,
}

impl ParseError<()> {
    pub(crate) fn with_input<I>(self, input: I) -> ParseError<I> {
        ParseError {
            index: self.index,
            kind: self.kind,
            input,
        }
    }
}

impl<I: ToUri> ParseError<I> {
    /// Recovers the input that were attempted to parse into a [`Uri`].
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
impl<I: Debug> std::error::Error for ParseError<I> {}
