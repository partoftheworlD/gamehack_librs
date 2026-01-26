use std::{ffi::FromBytesUntilNulError, fmt::Display, str::Utf8Error};

#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
/// Enum full of errors :c
pub enum Errors<'src> {
    EmptyBuffer(&'src str),
    ProcessNotFound,
    SignatureNotFound,
    NoNulByte(FromBytesUntilNulError),
    InvalidUtf8(Utf8Error),
}

/// Provides a human-readable representation of [`Errors`].
///
/// This implementation allows errors to be printed using the `{}` format specifier,
/// which is essential for user-facing error messages and logging.
impl Display for Errors<'_> {
    /// Formats the error into a user-friendly string.
    ///
    /// The resulting string is prefixed with `"Error: "` followed by a specific 
    /// message based on the error variant.
    ///
    fn fmt(&'_ self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match &self {
            Errors::EmptyBuffer(error) => error,
            Errors::ProcessNotFound => "Process not found!",
            Errors::SignatureNotFound => "Signature not found!",
            Errors::NoNulByte(_) => "No nul byte was present",
            Errors::InvalidUtf8(_) => "Attempt to interpret a sequence of u8 as a String failed",
        };
        write!(f, "Error: {message}")
    }
}

/// Allows for automatic conversion from [`FromBytesUntilNulError`] to [`Errors`].
///
/// This enables the use of the `?` operator in functions that return [`Errors`]
/// when calling methods that produce a [`FromBytesUntilNulError`].
impl From<FromBytesUntilNulError> for Errors<'_> {
    /// Converts a [`FromBytesUntilNulError`] into [`Errors::NoNulByte`].
    #[inline]
    fn from(err: FromBytesUntilNulError) -> Self {
        Errors::NoNulByte(err)
    }
}
/// Allows for automatic conversion from [`Utf8Error`] to [`Errors`].
///
/// This implementation facilitates the propagation of UTF-8 decoding errors 
/// using the `?` operator. It wraps the standard library's [`Utf8Error`] into 
/// the [`Errors::InvalidUtf8`] variant.
impl From<Utf8Error> for Errors<'_> {
    /// Converts a [`Utf8Error`] into [`Errors::InvalidUtf8`].
    fn from(err: Utf8Error) -> Self {
        Errors::InvalidUtf8(err)
    }
}
