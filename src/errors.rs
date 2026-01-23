use std::{ffi::FromBytesUntilNulError, fmt::Display, str::Utf8Error};

#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
pub enum Errors<'src> {
    EmptyBuffer(&'src str),
    ProcessNotFound,
    SignatureNotFound,
    NoNulByte(FromBytesUntilNulError),
    InvalidUtf8(Utf8Error),
}

impl Display for Errors<'_> {
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

impl From<FromBytesUntilNulError> for Errors<'_> {
    fn from(err: FromBytesUntilNulError) -> Self {
        Errors::NoNulByte(err)
    }
}

impl From<Utf8Error> for Errors<'_> {
    fn from(err: Utf8Error) -> Self {
        Errors::InvalidUtf8(err)
    }
}
