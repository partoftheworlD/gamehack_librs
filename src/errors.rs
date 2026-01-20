use std::fmt::Display;

#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
pub enum Errors<'src> {
    EmptyBuffer(&'src str),
    ProcessNotFound,
}

impl Display for Errors<'_> {
    fn fmt(&'_ self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match &self {
            Errors::EmptyBuffer(error) => error,
            Errors::ProcessNotFound => "Process not found!",
        };
        write!(f, "Error: {message}")
    }
}
