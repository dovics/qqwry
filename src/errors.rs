use std::io;
use std::string::FromUtf8Error;

#[derive(Debug)]
pub struct Error {
    message: String,
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self {
            message: err.to_string(),
        }
    }
}

impl From<&str> for Error {
    fn from(err: &str) -> Self {
        Self {
            message: err.to_string(),
        }
    }
}

impl From<String> for Error {
    fn from(err: String) -> Self {
        Self { message: err }
    }
}

impl From<FromUtf8Error> for Error {
    fn from(err: FromUtf8Error) -> Self {
        Self {
            message: err.to_string(),
        }
    }
}
