#[derive(Debug)]
pub enum Error {
    IoError(std::io::Error),
    OpensslError(openssl::error::ErrorStack),
    ZipError(zip::result::ZipError),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::IoError(e)
    }
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(e: openssl::error::ErrorStack) -> Self {
        Error::OpensslError(e)
    }
}

impl From<zip::result::ZipError> for Error {
    fn from(e: zip::result::ZipError) -> Self {
        Error::ZipError(e)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::IoError(e) => write!(f, "Io error: {}", e),
            Error::OpensslError(e) => write!(f, "Openssl error: {}", e),
            Error::ZipError(e) => write!(f, "Zip error: {}", e),
        }
    }
}
