pub use crate::ChainPathError;

#[derive(Debug)]
pub enum Error {
    MisChecksum,
    UnknownVersion,
    InvalidBase58,
    LanguageNotSupported,
    /// Index is out of range
    KeyIndexOutOfRange,
    /// ChainPathError
    ChainPath(ChainPathError),
    EdDsa(ed25519_dalek::ed25519::Error),
}

impl From<ChainPathError> for Error {
    fn from(err: ChainPathError) -> Error {
        Error::ChainPath(err)
    }
}

impl From<ed25519_dalek::ed25519::Error> for Error {
    fn from(err: ed25519_dalek::ed25519::Error) -> Error {
        Error::EdDsa(err)
    }
}
