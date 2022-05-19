#[derive(Debug, PartialEq)]
pub enum Error {
    Invalid,
    Empty,
    // Language is not supported
    LanguageNotSupported,
    // Key index is out of bounds
    KeyIndexOutOfBounds,
    Secp(secp256k1::Error),
}

impl From<secp256k1::Error> for Error {
    fn from(err: secp256k1::Error) -> Error {
        Error::Secp(err)
    }
}
