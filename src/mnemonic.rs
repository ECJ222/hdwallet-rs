use crate::error::Error;
use bip0039::{Count, Language, Mnemonic};

/// Generate mnemonic.
pub fn new_mnemonic(length: u32, language_of_choice: &str) -> Result<Mnemonic, Error> {
    let count = if length <= 12 {
        Count::Words12
    } else {
        Count::Words24
    };

    let language = match language_of_choice.to_lowercase().as_str() {
        "english" => Language::English,
        "japanese" => Language::Japanese,
        "korean" => Language::Korean,
        "italian" => Language::Italian,
        "french" => Language::French,
        "czech" => Language::Czech,
        "chinese-simplified" => Language::SimplifiedChinese,
        "chinese-traditional" => Language::TraditionalChinese,
        "portuguese" => Language::Portuguese,
        _ => return Err(Error::LanguageNotSupported),
    };

    Ok(Mnemonic::generate_in(language, count))
}

/// Generate seed phrase.
pub fn new_seed(mnemonic: Mnemonic, password: String) -> [u8; 64] {
    mnemonic.to_seed(password)
}
