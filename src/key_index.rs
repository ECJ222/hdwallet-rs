use super::error::Error;

/// Hardened key range (0 - 2 ^ 31).
const HARDENED_OFFSET: u32 = 2_147_483_648;

/// KeyIndex indicates the key type and index of a child key.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum KeyIndex {
    /// Normal key, index range 0 to 2 ** 31 - 1
    Normal(u32),
    /// Hardened key range 2 ** 31 to 2 ** 32 - 1
    Hardened(u32),
}

impl KeyIndex {
    /// Get normal index from KeyIndex types.
    pub fn get_index(self) -> u32 {
        match self {
            KeyIndex::Normal(i) => i,
            KeyIndex::Hardened(i) => i,
        }
    }

    /// Get index standards from KeyIndex types.
    pub fn normalize_index(self) -> u32 {
        match self {
            KeyIndex::Normal(i) => i,
            KeyIndex::Hardened(i) => i - HARDENED_OFFSET,
        }
    }

    /// Verify if Index is valid.
    pub fn is_valid(self) -> bool {
        match self {
            KeyIndex::Normal(i) => i < HARDENED_OFFSET,
            KeyIndex::Hardened(i) => i >= HARDENED_OFFSET,
        }
    }

    /// Harden Index from its normal standard.
    pub fn hardened_from_normalize_index(i: u32) -> Result<KeyIndex, Error> {
        if i < HARDENED_OFFSET {
            Ok(KeyIndex::Hardened(HARDENED_OFFSET + i))
        } else {
            Ok(KeyIndex::Hardened(i))
        }
    }

    /// Get KeyIndex type.
    pub fn from_index(i: u32) -> Result<Self, Error> {
        if i < HARDENED_OFFSET {
            Ok(KeyIndex::Normal(i))
        } else {
            Ok(KeyIndex::Hardened(i))
        }
    }
}