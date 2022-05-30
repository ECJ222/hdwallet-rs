#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

pub mod error;
pub mod extended_key;
pub mod mnemonic;

pub mod chain_path;
pub mod solana;
pub mod traits;

pub use crate::extended_key::{key_index::KeyIndex, SolanaExPrivateKey, SolanaExPublicKey};

pub use chain_path::{ChainPath, Error as ChainPathError, SubPath};

// re-exports
pub use ed25519_dalek;
pub use ring;
