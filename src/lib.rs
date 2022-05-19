#[macro_use]
extern crate lazy_static;

#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

pub mod key;
pub mod key_chain;
pub mod key_index;
pub mod mnemonic;
pub mod error;

pub use crate::key::{Derivation, ExtendedPrivateKey, ExtendedPublicKey};

pub use crate::key_index::KeyIndex;

pub use crate::key_chain::{
  chain_path::{ChainPath, SubPath},
  DefaultKeyChain, KeyChain,
};
