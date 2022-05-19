pub mod chain_path;

use crate::{error::Error, ChainPath, Derivation, ExtendedPrivateKey, SubPath};


pub trait KeyChain {
  fn derive_private_key(
      &self,
      chain_path: ChainPath,
  ) -> Result<(ExtendedPrivateKey, Derivation), Error>;
}

pub struct DefaultKeyChain {
  master_key: ExtendedPrivateKey,
}

impl DefaultKeyChain {
  pub fn new(master_key: ExtendedPrivateKey) -> Self {
      DefaultKeyChain { master_key }
  }
}

impl KeyChain for DefaultKeyChain {
  fn derive_private_key(
      &self,
      chain_path: ChainPath,
  ) -> Result<(ExtendedPrivateKey, Derivation), Error> {
      let mut iter = chain_path.iter();

      if iter.next() != Some(Ok(SubPath::Root)) {
          return Err(Error::Invalid);
      }
      let mut key = self.master_key.clone();
      let mut depth = 0;
      let mut parent_key = None;
      let mut key_index = None;
      // Iterate over Chain path.
      for sub_path in iter {
          match sub_path? {
              SubPath::Child(child_key_index) => {
                  depth += 1;
                  key_index = Some(child_key_index);
                  let child_key = key.derive_private_key(child_key_index)?;
                  parent_key = Some(key);
                  key = child_key;
              }
              _ => return Err(Error::Invalid),
          }
      }
      Ok((
          key,
          Derivation {
              depth,
              parent_key,
              key_index,
          },
      ))
  }
}