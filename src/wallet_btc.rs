use super::utils::key::{ExtendedKey};
use super::utils::mnemonic;

pub fn init() {
  let new_mnemonic = mnemonic::new_mnemonic(24, "English");
  let new_seed = mnemonic::new_seed(new_mnemonic.unwrap(), "".to_string());
  let private_key = ExtendedKey::new_master_private_key(new_seed).unwrap();
  println!("{:?}", ExtendedKey::new_master_public_key(&private_key));
}