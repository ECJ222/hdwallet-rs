pub mod key_chain;

use crate::ring::digest;
use crate::{
    chain_path::ChainPath,
    ed25519_dalek::{PublicKey, SecretKey as Sk},
    traits::{Deserialize, Serialize},
    SolanaExPrivateKey, SolanaExPublicKey,
};
use key_chain::{Derivation, KeyChain};

use base58::{FromBase58, ToBase58};

use std::rc::Rc;

use crate::error::Error;

#[derive(Debug, PartialEq, Eq)]
pub struct PrivKey {
    pub derivation: Derivation,
    pub extended_key: SolanaExPrivateKey,
}

impl PrivKey {
    pub fn from_master_key(extended_key: SolanaExPrivateKey) -> Self {
        PrivKey {
            extended_key,
            derivation: Derivation::master(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]

pub struct PubKey {
    pub derivation: Derivation,
    pub extended_key: SolanaExPublicKey,
}

impl PubKey {
    pub fn from_private_key(priv_key: &PrivKey) -> PubKey {
        let pub_key = SolanaExPublicKey::from_private_key(&priv_key.extended_key);

        PubKey {
            derivation: priv_key.derivation.clone(),
            extended_key: pub_key.unwrap(),
        }
    }
}

trait DerivationExt {
    fn parent_fingerprint(&self) -> Vec<u8>;
}

impl DerivationExt for Derivation {
    fn parent_fingerprint(&self) -> Vec<u8> {
        match self.parent_key {
            Some(ref key) => {
                let pubkey = SolanaExPublicKey::from_private_key(key);
                let buf = digest::digest(&digest::SHA256, &pubkey.unwrap().0.to_bytes());
                buf.as_ref()[0..4].to_vec()
            }
            None => vec![0; 4],
        }
    }
}

fn encode_derivation(buf: &mut Vec<u8>, derivation: &Derivation) {
    buf.extend_from_slice(&derivation.depth.to_be_bytes());
    buf.extend_from_slice(&derivation.parent_fingerprint());

    match derivation.key_index {
        Some(key_index) => {
            buf.extend_from_slice(&key_index.raw_index().to_be_bytes());
        }
        None => buf.extend_from_slice(&[0; 4]),
    }
}

fn decode_derivation(data: (&dyn KeyChain, ChainPath)) -> Result<Derivation, Error> {
    let slice: String = data.1.to_string();
    let chain_path = &slice[..(slice.len())];
    let (_extended_key, derivation) = data
        .0
        .derive_private_key(chain_path.into())
        .expect("fetch key");

    Ok(derivation)
}

fn encode_checksum(buf: &mut Vec<u8>) {
    let check_sum = {
        let buf = digest::digest(&digest::SHA256, buf);
        digest::digest(&digest::SHA256, buf.as_ref())
    };

    buf.extend_from_slice(&check_sum.as_ref()[0..4]);
}

impl Serialize<Vec<u8>> for PrivKey {
    fn serialize(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = [].to_vec();

        encode_derivation(&mut buf, &self.derivation);

        buf.extend_from_slice(&self.extended_key.chain_code);
        buf.extend_from_slice(&[0]);
        let private_key = Rc::try_unwrap(Rc::clone(&self.extended_key.private_key)).unwrap_err();
        buf.extend_from_slice(&private_key.to_bytes());
        assert_eq!(buf.len(), 74);
        encode_checksum(&mut buf);

        buf
    }
}

impl Serialize<String> for PrivKey {
    fn serialize(&self) -> String {
        Serialize::<Vec<u8>>::serialize(self).to_base58()
    }
}

impl Serialize<Vec<u8>> for PubKey {
    fn serialize(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = [].to_vec();

        encode_derivation(&mut buf, &self.derivation);

        buf.extend_from_slice(&self.extended_key.0.to_bytes());
        encode_checksum(&mut buf);

        buf
    }
}

impl Serialize<String> for PubKey {
    fn serialize(&self) -> String {
        let serialized_key: Vec<u8> = self.serialize();
        let public_address = Serialize::<Vec<u8>>::serialize(&self.extended_key).to_base58();

        public_address + &serialized_key.to_base58()
    }
}

impl Deserialize<(String, &dyn KeyChain, ChainPath<'_>), Error> for PrivKey {
    fn deserialize(data: (String, &dyn KeyChain, ChainPath)) -> Result<PrivKey, Error> {
        let buf = data.0.from_base58().map_err(|_| Error::InvalidBase58)?;

        let derivation = decode_derivation((data.1, data.2))?;
        let chain_code = buf[9..41].to_vec();
        let private_key = Rc::new(Sk::from_bytes(&buf[42..74])?);

        Ok(PrivKey {
            derivation,
            extended_key: SolanaExPrivateKey {
                private_key,
                chain_code,
            },
        })
    }
}

impl Deserialize<(String, &dyn KeyChain, ChainPath<'_>), Error> for PubKey {
    fn deserialize(data: (String, &dyn KeyChain, ChainPath)) -> Result<PubKey, Error> {
        let buf = data.0[44..]
            .from_base58()
            .map_err(|_| Error::InvalidBase58)?;

        let derivation = decode_derivation((data.1, data.2))?;

        let public_key = PublicKey::from_bytes(&buf[9..41]).unwrap();

        Ok(PubKey {
            derivation,
            extended_key: SolanaExPublicKey(public_key),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mnemonic;
    use crate::traits::Serialize;
    use key_chain::{DefaultKeyChain, KeyChain};

    #[test]
    fn test_deserialize_priv_key() {
        let new_mnemonic = mnemonic::new_mnemonic(24, "English");
        let seed = mnemonic::new_seed(new_mnemonic.unwrap(), "".to_string());
        let key_chain =
            DefaultKeyChain::new(SolanaExPrivateKey::new_master_key(&seed).expect("master key"));
        let (extended_key, derivation) =
            key_chain.derive_private_key("m".into()).expect("fetch key");
        let private_key = PrivKey {
            derivation,
            extended_key,
        };
        let serialized_key: String = private_key.serialize();
        let deserialized_key =
            PrivKey::deserialize((serialized_key, &key_chain, "m".into())).expect("deserialize");
        assert_eq!(private_key, deserialized_key);
    }

    #[test]
    fn test_deserialize_pub_key() {
        let new_mnemonic = mnemonic::new_mnemonic(24, "English");
        let seed = mnemonic::new_seed(new_mnemonic.unwrap(), "".to_string());
        let key_chain =
            DefaultKeyChain::new(SolanaExPrivateKey::new_master_key(&seed).expect("master key"));
        let (extended_key, derivation) =
            key_chain.derive_private_key("m".into()).expect("fetch key");
        let private_key = PrivKey {
            derivation,
            extended_key,
        };
        let public_key = PubKey::from_private_key(&private_key);
        let serialized_key: String = public_key.serialize();
        let deserialized_key =
            PubKey::deserialize((serialized_key, &key_chain, "m".into())).expect("deserialize");
        assert_eq!(public_key, deserialized_key);
    }
}
