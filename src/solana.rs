pub mod key_chain;

use crate::ring::digest;
use crate::{
    ed25519_dalek::{PublicKey, SecretKey as Sk},
    traits::{Deserialize, Serialize},
    KeyIndex, SolanaExPrivateKey, SolanaExPublicKey,
};
use key_chain::Derivation;

// &Serialize::<String>::serialize(&priv_key)

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
// pub struct PubKey(pub SolanaExPublicKey);

pub struct PubKey {
    pub derivation: Derivation,
    pub extended_key: SolanaExPublicKey,
}

impl PubKey {
    pub fn from_private_key(priv_key: &PrivKey) -> PubKey {
        let pub_key = SolanaExPublicKey::from_private_key(&priv_key.extended_key);
        // PubKey(pub_key.unwrap())
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

fn decode_derivation(buf: &[u8]) -> Result<Derivation, Error> {
    let depth = u8::from_be_bytes([buf[4]; 1]);
    let parent_fingerprint = &buf[5..=8];
    let key_index = {
        // is master key
        if parent_fingerprint == [0; 4] {
            None
        } else {
            let mut key_index_buf = [0u8; 4];
            key_index_buf.copy_from_slice(&buf[9..=12]);
            let raw_index = u32::from_be_bytes(key_index_buf);
            Some(KeyIndex::from(raw_index))
        }
    };
    Ok(Derivation {
        depth,
        parent_key: None,
        key_index,
    })
}

fn encode_checksum(buf: &mut Vec<u8>) {
    let check_sum = {
        let buf = digest::digest(&digest::SHA256, &buf);
        digest::digest(&digest::SHA256, &buf.as_ref())
    };

    buf.extend_from_slice(&check_sum.as_ref()[0..4]);
}

fn verify_checksum(buf: &[u8]) -> Result<(), Error> {
    let check_sum = {
        let buf = digest::digest(&digest::SHA256, &buf[0..78]);
        digest::digest(&digest::SHA256, &buf.as_ref())
    };
    if check_sum.as_ref()[0..4] == buf[78..82] {
        Ok(())
    } else {
        Err(Error::MisChecksum)
    }
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

        encode_derivation(
            &mut buf,
            &self.derivation,
        );

        buf.extend_from_slice(&self.extended_key.0.to_bytes());
        // assert_eq!(buf.len(), 78);
        encode_checksum(&mut buf);

        buf
    }
}

impl Serialize<String> for PubKey {
    fn serialize(&self) -> String {
        Serialize::<Vec<u8>>::serialize(&self.extended_key).to_base58()
    }
}

impl Deserialize<Vec<u8>, Error> for PrivKey {
    fn deserialize(data: Vec<u8>) -> Result<PrivKey, Error> {
        verify_checksum(&data)?;
        let derivation = decode_derivation(&data)?;
        let chain_code = data[13..45].to_vec();
        let private_key = Rc::new(Sk::from_bytes(&data[46..78])?);
        Ok(PrivKey {
            derivation,
            extended_key: SolanaExPrivateKey {
                private_key: private_key,
                chain_code,
            },
        })
    }
}

impl Deserialize<String, Error> for PrivKey {
    fn deserialize(data: String) -> Result<PrivKey, Error> {
        let data = data.from_base58().map_err(|_| Error::InvalidBase58)?;
        PrivKey::deserialize(data)
    }
}

impl Deserialize<Vec<u8>, Error> for PubKey {
    fn deserialize(data: Vec<u8>) -> Result<PubKey, Error> {
        verify_checksum(&data)?;

        let derivation = decode_derivation(&data)?;
        let private_key = Sk::from_bytes(&data[46..78])?;
        let public_key = PublicKey::from(&private_key);

        Ok(PubKey {
            derivation,
            extended_key: SolanaExPublicKey(public_key),
        })
    }
}

impl Deserialize<String, Error> for PubKey {
    fn deserialize(data: String) -> Result<PubKey, Error> {
        let data = data.from_base58().map_err(|_| Error::InvalidBase58)?;
        PubKey::deserialize(data)
    }
}

/*

Create a CLI based HD wallet that supports Bitcoin, Solana, Ethereum and Polkadot

Check this repo's for inspiration

CLI -> https://github.com/AleoHQ/wagyu/blob/master/ethereum/src/public_key.rs
HD WALLET -> https://github.com/jjyr/hdwallet/tree/master/src

CRYPTO INFORMATION [
  http://ethanfast.com/top-crypto.html,
  https://github.com/BL0CK-X/blockchain-api,
  https://docs.rs/ed25519/latest/ed25519/,
  https://github.com/ethereumjs/ethereumjs-util/blob/ebf40a0fba8b00ba9acae58405bca4415e383a0d/src/account.ts,
  https://github.com/satoshilabs/slips/blob/master/slip-0044.md,
  https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md,
  https://arshbot.medium.com/so-you-want-to-build-an-ethereum-hd-wallet-cb2b7d7e4998
  https://github.com/jjyr/hdwallet/tree/master/src,
  https://learnmeabitcoin.com/technical/base58
]

*/
