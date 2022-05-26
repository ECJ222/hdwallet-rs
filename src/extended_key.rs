pub mod key_index;

use curve25519_dalek::edwards::CompressedEdwardsY;

use crate::{
    error::Error,
    traits::{Deserialize, Serialize},
};
use ed25519_dalek::{PublicKey as Pk, SecretKey as Sk};
use key_index::KeyIndex;
use ring::hmac::{Context, Key, HMAC_SHA512};
use secp256k1::{PublicKey, Secp256k1, SecretKey, SignOnly, VerifyOnly};

use std::rc::Rc;

lazy_static! {
    static ref SECP256K1_SIGN_ONLY: Secp256k1<SignOnly> = Secp256k1::signing_only();
    static ref SECP256K1_VERIFY_ONLY: Secp256k1<VerifyOnly> = Secp256k1::verification_only();
}

/// Random entropy, part of extended key.
/// 
type ChainCode = Vec<u8>;

/// Extended Private Key implementation based on the Secp256k1 Curve
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinExPrivateKey {
    pub private_key: SecretKey,
    pub chain_code: ChainCode,
}

impl BitcoinExPrivateKey {
    /// Generate an BitcoinExPrivateKey from seed
    pub fn new_master_key(seed: &[u8]) -> Result<BitcoinExPrivateKey, Error> {
        let signature = {
            let signing_key = Key::new(HMAC_SHA512, b"Bitcoin seed");
            let mut h = Context::with_key(&signing_key);
            h.update(&seed);
            h.sign()
        };
        let sig_bytes = signature.as_ref();
        let (key, chain_code) = sig_bytes.split_at(sig_bytes.len() / 2);
        let private_key = SecretKey::from_slice(key)?;
        Ok(BitcoinExPrivateKey {
            private_key: private_key,
            chain_code: chain_code.to_vec(),
        })
    }

    fn sign_hardended_key(&self, index: u32) -> ring::hmac::Tag {
        let signing_key = Key::new(HMAC_SHA512, &self.chain_code);
        let mut h = Context::with_key(&signing_key);
        h.update(&[0x00]);
        h.update(&self.private_key[..]);
        h.update(&index.to_be_bytes());
        h.sign()
    }

    fn sign_normal_key(&self, index: u32) -> ring::hmac::Tag {
        let signing_key = Key::new(HMAC_SHA512, &self.chain_code);
        let mut h = Context::with_key(&signing_key);
        let public_key = PublicKey::from_secret_key(&*SECP256K1_SIGN_ONLY, &self.private_key);
        h.update(&public_key.serialize());
        h.update(&index.to_be_bytes());
        h.sign()
    }

    /// Derive a child key from BitcoinExPrivateKey.
    pub fn derive_private_key(&self, key_index: KeyIndex) -> Result<BitcoinExPrivateKey, Error> {
        if !key_index.is_valid() {
            return Err(Error::KeyIndexOutOfRange);
        }
        let signature = match key_index {
            KeyIndex::Hardened(index) => self.sign_hardended_key(index),
            KeyIndex::Normal(index) => self.sign_normal_key(index),
        };
        let sig_bytes = signature.as_ref();
        let (key, chain_code) = sig_bytes.split_at(sig_bytes.len() / 2);
        let mut private_key = SecretKey::from_slice(key)?;
        private_key.add_assign(&self.private_key[..])?;
        Ok(BitcoinExPrivateKey {
            private_key: private_key,
            chain_code: chain_code.to_vec(),
        })
    }
}

/// Extended Public Key implementation for the Secp256k1 Curve

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitcoinExPublicKey {
    pub public_key: PublicKey,
    pub chain_code: ChainCode,
}

impl BitcoinExPublicKey {
    /// Derive public normal child key from BitcoinExPublicKey,
    /// will return error if key_index is a hardened key.
    pub fn derive_public_key(&self, key_index: KeyIndex) -> Result<BitcoinExPublicKey, Error> {
        if !key_index.is_valid() {
            return Err(Error::KeyIndexOutOfRange);
        }

        let index = match key_index {
            KeyIndex::Normal(i) => i,
            KeyIndex::Hardened(_) => return Err(Error::KeyIndexOutOfRange),
        };

        let signature = {
            let signing_key = Key::new(HMAC_SHA512, &self.chain_code);
            let mut h = Context::with_key(&signing_key);
            h.update(&self.public_key.serialize());
            h.update(&index.to_be_bytes());
            h.sign()
        };
        let sig_bytes = signature.as_ref();
        let (key, chain_code) = sig_bytes.split_at(sig_bytes.len() / 2);
        let private_key = SecretKey::from_slice(key)?;
        let mut public_key = self.public_key;
        public_key.add_exp_assign(&*SECP256K1_VERIFY_ONLY, &private_key[..])?;
        Ok(BitcoinExPublicKey {
            public_key: public_key,
            chain_code: chain_code.to_vec(),
        })
    }

    /// BitcoinExPublicKey from BitcoinExPrivateKey
    pub fn from_private_key(extended_key: &BitcoinExPrivateKey) -> Self {
        let public_key =
            PublicKey::from_secret_key(&*SECP256K1_SIGN_ONLY, &extended_key.private_key);

        BitcoinExPublicKey {
            public_key: public_key,
            chain_code: extended_key.chain_code.clone(),
        }
    }
}

/// Serialize Extended Private Key.

impl Serialize<Vec<u8>> for BitcoinExPrivateKey {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = self.private_key[..].to_vec();
        buf.extend(&self.chain_code);
        buf
    }
}

/// Deserialize Extended Private Key.

impl Deserialize<&[u8], Error> for BitcoinExPrivateKey {
    fn deserialize(data: &[u8]) -> Result<Self, Error> {
        let private_key = SecretKey::from_slice(&data[..32])?;
        let chain_code = data[32..].to_vec();
        Ok(BitcoinExPrivateKey {
            private_key: private_key,
            chain_code,
        })
    }
}

/// Serialize Extended Public Key.

impl Serialize<Vec<u8>> for BitcoinExPublicKey {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = self.public_key.serialize().to_vec();
        buf.extend(&self.chain_code);
        buf
    }
}

/// Deserialize Extended Public Key.

impl Deserialize<&[u8], Error> for BitcoinExPublicKey {
    fn deserialize(data: &[u8]) -> Result<Self, Error> {
        let public_key = PublicKey::from_slice(&data[..33])?;
        let chain_code = data[33..].to_vec();
        Ok(BitcoinExPublicKey {
            public_key: public_key,
            chain_code,
        })
    }
}

/// Extended Private Key implementation based on the EdDSA Curve

#[derive(Debug, Clone)]
pub struct SolanaExPrivateKey {
    pub private_key: Rc<Sk>,
    pub chain_code: ChainCode,
}

impl Eq for SolanaExPrivateKey {}

impl PartialEq for SolanaExPrivateKey {
    fn eq(&self, other: &Self) -> bool {
        self.private_key.as_bytes() == other.private_key.as_bytes()
            && self.chain_code == other.chain_code
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolanaExPublicKey(pub Pk);

impl SolanaExPrivateKey {
    pub fn new_master_key(seed: &[u8]) -> Result<SolanaExPrivateKey, Error> {
        let signature = {
            let signing_key = Key::new(HMAC_SHA512, b"ed25519 seed");
            let mut h = Context::with_key(&signing_key);
            h.update(&seed);
            h.sign()
        };
        let sig_bytes = signature.as_ref();
        let (key, chain_code) = sig_bytes.split_at(sig_bytes.len() / 2);
        let private_key = Rc::new(Sk::from_bytes(key)?);

        Ok(SolanaExPrivateKey {
            private_key: private_key,
            chain_code: chain_code.to_vec(),
        })
    }

    fn sign_hardended_key(&self, index: u32) -> ring::hmac::Tag {
        let signing_key = Key::new(HMAC_SHA512, &self.chain_code);
        let mut h = Context::with_key(&signing_key);
        h.update(&[0x00]);
        h.update(&self.private_key.to_bytes());
        h.update(&index.to_be_bytes());
        h.sign()
    }

    pub fn derive_private_key(&self, key_index: KeyIndex) -> Result<SolanaExPrivateKey, Error> {
        if !key_index.is_valid() {
            return Err(Error::KeyIndexOutOfRange);
        }

        let signature = self.sign_hardended_key(key_index.raw_index());

        let sig_bytes = signature.as_ref();
        let (key, chain_code) = sig_bytes.split_at(sig_bytes.len() / 2);
        let private_key = Rc::new(Sk::from_bytes(key)?);

        Ok(SolanaExPrivateKey {
            private_key: private_key,
            chain_code: chain_code.to_vec(),
        })
    }
}

impl SolanaExPublicKey {
    pub fn from_private_key(extended_key: &SolanaExPrivateKey) -> Result<SolanaExPublicKey, Error> {
        let private_key = Rc::try_unwrap(Rc::clone(&extended_key.private_key)).unwrap_err();

        let public_key = Pk::from(&*private_key);

        Ok(SolanaExPublicKey(public_key))
    }

   pub fn is_on_curve(bytes: &[u8]) -> bool {
        CompressedEdwardsY::from_slice(bytes.as_ref())
            .decompress()
            .is_some()
    }
}

impl Serialize<Vec<u8>> for SolanaExPublicKey {
    fn serialize(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }
}