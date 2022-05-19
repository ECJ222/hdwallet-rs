use super::{key_index::KeyIndex, error::Error};
use ring::hmac::{Context, Key, HMAC_SHA512};
use secp256k1::{PublicKey, Secp256k1, SecretKey, SignOnly, VerifyOnly};

lazy_static! {
    /// Context for signature signing.
    static ref SECP256K1_SIGN_ONLY: Secp256k1<SignOnly> = Secp256k1::signing_only();
    /// Context for signature verification.
    static ref SECP256K1_VERIFY_ONLY: Secp256k1<VerifyOnly> = Secp256k1::verification_only();
}

pub struct Derivation {
    /// Derivation depth is 0 if it is master key
    pub depth: u8,
    pub parent_key: Option<ExtendedPrivateKey>,
    /// Used with parent key to derive this key
    pub key_index: Option<KeyIndex>,
}

#[derive(Debug, Clone)]
pub struct ExtendedPrivateKey {
    pub priv_key: SecretKey,
    pub chain_code: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ExtendedPublicKey {
    pub pub_key: PublicKey,
    pub chain_code: Vec<u8>,
}

impl Derivation {
    pub fn master() -> Self {
        Derivation {
            depth: 0,
            parent_key: None,
            key_index: None,
        }
    }
}

impl Default for Derivation {
    fn default() -> Self {
        Derivation::master()
    }
}

impl ExtendedPublicKey {
    /// Generate master public key from master private key.
    pub fn new_master_public_key(extended_key: &ExtendedPrivateKey) -> Self {
        let pub_key =
            PublicKey::from_secret_key(&*SECP256K1_SIGN_ONLY, &extended_key.priv_key);

        ExtendedPublicKey {
            pub_key: pub_key,
            chain_code: extended_key.chain_code.clone(),
        }
    }

    pub fn derive_public_key(&self, key_index: KeyIndex) -> Result<ExtendedPublicKey, Error> {
        // Ensure index does not exceed bounds.
        if !key_index.is_valid() {
            return Err(Error::KeyIndexOutOfBounds);
        }

        let index = match key_index {
            KeyIndex::Normal(i) => i,
            KeyIndex::Hardened(_) => return Err(Error::KeyIndexOutOfBounds),
        };

        let signature = {
            let signing_key = Key::new(HMAC_SHA512, &self.chain_code);
            let mut context = Context::with_key(&signing_key);
            context.update(&self.pub_key.serialize());
            context.update(&index.to_be_bytes());
            context.sign()
        };

        // Convert signature to bytes.
        let signature_bytes = signature.as_ref();
        // Get master private key and chain code bytes from signature.
        let (key, chain_code) = signature_bytes.split_at(signature_bytes.len() / 2);
        // Converts a private key bytes to usable private key.
        let priv_key = SecretKey::from_slice(key)?;
        // Public key.
        let mut pub_key = self.pub_key;
        // Add key to self.
        pub_key.add_exp_assign(&*SECP256K1_VERIFY_ONLY, &priv_key[..])?;

        Ok(ExtendedPublicKey {
            pub_key: pub_key,
            chain_code: chain_code.to_vec(),
        })
    }
}

impl ExtendedPrivateKey {
    /// Generate the master private key and chain code from Root seed.
    pub fn new_master_private_key(seed: [u8; 64]) -> Result<ExtendedPrivateKey, Error> {
        // Create signature from seed data with HMAC-SHA512.
        let signature = {
            let key = Key::new(HMAC_SHA512, b"Bitcoin seed");
            let mut context = Context::with_key(&key);
            context.update(&seed);
            context.sign()
        };

        // Convert signature to bytes.
        let signature_bytes = signature.as_ref();
        // Get master private key and chain code bytes from signature.
        let (master_key, chain_code) = signature_bytes.split_at(signature_bytes.len() / 2);
        // Converts a master private key bytes to usable private key.
        let priv_key = SecretKey::from_slice(master_key)?;

        Ok(ExtendedPrivateKey {
            priv_key: priv_key,
            chain_code: chain_code.to_vec(),
        })
    }

    fn sign_hardened_key(&self, index: u32) -> ring::hmac::Tag {
        let signing_key = Key::new(HMAC_SHA512, &self.chain_code);
        let mut context = Context::with_key(&signing_key);
        context.update(&[0x00]);
        context.update(&self.priv_key[..]);
        context.update(&index.to_be_bytes());
        context.sign()
    }

    fn sign_normal_key(&self, index: u32) -> ring::hmac::Tag {
        let signing_key = Key::new(HMAC_SHA512, &self.chain_code);
        let mut context = Context::with_key(&signing_key);
        let pub_key = PublicKey::from_secret_key(&*SECP256K1_SIGN_ONLY, &self.priv_key);
        context.update(&pub_key.serialize());
        context.update(&index.to_be_bytes());
        context.sign()
    }

    /// Generate child private key.
    pub fn derive_private_key(&self, key_index: KeyIndex) -> Result<ExtendedPrivateKey, Error> {
        let signature = match key_index {
            KeyIndex::Hardened(index) => self.sign_hardened_key(index),
            KeyIndex::Normal(index) => self.sign_normal_key(index),
        };

        // Convert signature to bytes.
        let signature_bytes = signature.as_ref();
        // Get master private key and chain code bytes from signature.
        let (key, chain_code) = signature_bytes.split_at(signature_bytes.len() / 2);
        // Converts a private key bytes to usable private key.
        let mut priv_key = SecretKey::from_slice(key)?;
        // Add current private ket to child private key.
        priv_key.add_assign(&self.priv_key[..])?;



        Ok(ExtendedPrivateKey {
            priv_key: priv_key,
            chain_code: chain_code.to_vec(),
        })
    }
}
