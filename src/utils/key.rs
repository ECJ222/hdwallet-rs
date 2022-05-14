use super::error::Error;
use ring::hmac::{Context, Key, HMAC_SHA512};
use secp256k1::{PublicKey, Secp256k1, SecretKey, SignOnly, VerifyOnly};

/// Normal child key ranges from 0 - 2 ^ 31 - 1.
const MAX_NORMAL_CHILD_KEY_INDEX: u32 = 2_147_483_647;

lazy_static! {
    /// Context for signature signing.
    static ref SECP256K1_SIGN_ONLY: Secp256k1<SignOnly> = Secp256k1::signing_only();
    /// Context for signature verification.
    static ref SECP256K1_VERIFY_ONLY: Secp256k1<VerifyOnly> = Secp256k1::verification_only();
}

#[derive(Debug, Clone)]
pub struct ExtendedKey {
    pub pub_key: Option<PublicKey>,
    pub priv_key: Option<SecretKey>,
    pub chain_code: Vec<u8>
}

impl ExtendedKey {
    /// Generate the master private key and chain code from Root seed.
    pub fn new_master_private_key(seed: [u8; 64]) -> Result<ExtendedKey, Error> {
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

        Ok(ExtendedKey {
            pub_key: None,
            priv_key: Some(priv_key),
            chain_code: chain_code.to_vec(),
        })
    }

    /// Generate master public key from master private key.
    pub fn new_master_public_key(extended_key: &ExtendedKey) -> Self {
        let pub_key =
            PublicKey::from_secret_key(&*SECP256K1_SIGN_ONLY, &extended_key.priv_key.unwrap());

        ExtendedKey {
            pub_key: Some(pub_key),
            priv_key: None,
            chain_code: extended_key.chain_code.clone(),
        }
    }

    /// Generate child private key.
    pub fn generate_private_key(&self, index: u32) -> Result<ExtendedKey, Error> {
        // Ensure index does not exceed bounds.
        if index > MAX_NORMAL_CHILD_KEY_INDEX {
            return Err(Error::KeyIndexOutOfBounds);
        }

        let signature = {
            let signing_key = Key::new(HMAC_SHA512, &self.chain_code);
            let mut context = Context::with_key(&signing_key);
            let pub_key =
                PublicKey::from_secret_key(&*SECP256K1_SIGN_ONLY, &self.priv_key.unwrap());
            context.update(&pub_key.serialize());
            context.update(&index.to_be_bytes());
            context.sign()
        };

        // Convert signature to bytes.
        let signature_bytes = signature.as_ref();
        // Get master private key and chain code bytes from signature.
        let (key, chain_code) = signature_bytes.split_at(signature_bytes.len() / 2);
        // Converts a private key bytes to usable private key.
        let mut priv_key = SecretKey::from_slice(key)?;
        // Add current private ket to child private key.
        priv_key.add_assign(&self.priv_key.unwrap()[..])?;

        Ok(ExtendedKey {
            pub_key: None,
            priv_key: Some(priv_key),
            chain_code: chain_code.to_vec(),
        })
    }

    pub fn generate_public_key(&self, index: u32) -> Result<ExtendedKey, Error> {
        // Ensure index does not exceed bounds.
        if index > MAX_NORMAL_CHILD_KEY_INDEX {
            return Err(Error::KeyIndexOutOfBounds);
        }

        let signature = {
            let signing_key = Key::new(HMAC_SHA512, &self.chain_code);
            let mut context = Context::with_key(&signing_key);
            context.update(&self.pub_key.unwrap().serialize());
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
        let mut pub_key = self.pub_key.unwrap();
        // Add key to self.
        pub_key.add_exp_assign(&*SECP256K1_VERIFY_ONLY, &priv_key[..])?;

        Ok(ExtendedKey {
            pub_key: Some(pub_key),
            priv_key: None,
            chain_code: chain_code.to_vec(),
        })
    }
}
