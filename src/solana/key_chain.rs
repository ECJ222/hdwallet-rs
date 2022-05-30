use crate::{error::Error, ChainPath, ChainPathError, KeyIndex, SolanaExPrivateKey, SubPath};

/// KeyChain derivation info
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Derivation {
    /// depth, 0 if it is master key
    pub depth: u8,
    /// parent key
    pub parent_key: Option<SolanaExPrivateKey>,
    /// key_index which used with parent key to derive this key
    pub key_index: Option<KeyIndex>,
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

pub trait KeyChain {
    fn derive_private_key(
        &self,
        chain_path: ChainPath,
    ) -> Result<(SolanaExPrivateKey, Derivation), Error>;
}

pub struct DefaultKeyChain {
    master_key: SolanaExPrivateKey,
}

impl DefaultKeyChain {
    #[allow(dead_code)]
    pub fn new(master_key: SolanaExPrivateKey) -> Self {
        DefaultKeyChain { master_key }
    }
}

impl KeyChain for DefaultKeyChain {
    fn derive_private_key(
        &self,
        chain_path: ChainPath,
    ) -> Result<(SolanaExPrivateKey, Derivation), Error> {
        let mut iter = chain_path.iter();
        // chain_path must start with root
        if iter.next() != Some(Ok(SubPath::Root)) {
            return Err(ChainPathError::Invalid.into());
        }
        let mut key = self.master_key.clone();
        let mut depth = 0;
        let mut parent_key = None;
        let mut key_index = None;
        for sub_path in iter {
            match sub_path? {
                SubPath::Child(child_key_index) => {
                    depth += 1;
                    key_index = Some(child_key_index);
                    let child_key = key.derive_private_key(child_key_index)?;
                    parent_key = Some(key);
                    key = child_key;
                }
                _ => return Err(ChainPathError::Invalid.into()),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{solana::PrivKey, solana::PubKey, traits::Serialize};
    use base58::ToBase58;

    fn from_hex(hex_string: &str) -> Vec<u8> {
        let strip_prefix = hex_string.starts_with("0x");
        if strip_prefix {
            hex::decode(&hex_string[2..]).expect("decode")
        } else {
            hex::decode(hex_string).expect("decode")
        }
    }

    fn to_hex(buf: Vec<u8>) -> String {
        hex::encode(buf)
    }

    #[test]
    fn test_bip32_vector_1() {
        let seed = from_hex("000102030405060708090a0b0c0d0e0f");
        let key_chain =
            DefaultKeyChain::new(SolanaExPrivateKey::new_master_key(&seed).expect("master key"));
        for (chain_path, hex_priv_key, hex_pub_key) in &[
            (
                "m",
                "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7",
                "C5ukMV73nk32h52MjxtnZXTrrr7rupD9CTDDRnYYDRYQ",
            ),
            (
                "m/0H",
                "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
                "ATcCGRoY87cSJESCXbHXEX6CDWQxepAViUvVnNsELhRu",
            ),
            (
                "m/0H/1H",
                "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2",
                "2hMz2f8WbLw5m2icKR2WVrcizvnguw8xaAnXjaeohuHQ",
            ),
            (
                "m/0H/1H/2H",
                "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9",
                "CkYmXLvWehLXBzUAJ3g3wsfc5QjoCtWtSydquF7HDxXS",
            ),
            (
                "m/0H/1H/2H/2H",
                "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662",
                "ALYYdMp2jVV4HGsZZPfLy1BQLMHL2CQG5XHpzr2XiHCw",
            ),
            (
                "m/0H/1H/2H/2H/1000000000H",
                "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793",
                "53n47S4RT9ozx5KrpH6uYfdnAjrTBJri8qZJBvRfw1Bf",
            ),
        ] {
            let (key, derivation) = key_chain
                .derive_private_key(ChainPath::from(*chain_path))
                .expect("fetch key");
            let priv_key = PrivKey {
                derivation,
                extended_key: key,
            };

            let pub_key = PubKey::from_private_key(&priv_key);

            assert_eq!(
                to_hex(priv_key.extended_key.private_key.to_bytes().to_vec()),
                *hex_priv_key
            );

            assert_eq!(
                &Serialize::<Vec<u8>>::serialize(&pub_key.extended_key).to_base58(),
                hex_pub_key
            );
        }
    }
}
