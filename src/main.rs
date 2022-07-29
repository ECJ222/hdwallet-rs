use hdwallet_rs::{
    extended_key::{SolanaExPrivateKey, SolanaExPublicKey, EthereumExPrivateKey, EthereumExPublicKey},
    //solana::{
      //  PrivKey,
       // PubKey,
       // key_chain::{DefaultKeyChain, KeyChain},
    //},
    ethereum::{
        PrivKey,
        PubKey, 
        key_chain::{DefaultKeyChain, KeyChain},
    },
    chain_path::ChainPath,
    traits::Serialize, 
    mnemonic
};
/*
fn main() {
    *********** SOL ***********
    let new_mnemonic = mnemonic::new_mnemonic(24, "English");
    println!("{:?}", new_mnemonic);
    let new_seed = mnemonic::new_seed(new_mnemonic.unwrap(), "".to_string());
    // let private_key = ExtendedPrivateKey::new_master_private_key(new_seed).unwrap();
    //let master_key = ExtendedEdDsaPrivKey::new_master_key(&new_seed).unwrap();
    let master_key = SolanaExPrivateKey::new_master_key(&new_seed);
    println!("{:?}", master_key);
    let seed = hex::decode("000102030405060708090a0b0c0d0e8f").expect("decode");
    let key_chain =
        DefaultKeyChain::new(SolanaExPrivateKey::new_master_key(&seed).unwrap());
    let key = key_chain
        .derive_private_key(ChainPath::from("m/44/501'/1'"))
        .expect("fetch key");
    let priv_key = PrivKey {
        derivation: key.1.clone(),
        extended_key: key.0.clone(),
    };
   // println!("{:?}", PubKey::from_private_key(&priv_key).extended_key.0.to_bytes());
    //println!("{:?}", &Serialize::<String>::serialize(&PubKey::from_private_key(&priv_key)));
    //println!("base58-encode -> {:?} \n\n\n extended_key -> {:?} \n\n\n derivation -> {:?} \n\n\n", &Serialize::<String>::serialize(&priv_key), hex::encode(priv_key.extended_key.private_key.to_bytes()), priv_key.derivation);
    //println!("{:?}", master_key.derive_private_key(KeyIndex::from(20)));
}
*/



fn main() {
        //*********** SOL ***********
        let new_mnemonic = mnemonic::new_mnemonic(24, "English");
        println!("{:?}", new_mnemonic);
        let new_seed = mnemonic::new_seed(new_mnemonic.unwrap(), "".to_string());
        let private_key = EthereumExPrivateKey::new_master_key(&new_seed).unwrap();
        //let master_key = ExtendedEdDsaPrivKey::new_master_key(&new_seed).unwrap();
        let master_key = SolanaExPrivateKey::new_master_key(&new_seed);
        println!("{:?}", master_key);
        let seed = hex::decode("000102030405060708090a0b0c0d0e8f").expect("decode");
        let key_chain =
            DefaultKeyChain::new(EthereumExPrivateKey::new_master_key(&seed).unwrap());
        let key = key_chain
            .derive_private_key(ChainPath::from("m/44/60/0"))
            .expect("fetch key");
        let priv_key = PrivKey {
            derivation: key.1.clone(),
            extended_key: key.0.clone(),
        };
          println!("{:?}", PubKey::from_private_key(&priv_key).extended_key.0.to_bytes());
          println!("{:?}", &Serialize::<String>::serialize(&PubKey::from_private_key(&priv_key)));
        //println!("base58-encode -> {:?} \n\n\n extended_key -> {:?} \n\n\n derivation -> {:?} \n\n\n", &Serialize::<String>::serialize(&priv_key), hex::encode(priv_key.extended_key.private_key.to_bytes()), priv_key.derivation);
        //println!("{:?}", master_key.derive_private_key(KeyIndex::from(20)));
}
    
