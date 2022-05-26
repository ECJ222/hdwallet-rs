// pub enum Network {
//   MainNet,
//   TestNet,
// }

// #[derive(Debug, Clone, PartialEq, Eq)]
// pub struct PrivKey {
//   pub network: Network,
//   pub derivation: Derivation,
//   pub extended_key: BitcoinExPrivateKey,
// }

// impl PrivKey {
//   pub fn from_master_key(extended_key: BitcoinExPrivateKey, network: Network) -> Self {
//       PrivKey {
//           extended_key,
//           network,
//           derivation: Derivation::master(),
//       }
//   }
// }
