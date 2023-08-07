// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

#[cfg(feature = "nostr")]
#[derive(Debug, serde::Deserialize)]
pub struct NIP19Vector {
    pub name: String,
    pub kind: String,
    #[serde(with = "hex")]
    pub bytes: [u8; 32],
    pub encoded: String,
}

#[cfg(feature = "nostr")]
impl NIP19Vector {
    pub fn new() -> Vec<Self> {
        serde_json::from_slice(include_bytes!("../data/nip-19.json"))
            .expect("file should be valid JSON")
    }
}

#[cfg(feature = "seedqr")]
#[derive(Debug, serde::Deserialize)]
pub struct SeedQRVector {
    pub name: String,
    pub seed: bip39::Mnemonic,
    pub as_digits: String,
    pub as_compact_bits: String,
    #[serde(with = "hex")]
    pub as_compact_bytes: Vec<u8>,
}

#[cfg(feature = "seedqr")]
impl SeedQRVector {
    pub fn new() -> Vec<Self> {
        serde_json::from_slice(include_bytes!("../data/seedqr.json"))
            .expect("file should be valid JSON")
    }
}

#[cfg(feature = "bip32")]
pub mod bip32;

#[cfg(feature = "blockchain-commons")]
mod blockchain_commons {
    use serde::Deserialize;

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub enum UR {
        #[serde(with = "hex")]
        Bytes(Vec<u8>),
        CryptoAddress(CryptoAddressVector),
        #[serde(rename = "crypto-eckey")]
        CryptoECKey(CryptoECKeyVector),
        #[serde(rename = "crypto-hdkey")]
        CryptoHDKey(CryptoHDKeyVector),
        #[serde(with = "hex")]
        CryptoPsbt(Vec<u8>),
        CryptoSeed(CryptoSeedVector),
    }

    impl UR {
        pub fn unwrap_crypto_address(&self) -> &CryptoAddressVector {
            match self {
                UR::CryptoAddress(v) => v,
                _ => panic!(),
            }
        }

        pub fn unwrap_crypto_eckey(&self) -> &CryptoECKeyVector {
            match self {
                UR::CryptoECKey(v) => v,
                _ => panic!(),
            }
        }

        pub fn unwrap_crypto_hdkey(&self) -> &CryptoHDKeyVector {
            match self {
                UR::CryptoHDKey(v) => v,
                _ => panic!(),
            }
        }
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub enum CryptoAddressVector {
        Bitcoin(bitcoin::Address<bitcoin::address::NetworkUnchecked>),
        #[serde(with = "prefix_hex")]
        Ethereum(Vec<u8>),
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct CryptoECKeyVector {
        pub is_private: bool,
        #[serde(with = "hex")]
        pub data: Vec<u8>,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub enum CryptoHDKeyVector {
        Xpub {
            key: bitcoin::bip32::ExtendedPubKey,
            origin: Option<bitcoin::bip32::DerivationPath>,
        },
        Xprv {
            key: bitcoin::bip32::ExtendedPrivKey,
        },
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct CryptoSeedVector {
        #[serde(with = "hex")]
        pub payload: Vec<u8>,
        pub creation_date: u64,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct URVector {
        pub name: String,
        #[serde(with = "hex")]
        pub as_cbor: Vec<u8>,
        pub as_ur: String,
        pub ur: UR,
    }

    impl URVector {
        pub fn new() -> Vec<Self> {
            const FILES: &[&[u8]] = &[
                include_bytes!("../data/bcr-2020-006.json"),
                include_bytes!("../data/bcr-2020-007.json"),
                include_bytes!("../data/bcr-2020-008.json"),
                include_bytes!("../data/bcr-2020-009.json"),
            ];

            let mut vectors = Vec::new();
            for file in FILES {
                let vector: Vec<Self> =
                    serde_json::from_slice(file).expect("files should be valid JSON");
                vectors.extend_from_slice(&vector);
            }
            vectors
        }
    }

    mod prefix_hex {
        use std::{fmt::Display, fmt::Formatter, marker::PhantomData};

        use hex::FromHex;
        use serde::{
            de::{Error, Visitor},
            Deserializer,
        };

        pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
        where
            D: Deserializer<'de>,
            T: FromHex,
            <T as FromHex>::Error: Display,
        {
            struct HexStrVisitor<T>(PhantomData<T>);
            impl<'de, T> Visitor<'de> for HexStrVisitor<T>
            where
                T: FromHex,
                <T as FromHex>::Error: Display,
            {
                type Value = T;

                fn expecting(&self, f: &mut Formatter) -> std::fmt::Result {
                    f.write_str("hex encoded string with 0x prefix")
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: Error,
                {
                    let v = v
                        .strip_prefix("0x")
                        .ok_or_else(|| Error::custom("invalid prefix"))?;

                    FromHex::from_hex(v).map_err(Error::custom)
                }

                fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
                where
                    E: Error,
                {
                    self.visit_str(&v)
                }
            }

            deserializer.deserialize_str(HexStrVisitor(PhantomData))
        }
    }
}

#[cfg(feature = "blockchain-commons")]
pub use self::blockchain_commons::*;
