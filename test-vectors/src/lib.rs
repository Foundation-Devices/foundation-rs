// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

#[cfg(feature = "nostr")]
#[derive(Debug, serde::Deserialize)]
pub struct NIP19Vector {
    pub name: String,
    pub kind: String,
    #[serde(with = "faster_hex::nopfx_ignorecase")]
    pub bytes: Vec<u8>,
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
    #[serde(with = "faster_hex::nopfx_ignorecase")]
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
#[cfg(feature = "firmware")]
pub mod firmware;
#[cfg(feature = "psbt")]
pub mod psbt;

#[cfg(feature = "blockchain-commons")]
mod blockchain_commons {
    use serde::Deserialize;

    #[derive(Debug, Clone, Deserialize)]
    pub enum UR {
        #[serde(rename = "bytes", with = "faster_hex::nopfx_ignorecase")]
        Bytes(Vec<u8>),
        #[serde(rename = "address")]
        Address(AddressVector),
        #[serde(rename = "eckey")]
        ECKey(ECKeyVector),
        #[serde(rename = "hdkey")]
        HDKey(HDKeyVector),
        #[serde(rename = "psbt", with = "faster_hex::nopfx_ignorecase")]
        Psbt(Vec<u8>),
        #[serde(rename = "seed")]
        Seed(SeedVector),
    }

    impl UR {
        pub fn unwrap_address(&self) -> &AddressVector {
            match self {
                UR::Address(v) => v,
                _ => panic!(),
            }
        }

        pub fn unwrap_eckey(&self) -> &ECKeyVector {
            match self {
                UR::ECKey(v) => v,
                _ => panic!(),
            }
        }

        pub fn unwrap_hdkey(&self) -> &HDKeyVector {
            match self {
                UR::HDKey(v) => v,
                _ => panic!(),
            }
        }
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub enum AddressVector {
        Bitcoin(bitcoin::Address<bitcoin::address::NetworkUnchecked>),
        #[serde(with = "faster_hex::withpfx_ignorecase")]
        Ethereum(Vec<u8>),
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct ECKeyVector {
        pub is_private: bool,
        #[serde(with = "faster_hex::nopfx_ignorecase")]
        pub data: Vec<u8>,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub enum HDKeyVector {
        Xpub {
            key: bitcoin::bip32::Xpub,
            origin: Option<bitcoin::bip32::DerivationPath>,
        },
        Xprv {
            key: bitcoin::bip32::Xpriv,
        },
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct SeedVector {
        #[serde(with = "faster_hex::nopfx_ignorecase")]
        pub payload: Vec<u8>,
        pub creation_date: u64,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    pub struct URVector {
        pub name: String,
        #[serde(with = "faster_hex::nopfx_ignorecase")]
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
}

#[cfg(feature = "blockchain-commons")]
pub use self::blockchain_commons::*;
