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
