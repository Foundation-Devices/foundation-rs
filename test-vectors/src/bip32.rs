// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

#[derive(Debug, serde::Deserialize)]
pub struct TestVectors {
    pub valid: Vec<TestVector>,
    pub invalid: Vec<InvalidTestVector>,
}

impl TestVectors {
    pub fn new() -> Self {
        serde_json::from_slice(include_bytes!("../data/bip-0032.json"))
            .expect("file should be valid JSON")
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TestVector {
    pub name: String,
    #[serde(rename = "seed-hex", with = "faster_hex::nopfx_ignorecase")]
    pub seed: Vec<u8>,
    pub chains: Vec<Chain>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Chain {
    pub chain: String,
    pub extended_public_key: ExtendedKey,
    pub extended_private_key: ExtendedKey,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct InvalidTestVector {
    pub name: String,
    pub extended_keys: Vec<ExtendedKey>,
}

#[derive(Debug, serde::Deserialize)]
pub struct ExtendedKey(#[serde(with = "base58")] pub Vec<u8>);

mod base58 {
    use bs58::decode::DecodeTarget;
    use std::fmt::Formatter;
    use std::marker::PhantomData;

    use serde::{
        de::{Error, Visitor},
        Deserializer,
    };

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: DecodeTarget + Default,
    {
        struct Base58Visitor<T>(PhantomData<T>);
        impl<'de, T> Visitor<'de> for Base58Visitor<T>
        where
            T: DecodeTarget + Default,
        {
            type Value = T;

            fn expecting(&self, f: &mut Formatter) -> std::fmt::Result {
                f.write_str("Base58 encoded string")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                let mut target = T::default();
                bs58::decode(v).onto(&mut target).map_err(E::custom)?;
                Ok(target)
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: Error,
            {
                self.visit_str(&v)
            }
        }

        deserializer.deserialize_str(Base58Visitor(PhantomData))
    }
}
