// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

#[derive(Debug, serde::Deserialize)]
pub struct TestVectors {
    pub invalid: Vec<TestVector>,
    pub valid: Vec<TestVector>,
}

impl TestVectors {
    pub fn bip_0174() -> Self {
        serde_json::from_slice(include_bytes!("../data/bip-0174.json"))
            .expect("file should be valid JSON")
    }

    pub fn bip_0370() -> Self {
        serde_json::from_slice(include_bytes!("../data/bip-0370.json"))
            .expect("file should be valid JSON")
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct TestVector {
    pub description: String,
    #[serde(with = "faster_hex::nopfx_ignorecase", rename = "as-hex")]
    pub data: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bip_0174() {
        TestVectors::bip_0174();
    }

    #[test]
    fn test_parse_bip_0370() {
        TestVectors::bip_0370();
    }
}
