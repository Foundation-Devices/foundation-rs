// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use foundation_test_vectors::{CryptoHDKeyVector, URVector, UR};
use foundation_ur::registry::{CryptoHDKey, CryptoKeypath};

#[test]
fn test_roundtrip() {
    let vectors = URVector::new();

    for vector in vectors
        .iter()
        .filter(|v| matches!(v.ur, UR::CryptoHDKey(_)))
    {
        let hdkey = match vector.ur.unwrap_crypto_hdkey() {
            CryptoHDKeyVector::Xpub { key, origin } => {
                let mut hdkey = CryptoHDKey::try_from(key).unwrap();

                match hdkey {
                    CryptoHDKey::DerivedKey(ref mut derived_key) => {
                        derived_key.origin = origin.as_ref().map(CryptoKeypath::from);
                    }
                    _ => unreachable!(),
                }

                hdkey
            }
            CryptoHDKeyVector::Xprv { key } => CryptoHDKey::try_from(key).unwrap(),
        };

        let cbor = minicbor::to_vec(&hdkey).unwrap();
        assert_eq!(cbor, vector.as_cbor);
    }
}
