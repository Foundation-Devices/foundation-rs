// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use foundation_test_vectors::{HDKeyVector, URVector, UR};
use foundation_urtypes::registry::{HDKeyRef, KeypathRef};

#[test]
fn test_roundtrip_ref() {
    let vectors = URVector::new();

    for vector in vectors.iter().filter(|v| matches!(v.ur, UR::HDKey(_))) {
        let hdkey = match vector.ur.unwrap_hdkey() {
            HDKeyVector::Xpub { key, origin } => {
                let mut hdkey = HDKeyRef::try_from(key).unwrap();

                match hdkey {
                    HDKeyRef::DerivedKey(ref mut derived_key) => {
                        derived_key.origin = origin.as_ref().map(KeypathRef::from);
                    }
                    _ => unreachable!(),
                }

                hdkey
            }
            HDKeyVector::Xprv { key } => HDKeyRef::try_from(key).unwrap(),
        };

        let cbor = minicbor::to_vec(&hdkey).unwrap();
        println!("our cbor: {}", hex::encode(&cbor));
        println!("test vector cbor: {}", hex::encode(&vector.as_cbor));
        assert_eq!(cbor, vector.as_cbor);
    }
}
