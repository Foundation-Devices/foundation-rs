// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use faster_hex::hex_string;
use foundation_test_vectors::{HDKeyVector, URVector, UR};
use foundation_urtypes::{
    registry::{HDKeyRef, KeypathRef, MasterKey},
    value::{Error, Value},
};
use minicbor::Encoder;

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
        println!("our cbor: {}", hex_string(&cbor));
        println!("test vector cbor: {}", hex_string(&vector.as_cbor));
        assert_eq!(cbor, vector.as_cbor);
    }
}

#[test]
fn master_private_key_roundtrips_through_value() {
    let hdkey = HDKeyRef::MasterKey(MasterKey {
        key_data: core::array::from_fn(|i| (i + 1) as u8),
        chain_code: core::array::from_fn(|i| (0x80 + i) as u8),
    });
    let cbor = minicbor::to_vec(&hdkey).unwrap();

    for ur_type in ["hdkey", "crypto-hdkey"] {
        let decoded = Value::from_ur(ur_type, &cbor).unwrap();
        assert_eq!(decoded, Value::HDKey(hdkey.clone()));
    }
}

#[test]
fn master_private_key_rejects_invalid_prefix_and_length() {
    fn encode_master_key(key_data: &[u8]) -> Vec<u8> {
        let mut cbor = Vec::new();
        let mut encoder = Encoder::new(&mut cbor);
        encoder.map(3).unwrap();
        encoder.u8(1).unwrap();
        encoder.bool(true).unwrap();
        encoder.u8(3).unwrap();
        encoder.bytes(key_data).unwrap();
        encoder.u8(4).unwrap();
        encoder.bytes(&[0x42; 32]).unwrap();
        cbor
    }

    let mut invalid_prefix = [0x11; 33];
    invalid_prefix[0] = 1;
    let invalid_values = [
        encode_master_key(&invalid_prefix),
        encode_master_key(&[0; 32]),
        encode_master_key(&[0; 34]),
    ];

    for cbor in invalid_values {
        assert!(matches!(
            Value::from_ur("crypto-hdkey", &cbor),
            Err(Error::InvalidCbor(_))
        ));
    }
}
