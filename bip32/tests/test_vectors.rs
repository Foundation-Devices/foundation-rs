// SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use foundation_bip32::{
    parser::{xprv, xpub},
    DerivationPathStr, Xpriv, VERSION_XPUB,
};
use foundation_test_vectors::bip32::TestVectors;
use secp256k1::Secp256k1;

#[test]
fn parse_xpub() {
    let vectors = TestVectors::new();

    for test_vector in vectors.valid {
        println!("Test vector: {}", test_vector.name);
        for chain in &test_vector.chains {
            let buf = chain.extended_public_key.as_slice();
            xpub::<_, nom::error::Error<_>>(buf).unwrap();
        }
    }
}

#[test]
fn parse_only_xpub() {
    let vectors = TestVectors::new();

    for test_vector in vectors.valid {
        println!("Test vector: {}", test_vector.name);
        for chain in &test_vector.chains {
            let buf = chain.extended_private_key.as_slice();
            xpub::<_, nom::error::Error<_>>(buf).unwrap_err();
        }
    }
}

#[test]
fn parse_invalid_xpub() {
    let vectors = TestVectors::new();

    for test_vector in vectors.invalid {
        println!("Test vector: {}", test_vector.name);
        for (i, key) in test_vector.extended_keys.iter().enumerate() {
            println!("Index: {}", i);
            xpub::<_, nom::error::Error<_>>(key.as_slice()).unwrap_err();
        }
    }
}

#[test]
fn parse_xprv() {
    let vectors = TestVectors::new();

    for test_vector in vectors.valid {
        println!("Test vector: {}", test_vector.name);
        for chain in &test_vector.chains {
            let buf = chain.extended_private_key.as_slice();
            xprv::<_, nom::error::Error<_>>(buf).unwrap();
        }
    }
}

#[test]
fn parse_only_xprv() {
    let vectors = TestVectors::new();

    for test_vector in vectors.valid {
        println!("Test vector: {}", test_vector.name);
        for chain in &test_vector.chains {
            let buf = chain.extended_public_key.as_slice();
            xprv::<_, nom::error::Error<_>>(buf).unwrap_err();
        }
    }
}

#[test]
fn derivations() {
    let secp = Secp256k1::signing_only();
    let test_vectors = TestVectors::new();

    for test_vector in test_vectors.valid {
        println!("Test vector: {}", test_vector.name);

        let master_key = Xpriv::new_master(VERSION_XPUB, &test_vector.seed).unwrap();

        for chain in test_vector.chains {
            println!("Derivation path: {}.", chain.chain);

            let derivation_path = DerivationPathStr::from_str(&chain.chain).unwrap();

            let expected_xprv =
                xprv::<_, nom::error::Error<_>>(chain.extended_private_key.as_slice())
                    .map(|(_, v)| v)
                    .expect("test vector extended private key should be valid");
            let xprv = master_key.derive_xpriv(&secp, derivation_path.iter());
            assert_eq!(xprv.private_key, expected_xprv.private_key);
        }
    }
}
