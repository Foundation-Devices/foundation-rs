// SPDX-FileCopyrightText: © 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! `verify_signature()` as an entry point of its own.
//!
//! `tests/test-vectors.rs` drives `Header::verify()` directly, which leaves the
//! signature entry point untested on a header that should never reach a key
//! lookup. It used to `assert!(header.verify().is_ok())`, so a caller that had
//! not verified first got a panic; it now returns `InvalidHeader`.
//!
//! The context is pre-allocated rather than taken from `secp256k1::global`, so
//! this runs under `--no-default-features` too, where the `binary` feature and
//! its global context are absent.
//!
//! Assertions use `matches!` because `VerifySignatureError` is `Debug` only.
//! Deriving `PartialEq` on it would be a further change to the public API, and
//! this test is not the place to make one.

use bitcoin_hashes::sha256d;
use foundation_firmware::{
    header, verify_signature, VerifyHeaderError, VerifySignatureError, MAX_PUBLIC_KEYS,
};
use foundation_test_vectors::firmware::{INVALID_MAGIC, VALID_HEADER};
use nom::Finish;
use secp256k1::{ffi::types::AlignedType, Secp256k1};

/// Generous: passport2 runs the same call with 20 of these.
const CTX_WORDS: usize = 64;

fn firmware_hash() -> sha256d::Hash {
    sha256d::Hash::from_byte_array([42; 32])
}

/// Every rejection below happens before a key is looked up or a signature is
/// checked, so the context is never actually used — but the entry point still
/// takes one, and building it here is what keeps this test honest about the
/// no-default-features configuration.
macro_rules! with_secp {
    (|$secp:ident| $body:block) => {{
        let mut buf = [AlignedType::ZERO; CTX_WORDS];
        let $secp = Secp256k1::preallocated_new(&mut buf)
            .expect("pre-allocated context buffer should be large enough");
        $body
    }};
}

#[test]
fn an_out_of_range_first_key_index_is_an_invalid_header() {
    with_secp!(|secp| {
        for index in [MAX_PUBLIC_KEYS, u32::MAX] {
            let (_, mut hdr) = header(VALID_HEADER).finish().unwrap();
            hdr.signature.public_key1 = index;

            let result = verify_signature(&secp, &hdr, &firmware_hash(), None);
            assert!(
                matches!(
                    result,
                    Err(VerifySignatureError::InvalidHeader(
                        VerifyHeaderError::InvalidPublicKey1Index(reported)
                    )) if reported == index
                ),
                "index {index} gave {result:?}"
            );
        }
    });
}

#[test]
fn an_out_of_range_second_key_index_is_an_invalid_header() {
    with_secp!(|secp| {
        for index in [MAX_PUBLIC_KEYS, u32::MAX] {
            let (_, mut hdr) = header(VALID_HEADER).finish().unwrap();
            hdr.signature.public_key1 = 0;
            hdr.signature.public_key2 = index;

            let result = verify_signature(&secp, &hdr, &firmware_hash(), None);
            assert!(
                matches!(
                    result,
                    Err(VerifySignatureError::InvalidHeader(
                        VerifyHeaderError::InvalidPublicKey2Index(reported)
                    )) if reported == index
                ),
                "index {index} gave {result:?}"
            );
        }
    });
}

#[test]
fn an_unknown_magic_is_an_invalid_header() {
    with_secp!(|secp| {
        let (_, hdr) = header(INVALID_MAGIC).finish().unwrap();
        let magic = hdr.information.magic;

        let result = verify_signature(&secp, &hdr, &firmware_hash(), None);
        assert!(
            matches!(
                result,
                Err(VerifySignatureError::InvalidHeader(
                    VerifyHeaderError::UnknownMagic(reported)
                )) if reported == magic
            ),
            "got {result:?}"
        );
    });
}

#[test]
fn a_header_the_caller_never_verified_does_not_panic() {
    // The point of the change: this call used to assert!(header.verify().is_ok()).
    with_secp!(|secp| {
        let (_, mut hdr) = header(VALID_HEADER).finish().unwrap();
        hdr.signature.public_key1 = u32::MAX;
        hdr.signature.public_key2 = u32::MAX;

        assert!(matches!(
            verify_signature(&secp, &hdr, &firmware_hash(), None),
            Err(VerifySignatureError::InvalidHeader(_))
        ));
    });
}
