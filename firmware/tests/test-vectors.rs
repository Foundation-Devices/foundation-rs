// SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use foundation_firmware::{header, VerifyHeaderError, MAX_PUBLIC_KEYS, USER_KEY};
use foundation_test_vectors::firmware::{
    INVALID_MAGIC, INVALID_MAX_LENGTH, INVALID_MIN_LENGTH, INVALID_PUBLIC_KEY1,
    INVALID_PUBLIC_KEY2, INVALID_TIMESTAMP, VALID_HEADER,
};
use nom::Finish;

#[test]
pub fn valid_header() {
    let (_, header) = header(VALID_HEADER).finish().unwrap();
    header.verify().unwrap();
}

#[test]
pub fn invalid_magic() {
    let (_, header) = header(INVALID_MAGIC).finish().unwrap();
    assert_eq!(header.verify(), Err(VerifyHeaderError::UnknownMagic(0)));
}

#[test]
pub fn invalid_min_length() {
    let (_, header) = header(INVALID_MIN_LENGTH).finish().unwrap();
    assert_eq!(
        header.verify(),
        Err(VerifyHeaderError::FirmwareTooSmall(2047))
    );
}

#[test]
pub fn invalid_max_length() {
    let (_, header) = header(INVALID_MAX_LENGTH).finish().unwrap();
    assert_eq!(
        header.verify(),
        Err(VerifyHeaderError::FirmwareTooBig(1834753))
    );
}

#[test]
pub fn invalid_public_key1() {
    let (_, header) = header(INVALID_PUBLIC_KEY1).finish().unwrap();
    assert_eq!(
        header.verify(),
        Err(VerifyHeaderError::InvalidPublicKey1Index(5))
    );
}

#[test]
pub fn invalid_public_key2() {
    let (_, header) = header(INVALID_PUBLIC_KEY2).finish().unwrap();
    assert_eq!(
        header.verify(),
        Err(VerifyHeaderError::InvalidPublicKey2Index(5))
    );
}

#[test]
pub fn invalid_timestamp() {
    let (_, header) = header(INVALID_TIMESTAMP).finish().unwrap();
    assert_eq!(header.verify(), Err(VerifyHeaderError::InvalidTimestamp));
}

/// The number of bytes `header()` consumes: an `Information` plus two indexed
/// compact signatures.
const PARSED_HEADER_LEN: usize = 34 + (4 + 64) * 2;

#[test]
pub fn public_key_index_at_the_key_count() {
    // There are MAX_PUBLIC_KEYS keys, so that value is one past the last index.
    for index in [MAX_PUBLIC_KEYS, MAX_PUBLIC_KEYS + 1, u32::MAX] {
        let (_, mut header) = header(VALID_HEADER).finish().unwrap();
        header.signature.public_key1 = index;

        assert_eq!(
            header.verify(),
            Err(VerifyHeaderError::InvalidPublicKey1Index(index)),
            "index {index} accepted for public_key1"
        );
        assert_eq!(header.signature.public_key1(), None);
    }
}

#[test]
pub fn second_public_key_index_at_the_key_count() {
    for index in [MAX_PUBLIC_KEYS, MAX_PUBLIC_KEYS + 1, u32::MAX] {
        let (_, mut header) = header(VALID_HEADER).finish().unwrap();
        header.signature.public_key1 = 0;
        header.signature.public_key2 = index;

        assert_eq!(
            header.verify(),
            Err(VerifyHeaderError::InvalidPublicKey2Index(index)),
            "index {index} accepted for public_key2"
        );
        assert_eq!(header.signature.public_key2(), None);
    }
}

#[test]
pub fn every_in_range_index_resolves() {
    let (_, mut header) = header(VALID_HEADER).finish().unwrap();

    for index in 0..MAX_PUBLIC_KEYS {
        header.signature.public_key1 = index;
        header.signature.public_key2 = index;

        assert!(header.signature.public_key1().is_some(), "index {index}");
        assert!(header.signature.public_key2().is_some(), "index {index}");
    }
}

#[test]
pub fn a_user_signed_header_does_not_index_the_foundation_keys() {
    let (_, mut header) = header(VALID_HEADER).finish().unwrap();
    header.signature.public_key1 = USER_KEY;

    // The index checks are skipped for a user signed image, so this stays valid,
    // and the out of range index is never looked up.
    header.verify().unwrap();
    assert!(header.is_signed_by_user());
    assert_eq!(header.signature.public_key1(), None);
}

#[test]
pub fn empty_and_truncated_input_do_not_parse() {
    assert!(header(&[]).finish().is_err());

    for len in 1..PARSED_HEADER_LEN {
        assert!(
            header(&VALID_HEADER[..len]).finish().is_err(),
            "{len} bytes parsed as a header"
        );
    }

    // ... and a whole one still does.
    header(&VALID_HEADER[..PARSED_HEADER_LEN]).finish().unwrap();
}
