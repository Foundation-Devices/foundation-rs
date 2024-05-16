// SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use foundation_firmware::{header, VerifyHeaderError};
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
