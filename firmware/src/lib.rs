// SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// SPDX-FileCopyrightText: 2018 Coinkite, Inc. <coldcardwallet.com>
// SPDX-License-Identifier: GPL-3.0-only

//! Firmware images verification.

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]

use bitcoin_hashes::{sha256d, Hash};
use heapless::{String, Vec};
use nom::IResult;
use secp256k1::{ecdsa, Message, PublicKey, Secp256k1, Verification};

/// Length of the header, in bytes.
pub const HEADER_LEN: u32 = 2048;

/// Length of the firmware date in bytes.
pub const DATE_LEN: usize = 14;

/// Length of the firmware version, in bytes.
pub const VERSION_LEN: usize = 8;

/// Maximum length of the firmware, in bytes.
pub const MAX_LEN: u32 = (1792 * 1024) - 256;

/// Magic value to indicate that the index in the public key is indicating
/// a self signed firmware.
pub const USER_KEY: u32 = 255;

/// See [`foundation_public_keys`] for information.
const FOUNDATION_PUBLIC_KEYS: [[u8; 65]; 4] = [
    // Key: 00-pub.bin
    [
        0x04, 0xdd, 0x60, 0x31, 0xc6, 0x40, 0x98, 0x99, 0xcf, 0x7f, 0x7b, 0xc3, 0x47, 0x96, 0xac,
        0x92, 0xe4, 0x44, 0x36, 0x59, 0x53, 0x49, 0x9b, 0x94, 0x36, 0xfc, 0x94, 0x40, 0x59, 0xc4,
        0x9b, 0x0e, 0x6a, 0x45, 0x91, 0x29, 0x8c, 0xa8, 0x36, 0x7e, 0x3a, 0x14, 0xe5, 0x13, 0x72,
        0xb2, 0x74, 0xf3, 0xe8, 0x07, 0x1b, 0x21, 0xfd, 0x3d, 0xed, 0xd7, 0xa2, 0xe2, 0x7b, 0xe8,
        0x94, 0x4c, 0x02, 0x7e, 0x01,
    ],
    // Key: 01-pub.bin
    [
        0x04, 0xc6, 0xcd, 0xf9, 0xf6, 0x35, 0x31, 0xe7, 0x67, 0x5b, 0x55, 0x35, 0x9e, 0xb7, 0xe5,
        0xca, 0x1f, 0xb9, 0x84, 0x76, 0x54, 0x02, 0xc4, 0xac, 0xb1, 0x53, 0x5e, 0xcb, 0x5b, 0xd9,
        0xd7, 0xb5, 0x8e, 0x81, 0xe1, 0x51, 0xa6, 0xc5, 0xbe, 0x87, 0x94, 0xa9, 0x9c, 0x6f, 0x82,
        0xb0, 0xe3, 0xb4, 0x53, 0x04, 0xf0, 0xa0, 0x48, 0x7b, 0xb2, 0x2a, 0xe2, 0x1d, 0x26, 0xfa,
        0xb7, 0x18, 0xb9, 0x32, 0xf9,
    ],
    // Key: 02-pub.bin
    [
        0x04, 0xea, 0xe2, 0xa4, 0xf7, 0x90, 0x3f, 0xc7, 0xa6, 0x02, 0x58, 0x1f, 0x16, 0x36, 0x49,
        0xba, 0xbb, 0x72, 0xf4, 0xd3, 0x58, 0x8a, 0x2a, 0xd0, 0x34, 0xae, 0x63, 0xbd, 0x18, 0x9e,
        0xb0, 0x9c, 0xe9, 0x19, 0xce, 0x27, 0xc1, 0x40, 0x15, 0x91, 0xbc, 0x56, 0x64, 0xf5, 0x8d,
        0x70, 0xb1, 0x38, 0x28, 0x77, 0x50, 0x80, 0xb1, 0x3d, 0x0f, 0x93, 0xe6, 0xc8, 0xa9, 0x83,
        0xe8, 0x70, 0xc2, 0xbe, 0xad,
    ],
    // Key: 03-pub.bin
    [
        0x04, 0xca, 0x32, 0xae, 0xb0, 0xf2, 0x25, 0x7f, 0xa2, 0x0c, 0xac, 0x3a, 0x56, 0xa5, 0x8b,
        0x97, 0xde, 0x99, 0x30, 0xef, 0x14, 0xfd, 0xd6, 0x90, 0x5d, 0x6d, 0x6e, 0x40, 0xb8, 0x30,
        0x98, 0xc1, 0x3e, 0x99, 0x77, 0x25, 0xdb, 0x1c, 0xbe, 0x4d, 0x9b, 0x1b, 0x8a, 0x54, 0x63,
        0x0e, 0x89, 0x4b, 0x3e, 0x23, 0x52, 0x2e, 0x5e, 0x14, 0xf3, 0x7e, 0xbb, 0x3e, 0xd9, 0xae,
        0x6e, 0xda, 0xa1, 0xba, 0xcd,
    ],
];

/// Maximum index in the [`Signature::public_key1`] and
/// [`Signature::public_key2`] fields if it isn't an user key ([`USER_KEY`]).
pub const MAX_PUBLIC_KEYS: u32 = FOUNDATION_PUBLIC_KEYS.len() as u32;

/// The header of the firmware.
#[derive(Debug)]
pub struct Header {
    /// Firmware information.
    pub information: Information,
    /// Signatures data.
    pub signature: Signature,
}

impl Header {
    /// Verify that the header is well-formed.
    pub fn verify(&self) -> Result<(), VerifyHeaderError> {
        match self.information.magic {
            Information::MAGIC_MONO | Information::MAGIC_COLOR => (),
            _ => return Err(VerifyHeaderError::UnknownMagic(self.information.magic)),
        };

        if self.information.timestamp == 0 {
            return Err(VerifyHeaderError::InvalidTimestamp);
        }

        if self.information.length < HEADER_LEN {
            return Err(VerifyHeaderError::FirmwareTooSmall(self.information.length));
        }

        if self.information.length > MAX_LEN {
            return Err(VerifyHeaderError::FirmwareTooBig(self.information.length));
        }

        if !self.is_signed_by_user() {
            if self.signature.public_key1 > MAX_PUBLIC_KEYS {
                return Err(VerifyHeaderError::InvalidPublicKey1Index(
                    self.signature.public_key1,
                ));
            }

            if self.signature.public_key2 > MAX_PUBLIC_KEYS {
                return Err(VerifyHeaderError::InvalidPublicKey2Index(
                    self.signature.public_key2,
                ));
            }

            if self.signature.public_key1 == self.signature.public_key2 {
                return Err(VerifyHeaderError::SamePublicKeys(
                    self.signature.public_key1,
                ));
            }
        }

        Ok(())
    }

    /// Returns `true` if the firmware was signed by the user and not a
    /// Foundation approved key.
    ///
    /// # See also
    ///
    /// - [`foundation_public_keys`].
    pub fn is_signed_by_user(&self) -> bool {
        self.signature.public_key1 == USER_KEY
    }
}

/// Firmware information.
#[derive(Debug)]
pub struct Information {
    /// Magic bytes value.
    pub magic: u32,
    /// The time stamp of the firmware.
    pub timestamp: u32,
    /// The date of the firmware as a string.
    pub date: String<DATE_LEN>,
    /// Version of the firmware as a string.
    pub version: String<VERSION_LEN>,
    /// The length of the firmware, in bytes.
    pub length: u32,
}

impl Information {
    /// Magic constant for mono devices.
    pub const MAGIC_MONO: u32 = 0x50415353;
    /// Magic constant for color devices.
    pub const MAGIC_COLOR: u32 = 0x53534150;
    /// The size of this structure when serialized, in bytes.
    pub const LEN: usize = (4 * 2) + DATE_LEN + VERSION_LEN + 4;

    /// Serialize the structure.
    pub fn serialize(&self) -> [u8; Self::LEN] {
        let mut off = 0;
        let mut buf = [0; Self::LEN];

        buf[off..off + 4].copy_from_slice(&self.magic.to_le_bytes());
        off += 4;

        buf[off..off + 4].copy_from_slice(&self.timestamp.to_le_bytes());
        off += 4;

        buf[off..off + self.date.len()].copy_from_slice(self.date.as_bytes());
        off += self.date.len();

        // Fill with zeroes the rest of the date.
        buf[off..off + (DATE_LEN - self.date.len())].fill(0);
        off += DATE_LEN - self.date.len();

        buf[off..off + self.version.len()].copy_from_slice(&self.version.as_bytes());
        off += self.version.len();

        // Fill with zeroes the rest of the version.
        buf[off..off + (VERSION_LEN - self.version.len())].fill(0);
        off += VERSION_LEN - self.version.len();

        buf[off..off + 4].copy_from_slice(&self.length.to_le_bytes());

        buf
    }
}

/// Firmware signature information.
///
/// The public key indexes are indexes of the [`foundation_public_keys`]
/// array.
#[derive(Debug)]
pub struct Signature {
    /// The first public key index.
    pub public_key1: u32,
    /// The signature of the firmware associated with the first public key.
    pub signature1: ecdsa::Signature,
    /// The second public key index.
    pub public_key2: u32,
    /// The signature of the firmware associated with the second public key.
    pub signature2: ecdsa::Signature,
}

impl Signature {
    /// Return the first public key.
    ///
    /// # Panics
    ///
    /// This function can panic if `public_key1` is out of range.  The header
    /// should have been verified before with [`Header::verify`].
    pub fn public_key1(&self) -> PublicKey {
        let public_keys = foundation_public_keys();
        public_keys[usize::try_from(self.public_key1).unwrap()]
    }

    /// Return the second public key.
    ///
    /// # Panics
    ///
    /// This function can panic if `public_key2` is out of range.  The header
    /// should have been verified before with [`Header::verify`].
    pub fn public_key2(&self) -> PublicKey {
        let public_keys = foundation_public_keys();
        public_keys[usize::try_from(self.public_key2).unwrap()]
    }
}

/// Errors that can happen when verifying the firmware header.
#[derive(Debug)]
pub enum VerifyHeaderError {
    /// Unknown magic bytes.
    UnknownMagic(u32),
    /// The time stamp is invalid.
    InvalidTimestamp,
    /// The reported firmware image length is too small.
    FirmwareTooSmall(u32),
    /// The reported firmware image length is too big.
    FirmwareTooBig(u32),
    /// The first public key index is invalid.
    InvalidPublicKey1Index(u32),
    /// The second public key index is invalid.
    InvalidPublicKey2Index(u32),
    /// The firmware was signed with the same key for both signatures.
    SamePublicKeys(u32),
}

impl core::fmt::Display for VerifyHeaderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VerifyHeaderError::UnknownMagic(magic) => {
                write!(f, "invalid magic bytes: {magic:#08X}")
            }
            VerifyHeaderError::InvalidTimestamp => write!(f, "invalid timestamp"),
            VerifyHeaderError::FirmwareTooSmall(size) => {
                write!(f, "firmware is too small: {size} bytes")
            }
            VerifyHeaderError::FirmwareTooBig(size) => {
                write!(f, "firmware is too big: {size} bytes")
            }
            VerifyHeaderError::InvalidPublicKey1Index(index) => {
                write!(f, "public key 1 index is out of range: {index}")
            }
            VerifyHeaderError::InvalidPublicKey2Index(index) => {
                write!(f, "public key 2 index is out of range: {index}")
            }
            VerifyHeaderError::SamePublicKeys(index) => write!(
                f,
                "the same public key ({index}) was used to sign the firmware."
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for VerifyHeaderError {}

/// Parse the firmware's [`Header`].
pub fn header(i: &[u8]) -> IResult<&[u8], Header> {
    nom::combinator::map(
        nom::sequence::tuple((information, signature)),
        |(information, signature)| Header {
            information,
            signature,
        },
    )(i)
}

fn information(i: &[u8]) -> IResult<&[u8], Information> {
    nom::combinator::map(
        nom::sequence::tuple((
            nom::number::complete::le_u32,
            nom::number::complete::le_u32,
            string::<_, DATE_LEN>,
            string::<_, VERSION_LEN>,
            nom::number::complete::le_u32,
        )),
        |(magic, timestamp, date, version, length)| Information {
            magic,
            timestamp,
            date,
            version,
            length,
        },
    )(i)
}

fn signature(i: &[u8]) -> IResult<&[u8], Signature> {
    nom::combinator::map(
        nom::sequence::tuple((
            nom::number::complete::le_u32,
            compact_signature,
            nom::number::complete::le_u32,
            compact_signature,
        )),
        |(public_key1, signature1, public_key2, signature2)| Signature {
            public_key1,
            signature1,
            public_key2,
            signature2,
        },
    )(i)
}

fn compact_signature<'a, E>(i: &'a [u8]) -> IResult<&'a [u8], ecdsa::Signature, E>
where
    E: nom::error::ParseError<&'a [u8]> + nom::error::FromExternalError<&'a [u8], secp256k1::Error>,
{
    let start_input = i;
    let mut buf = [0; 64];
    let (i, ()) = nom::multi::fill(nom::number::complete::u8, &mut buf)(i)?;
    ecdsa::Signature::from_compact(&buf)
        .map(|v| (i, v))
        .map_err(|e| {
            nom::Err::Failure(E::from_external_error(
                start_input,
                nom::error::ErrorKind::Fail,
                e,
            ))
        })
}

fn string<'a, E, const N: usize>(i: &'a [u8]) -> IResult<&'a [u8], String<N>, E>
where
    E: nom::error::ParseError<&'a [u8]>
        + nom::error::FromExternalError<&'a [u8], core::str::Utf8Error>,
{
    let start_input = i;
    let mut buf: Vec<u8, N> = Vec::new();
    buf.resize(N, 0).unwrap();
    let (i, ()) = nom::multi::fill(nom::number::complete::u8, &mut buf)(i)?;

    // Basically strlen.
    let len = buf
        .iter()
        .enumerate()
        .find_map(|(i, &b)| if b == b'\0' { Some(i) } else { None });

    // Return error if the length is unknown.
    match len {
        Some(len) => buf.truncate(len),
        None => {
            return Err(nom::Err::Failure(E::from_error_kind(
                start_input,
                nom::error::ErrorKind::Fail,
            )))
        }
    }

    String::from_utf8(buf)
        .map_err(|e| {
            nom::Err::Failure(E::from_external_error(
                start_input,
                nom::error::ErrorKind::Fail,
                e,
            ))
        })
        // Not really needed but if our tool only uses ASCII character
        // validate that instead, simplifies the FFI interface as we
        // don't have to handle UTF-8 on the C side of things.
        .and_then(|s| {
            if s.is_ascii() {
                Ok(s)
            } else {
                Err(nom::Err::Failure(E::from_error_kind(
                    start_input,
                    nom::error::ErrorKind::Fail,
                )))
            }
        })
        .map(|v| (i, v))
}

/// Keys that are used in Passport to verify the validity of a firmware, they
/// are in a specific order and map to an index in
pub fn foundation_public_keys() -> [PublicKey; 4] {
    [
        PublicKey::from_slice(&FOUNDATION_PUBLIC_KEYS[0]).expect("public key 0 can't be invalid"),
        PublicKey::from_slice(&FOUNDATION_PUBLIC_KEYS[1]).expect("public key 1 can't be invalid"),
        PublicKey::from_slice(&FOUNDATION_PUBLIC_KEYS[2]).expect("public key 2 can't be invalid"),
        PublicKey::from_slice(&FOUNDATION_PUBLIC_KEYS[3]).expect("public key 3 can't be invalid"),
    ]
}

/// Verifies the signature of the firmware.
pub fn verify_signature<C: Verification>(
    secp: &Secp256k1<C>,
    header: &Header,
    firmware_hash: &sha256d::Hash,
    user_public_key: Option<&PublicKey>,
) -> Result<(), VerifySignatureError> {
    assert!(header.verify().is_ok());

    let message = Message::from_digest(firmware_hash.to_byte_array());

    // Perform the signature verification depending on the mode.
    match (header.is_signed_by_user(), user_public_key) {
        (true, Some(public_key)) => {
            // See below on the normal verificationn as to why.
            let mut signature1 = header.signature.signature1;
            signature1.normalize_s();

            public_key
                .verify(secp, &message, &header.signature.signature1)
                .map_err(|error| VerifySignatureError::InvalidUserSignature {
                    public_key: public_key.clone(),
                    signature: header.signature.signature1.clone(),
                    error,
                })
        }
        (true, None) => Err(VerifySignatureError::MissingUserPublicKey),
        (false, _) => {
            // Normalize the signatures as micro-ecc does not normalize the
            // signatures and libsecp256k1 (rust-secp256k1) does not accept
            // signatures that are not normalized to avoid malleability
            // attacks.
            //
            // This is not a problem for the signatures of the firmware as we
            // do not care if the signature changes itself, only that it is
            // valid.
            let mut signature1 = header.signature.signature1;
            let mut signature2 = header.signature.signature2;
            signature1.normalize_s();
            signature2.normalize_s();

            header
                .signature
                .public_key1()
                .verify(secp, &message, &signature1)
                .map_err(|error| VerifySignatureError::FailedSignature1 {
                    index: header.signature.public_key1,
                    signature: header.signature.signature1,
                    error,
                })?;

            header
                .signature
                .public_key2()
                .verify(secp, &message, &signature2)
                .map_err(|error| VerifySignatureError::FailedSignature2 {
                    index: header.signature.public_key2,
                    signature: header.signature.signature2,
                    error,
                })?;

            Ok(())
        }
    }
}

/// Errors that can happen when verifying the firmware signatures.
#[derive(Debug)]
pub enum VerifySignatureError {
    /// The user signed firmware is not valid.
    InvalidUserSignature {
        /// The public key of the user.
        public_key: PublicKey,
        /// The signature of the firmware.
        signature: ecdsa::Signature,
        /// The signtature verification error.
        error: secp256k1::Error,
    },
    /// The first signature verification failed.
    FailedSignature1 {
        /// The index of the public key used.
        index: u32,
        /// The signature of the firmware.
        signature: ecdsa::Signature,
        /// The signtature verification error.
        error: secp256k1::Error,
    },
    /// The second signature verification failed.
    FailedSignature2 {
        /// The index of the public key used.
        index: u32,
        /// The signature of the firmware.
        signature: ecdsa::Signature,
        /// The signtature verification error.
        error: secp256k1::Error,
    },
    /// The firmware was signed by the user but no user public key was found.
    MissingUserPublicKey,
}

impl core::fmt::Display for VerifySignatureError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VerifySignatureError::InvalidUserSignature { .. } => {
                write!(f, "invalid user signature")
            }
            VerifySignatureError::FailedSignature1 { .. } => write!(f, "first signature failed"),
            VerifySignatureError::FailedSignature2 { .. } => write!(f, "second signature failed"),
            VerifySignatureError::MissingUserPublicKey => {
                write!(f, "firmware is user signed but user public key is missing")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for VerifySignatureError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            VerifySignatureError::InvalidUserSignature { error, .. } => Some(error),
            VerifySignatureError::FailedSignature1 { error, .. } => Some(error),
            VerifySignatureError::FailedSignature2 { error, .. } => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants_consistency() {
        // Originally the date field was designed to hold that string.
        assert_eq!(DATE_LEN, b"Jan. 01, 2021".len() + 1);

        // These are the same.
        assert_eq!(foundation_public_keys().len(), 4);
        assert_eq!(FOUNDATION_PUBLIC_KEYS.len(), 4);
        assert_eq!(MAX_PUBLIC_KEYS, 4);
        assert_eq!(Information::LEN, 34); // Should be equal to sizeof(fw_info_t)
    }

    // Just check that we don't panic.
    #[test]
    fn foundation_keys_to_typed_secp256k1_public_key() {
        foundation_public_keys();
    }
}
