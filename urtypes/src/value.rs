// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

//! An Uniform Resource value.
//!
//! The [`Value`] type aggregates every known UR type (by this crate) into a
//! single enumeration variant containing those.
//!
//! This can be used to parse a Uniform Resource by checking on the UR type
//! and then calling the corresponding decoder.
//!
//! # Example
//!
//! Parsing a UR:
//!
//! ```rust
//! // As a UR: ur:bytes/gdaebycpeofygoiyktlonlpkrksfutwyzmwmfyeozs
//! use foundation_urtypes::value::Value;
//! const PAYLOAD: &[u8] = &[
//!     0x50, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
//!     0xEE, 0xFF,
//! ];
//! const UR_TYPE: &str = "bytes";
//!
//! let value = Value::from_ur(UR_TYPE, PAYLOAD).unwrap();
//! println!("{:?}", value);
//! ```

use core::fmt::{Display, Formatter};

use minicbor::{bytes::ByteSlice, encode::Write, Encode, Encoder};

use crate::registry::{HDKey, PassportRequest, PassportResponse};

#[derive(Debug, PartialEq)]
pub enum Value<'a> {
    /// bytes.
    Bytes(&'a [u8]),
    /// crypto-hdkey.
    HDKey(HDKey<'a>),
    /// crypto-psbt.
    Psbt(&'a [u8]),
    /// crypto-request for Passport.
    PassportRequest(PassportRequest),
    /// crypto-response for Passport.
    PassportResponse(PassportResponse<'a>),
}

impl<'a> Value<'a> {
    /// Construct a new [`Value`] from the type and the CBOR payload.
    pub fn from_ur(ur_type: &str, payload: &'a [u8]) -> Result<Self, Error> {
        let value = match ur_type {
            "bytes" => Self::Bytes(minicbor::decode::<&ByteSlice>(payload)?),
            "hdkey" | "crypto-hdkey" => Self::HDKey(minicbor::decode(payload)?),
            "psbt" | "crypto-psbt" => Self::Psbt(minicbor::decode::<&ByteSlice>(payload)?),
            // TODO: Remove crypto-request and crypto-response, these have
            // been removed from the UR registry standard (BCR-2020-006).
            "x-passport-request" | "crypto-request" => {
                Self::PassportRequest(minicbor::decode(payload)?)
            }
            "x-passport-response" | "crypto-response" => {
                Self::PassportResponse(minicbor::decode(payload)?)
            }
            _ => return Err(Error::UnsupportedResource),
        };

        Ok(value)
    }

    /// Return the type of this value as a string.
    ///
    /// # Notes
    ///
    /// This will return the _deprecated_ types as some implementers of UR
    /// still don't support the newer ones.
    ///
    /// When changing this to use the newer types also change
    /// [`Value::from_ur`].
    pub fn ur_type(&self) -> &'static str {
        match self {
            Value::Bytes(_) => "bytes",
            Value::HDKey(_) => "crypto-hdkey",
            Value::Psbt(_) => "crypto-psbt",
            Value::PassportRequest(_) => "crypto-request",
            Value::PassportResponse(_) => "crypto-response",
        }
    }
}

impl<'a, C> Encode<C> for Value<'a> {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            Value::Bytes(v) => minicbor::bytes::encode(v, e, ctx),
            Value::HDKey(v) => v.encode(e, ctx),
            Value::Psbt(v) => minicbor::bytes::encode(v, e, ctx),
            Value::PassportRequest(v) => v.encode(e, ctx),
            Value::PassportResponse(v) => v.encode(e, ctx),
        }
    }
}

/// Errors that can occur when parsing a value.
#[derive(Debug)]
pub enum Error {
    /// Unsupported Uniform Resource type.
    UnsupportedResource,
    /// Failed to decode CBOR payload.
    InvalidCbor(minicbor::decode::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedResource => write!(f, "unsupported Uniform Resource type"),
            Self::InvalidCbor(_) => write!(f, "failed to decode CBOR payload"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidCbor(e) => Some(e),
            _ => None,
        }
    }
}

impl From<minicbor::decode::Error> for Error {
    fn from(error: minicbor::decode::Error) -> Self {
        Self::InvalidCbor(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_string_bytes() {
        const BYTES_PAYLOAD: &[u8] = &[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        const CBOR_PAYLOAD: &[u8] = &[
            0x50, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
            0xDD, 0xEE, 0xFF,
        ];

        let value = Value::from_ur("bytes", CBOR_PAYLOAD).unwrap();
        assert_eq!(value, Value::Bytes(BYTES_PAYLOAD));

        let cbor = minicbor::to_vec(&value).unwrap();
        assert_eq!(cbor, CBOR_PAYLOAD);
    }
}
