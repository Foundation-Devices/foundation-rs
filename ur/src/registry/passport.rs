// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

//! # Passport specific UR types.
//!
//! ## CDDL for Request.
//!
//! ```cddl
//! ; At least one of the fields MUST be specified.
//!
//! passport-request = {
//!     transaction-id: uuid
//!     ? scv-challenge-request: #6.710(scv-challenge),
//!     ? passport-model-request: #6.720(bool) .default false,
//!     ? passport-firmware-version-request: #6.770(bool) .default false,
//! }
//!
//! ; TODO: use fixed numbers.
//! transaction-id = uint
//! scv-challenge-request = uint
//! passport-model-request = uint
//! passport-firmware-version-request = uint
//! ```
//!
//! # CDDL for Response.
//!
//! ```cddl
//! passport-response = {
//!     transaction-id: uuid,
//!     ? scv-solution-response: #6.711(scv-solution),
//!     ? passport-model-response: #6.721(passport-model),
//!     ? passport-firmware-version-response: #6.771(text)
//! }
//!
//! ; TODO: use fixed numbers.
//! transaction-id = uint
//! scv-solution-response = uint
//! passport-model-response = uint
//! passport-firmware-version-response = uint
//!
//! ```

use crate::{
    passport::Model,
    supply_chain_validation::{Challenge, Solution},
};

use minicbor::{
    data::{Tag, Type},
    decode::Error,
    encode::Write,
    Decode, Decoder, Encode, Encoder,
};
use uuid::Uuid;

/// Passport model request tag.
pub const PASSPORT_MODEL_REQUEST_TAG: Tag = Tag::Unassigned(720);
/// Passport firmware version request tag.
pub const PASSPORT_FIRMWARE_VERSION_REQUEST_TAG: Tag = Tag::Unassigned(770);
/// Passport firmware version response tag.
pub const PASSPORT_FIRMWARE_VERSION_RESPONSE_TAG: Tag = Tag::Unassigned(771);

/// Passport custom `crypto-request`.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct PassportRequest {
    /// Transaction identifier.
    pub transaction_id: Uuid,
    /// Supply chain validation challenge.
    pub scv_challenge: Option<Challenge>,
    /// Request Passport model.
    pub passport_model: bool,
    /// Request Passport firmware version.
    pub passport_firmware_version: bool,
}

impl<'b, C> Decode<'b, C> for PassportRequest {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, Error> {
        let mut transaction_id = None;
        let mut scv_challenge = None;
        let mut passport_model = false;
        let mut passport_firmware_version = false;

        macro_rules! decode_inner {
            () => {
                // TODO: ignore index for now.
                //  Decoding is based on the tags. Use indexes once Envoy
                //  sends "stable" indexes.
                d.u32()?;
                match d.probe().tag()? {
                    ur::registry::uuid::TAG => {
                        transaction_id = Some(ur::registry::uuid::decode(d, ctx)?);
                    }
                    Challenge::TAG => {
                        d.tag()?;
                        scv_challenge = Some(Challenge::decode(d, ctx)?);
                    }
                    PASSPORT_MODEL_REQUEST_TAG => {
                        d.tag()?;
                        passport_model = d.bool()?;
                    }
                    PASSPORT_FIRMWARE_VERSION_REQUEST_TAG => {
                        d.tag()?;
                        passport_firmware_version = d.bool()?;
                    }
                    _ => return Err(Error::message("unknown tag")),
                }
            };
        }

        if let Some(len) = d.map()? {
            for _ in 0..len {
                decode_inner!();
            }
        } else {
            while d.datatype()? != Type::Break {
                decode_inner!();
            }
        }

        Ok(Self {
            transaction_id: transaction_id
                .ok_or_else(|| Error::message("transaction-id missing"))?,
            scv_challenge,
            passport_model,
            passport_firmware_version,
        })
    }
}

impl<C> Encode<C> for PassportRequest {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        let len = 1
            + self.scv_challenge.is_some() as u64
            + self.passport_model as u64
            + self.passport_firmware_version as u64;
        e.map(len)?;

        e.u8(1)?;
        ur::registry::uuid::encode(&self.transaction_id, e, ctx)?;

        if let Some(ref scv_challenge) = self.scv_challenge {
            e.u8(2)?.tag(Challenge::TAG)?;
            scv_challenge.encode(e, ctx)?;
        }

        if self.passport_model {
            e.u8(3)?
                .tag(PASSPORT_MODEL_REQUEST_TAG)?
                .bool(self.passport_model)?;
        }

        if self.passport_firmware_version {
            e.u8(4)?
                .tag(PASSPORT_FIRMWARE_VERSION_REQUEST_TAG)?
                .bool(self.passport_firmware_version)?;
        }

        Ok(())
    }
}

/// Passport custom `crypto-request`.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct PassportResponse<'a> {
    /// Transaction identifier.
    pub transaction_id: Uuid,
    /// Solution to the supply validation challenge.
    pub scv_solution: Option<Solution<'a>>,
    /// Passport model
    pub passport_model: Option<Model>,
    /// Passport firmware version.
    pub passport_firmware_version: Option<&'a str>,
}

impl<'b, C> Decode<'b, C> for PassportResponse<'b> {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, Error> {
        let mut transaction_id = None;
        let mut scv_solution = None;
        let mut passport_model = None;
        let mut passport_firmware_version = None;

        macro_rules! decode_inner {
            () => {
                // TODO: ignore index for now.
                //  Decoding is based on the tags. Use indexes once Envoy
                //  sends "stable" indexes.
                d.u32()?;
                match d.probe().tag()? {
                    ur::registry::uuid::TAG => {
                        transaction_id = Some(ur::registry::uuid::decode(d, ctx)?);
                    }
                    Solution::TAG => {
                        d.tag()?;
                        scv_solution = Some(Solution::decode(d, ctx)?);
                    }
                    Model::TAG => {
                        d.tag()?;
                        passport_model = Some(Model::decode(d, ctx)?);
                    }
                    PASSPORT_FIRMWARE_VERSION_RESPONSE_TAG => {
                        d.tag()?;
                        passport_firmware_version = Some(d.str()?);
                    }
                    _ => return Err(Error::message("unknown map entry")),
                }
            };
        }

        if let Some(len) = d.map()? {
            for _ in 0..len {
                decode_inner!();
            }
        } else {
            while d.datatype()? != Type::Break {
                decode_inner!();
            }
        }

        Ok(Self {
            transaction_id: transaction_id
                .ok_or_else(|| Error::message("transaction-id is not present"))?,
            scv_solution,
            passport_model,
            passport_firmware_version,
        })
    }
}

impl<'a, C> Encode<C> for PassportResponse<'a> {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        let len = 1
            + self.scv_solution.is_some() as u64
            + self.passport_model.is_some() as u64
            + self.passport_firmware_version.is_some() as u64;

        e.map(len)?;

        e.u8(1)?;
        ur::registry::uuid::encode(&self.transaction_id, e, ctx)?;

        if let Some(ref scv_solution) = self.scv_solution {
            e.u8(2)?.tag(Solution::TAG)?;
            scv_solution.encode(e, ctx)?;
        }

        if let Some(ref passport_model) = self.passport_model {
            e.u8(3)?.tag(Model::TAG)?;
            passport_model.encode(e, ctx)?;
        }

        if let Some(passport_firmware_version) = self.passport_firmware_version {
            e.u8(4)?
                .tag(PASSPORT_FIRMWARE_VERSION_RESPONSE_TAG)?
                .str(passport_firmware_version)?;
        }

        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_passport_request() {
        let mut id = [0; 32];
        let mut signature = [0; 64];

        hex::decode_to_slice(
            "2e99758548972a8e8822ad47fa1017ff72f06f3ff6a016851f45c398732bc50c",
            &mut id,
        )
        .unwrap();
        hex::decode_to_slice("7d0a8468ed220400c0b8e6f335baa7e070ce880a37e2ac5995b9a97b809026de626da636ac7365249bb974c719edf543b52ed286646f437dc7f810cc2068375c", &mut signature).unwrap();

        let request = PassportRequest {
            transaction_id: Default::default(),
            scv_challenge: Some(Challenge { id, signature }),
            passport_model: true,
            passport_firmware_version: true,
        };

        let encoded = &minicbor::to_vec(&request).unwrap();
        let decoded: PassportRequest = minicbor::decode(&encoded).unwrap();

        assert_eq!(decoded, request);
    }

    #[test]
    fn test_roundtrip_passport_response() {
        let mut id = [0; 32];
        let mut signature = [0; 64];

        hex::decode_to_slice(
            "2e99758548972a8e8822ad47fa1017ff72f06f3ff6a016851f45c398732bc50c",
            &mut id,
        )
        .unwrap();
        hex::decode_to_slice("7d0a8468ed220400c0b8e6f335baa7e070ce880a37e2ac5995b9a97b809026de626da636ac7365249bb974c719edf543b52ed286646f437dc7f810cc2068375c", &mut signature).unwrap();

        let response = PassportResponse {
            transaction_id: Default::default(),
            scv_solution: Some(Solution {
                word1: "abandon",
                word2: "ability",
                word3: "able",
                word4: "about",
            }),
            passport_model: Some(Model::Batch2),
            passport_firmware_version: Some("2.0.5"),
        };

        let encoded = &minicbor::to_vec(&response).unwrap();
        let decoded: PassportResponse = minicbor::decode(&encoded).unwrap();

        assert_eq!(decoded, response);
    }

    #[test]
    fn test_request_decode() {
        const TEST_VECTOR: &str = "a201d8255083816f6064ff4046b93a85687f8f608202d902c6a30178403338633663303561633639613166623737626366333736333330383835326364336530383066653165343630346361613831623534383236653264613062643202788037393035306564663562386636343937663936626661633031333363396365663561303764613363343835613432373466646666396433616637346632393833636566386432303337663164626636613435356431356530666236346162313665333664643336353062363533323265333239303138313639633631356636610378603045022079050ec39f5bc28f64c297c3b96bc3bac380133cc29cc3af5a07c39a3c485a4274c3bdc3bfc29d3ac3b74f29c283022100c38ec3b8c392037f1dc2bf6a455d15c3a0c3bb64c2ab16c3a36dc393650b65322e32c2901816c29c615f6a";
        let cbor = hex::decode(TEST_VECTOR).unwrap();
        let decoded: PassportRequest = minicbor::decode(&cbor).unwrap();
    }
}
