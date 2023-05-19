// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

//! # Supply Chain Validation.
//!
//! ## CDDL for Supply Chain Validation.
//!
//! ```cddl
//! scv-challenge = {
//!     scv-challenge-id: text .size 64,         ; hex encoded string.
//!     scv-challenge-signature: text .size 128, ; hex encoded string.
//! }
//!
//! scv-solution = {
//!     scv-solution-word1: text,
//!     scv-solution-word2: text,
//!     scv-solution-word3: text,
//!     scv-solution-word4: text,
//! }
//!
//! scv-challenge-id = 1
//! scv-challenge-signature = 2
//!
//! scv-solution-word1 = 1
//! scv-solution-word2 = 2
//! scv-solution-word3 = 3
//! scv-solution-word4 = 4
//! ```

use core::str;

use minicbor::data::{Tag, Type};
use minicbor::decode::Error;
use minicbor::encode::Write;
use minicbor::{Decode, Decoder, Encode, Encoder};

/// Supply Chain Validation challenge.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Challenge {
    /// The ID of the challenge.
    pub id: [u8; 32],
    /// The signature of the challenge.
    pub signature: [u8; 64],
}

impl Challenge {
    /// Tag for embedding [`Challenge`] in other types.
    pub const TAG: Tag = Tag::Unassigned(710);
}

impl<'b, C> Decode<'b, C> for Challenge {
    fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, Error> {
        let mut id = None;
        let mut signature = None;

        macro_rules! decode_inner {
            () => {
                match d.u32()? {
                    1 => {
                        let mut buf = [0; 32];
                        hex::decode_to_slice(d.str()?, &mut buf)
                            .map_err(|_| Error::message("invalid hex string (id)"))?;
                        id = Some(buf);
                    }
                    2 => {
                        let mut buf = [0; 64];
                        hex::decode_to_slice(d.str()?, &mut buf)
                            .map_err(|_| Error::message("invalid hex string (signature)"))?;
                        signature = Some(buf);
                    }
                    3 => (),
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
            id: id.ok_or_else(|| Error::message("id is missing"))?,
            signature: signature.ok_or_else(|| Error::message("signature is missing"))?,
        })
    }
}

impl<C> Encode<C> for Challenge {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        let mut id = [0; 64];
        let mut signature = [0; 128];

        // unreachable errors.
        hex::encode_to_slice(self.id, &mut id).unwrap();
        hex::encode_to_slice(self.signature, &mut signature).unwrap();
        let id = str::from_utf8(&id).unwrap();
        let signature = str::from_utf8(&signature).unwrap();

        e.map(2)?;
        e.u8(1)?.str(id)?;
        e.u8(2)?.str(signature)?;

        Ok(())
    }
}

/// Supply Chain Validation solution.
#[derive(Debug, Decode, Clone, Encode, Eq, PartialEq, Hash)]
#[cbor(map)]
pub struct Solution<'a> {
    /// Word 1.
    #[cbor(b(1))]
    pub word1: &'a str,
    /// Word 2.
    #[cbor(b(2))]
    pub word2: &'a str,
    /// Word 3.
    #[cbor(b(3))]
    pub word3: &'a str,
    /// Word 4.
    #[cbor(b(4))]
    pub word4: &'a str,
}

impl<'a> Solution<'a> {
    /// Tag for embedding [`Solution`] in other types.
    pub const TAG: Tag = Tag::Unassigned(711);
}
