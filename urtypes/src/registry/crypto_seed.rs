// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use minicbor::{Decode, Encode};

use crate::cbor::Timestamp;

/// Cryptographic Seed.
#[doc(alias("crypto-seed"))]
#[derive(Debug, Decode, Encode)]
pub struct CryptoSeed<'a> {
    /// Seed entropy.
    #[cbor(n(0), with = "payload")]
    pub payload: &'a [u8],
    /// Creation date.
    #[cbor(n(1))]
    pub creation_date: Option<Timestamp>,
    /// Short name for the seed.
    #[cbor(n(2))]
    pub name: Option<&'a str>,
    /// Description of the seed.
    #[cbor(n(3))]
    pub note: Option<&'a str>,
}

/// CBOR decoding and encoding of `crypto-seed-digest`.
#[doc(alias("crypto-seed-digest"))]
pub mod digest {
    use minicbor::data::Tag;
    use minicbor::encode::Write;
    use minicbor::{Decoder, Encoder};

    /// Tag representing a `crypto-seed-digest`.
    pub const TAG: Tag = Tag::new(600);

    /// Encode a `crypto-seed-digest`.
    #[doc(alias("crypto-seed-digest"))]
    pub fn encode<C, W: Write>(
        seed_digest: &[u8; 32],
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.tag(TAG)?.bytes(seed_digest)?;
        Ok(())
    }

    /// Decode a `crypto-seed-digest`.
    #[doc(alias("crypto-seed-digest"))]
    pub fn decode<C>(d: &mut Decoder, _ctx: &mut C) -> Result<[u8; 32], minicbor::decode::Error> {
        if d.tag()? != TAG {
            return Err(minicbor::decode::Error::message(
                "invalid crypto-seed-digest tag",
            ));
        };

        let seed_digest = d.bytes()?;
        if seed_digest.len() != 32 {
            return Err(minicbor::decode::Error::message(
                "invalid crypto-seed-digest length",
            ));
        }

        let mut buf = [0u8; 32];
        buf.copy_from_slice(seed_digest);
        Ok(buf)
    }
}

mod payload {
    use minicbor::encode::Write;
    use minicbor::{Decoder, Encoder};

    pub fn encode<C, W: Write>(
        payload: &[u8],
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        if !(1..=64).contains(&payload.len()) {
            return Err(minicbor::encode::Error::message("invalid seed payload"));
        }

        e.bytes(payload)?;

        Ok(())
    }

    pub fn decode<'b, C>(
        d: &mut Decoder<'b>,
        _ctx: &mut C,
    ) -> Result<&'b [u8], minicbor::decode::Error> {
        let payload = d.bytes()?;

        if !(1..=64).contains(&payload.len()) {
            return Err(minicbor::decode::Error::message(
                "invalid crypto-seed-digest length",
            ));
        }

        Ok(payload)
    }
}
