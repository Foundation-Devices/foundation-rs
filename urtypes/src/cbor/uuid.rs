// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Encoding and decoding of [`Uuid`] types.
//!
//! # Examples
//!
//! Usage with [`minicbor`]:
//!
//! ```
//! use minicbor::{Decode, Encode};
//! use uuid::Uuid;
//!
//! #[derive(Decode, Encode)]
//! pub struct MyStructure {
//!     #[cbor(n(0), with = "foundation_urtypes::cbor::uuid")]
//!     pub id: Uuid,
//! }
//! ```

use minicbor::{data::Tag, decode::Error, encode::Write, Decoder, Encoder};

use uuid::Uuid;

/// Tag representing of [`Uuid`].
pub const TAG: Tag = Tag::Unassigned(37);

/// Encode an [`Uuid`].
pub fn encode<C, W: Write>(
    uuid: &Uuid,
    e: &mut Encoder<W>,
    _ctx: &mut C,
) -> Result<(), minicbor::encode::Error<W::Error>> {
    e.tag(TAG)?.bytes(uuid.as_bytes())?;
    Ok(())
}

/// Decode an [`Uuid`].
pub fn decode<C>(d: &mut Decoder, _ctx: &mut C) -> Result<Uuid, Error> {
    if d.tag()? != TAG {
        return Err(Error::message("invalid UUID tag"));
    };

    let uuid = d.bytes()?;
    if uuid.len() != 16 {
        return Err(Error::message("invalid UUID size"));
    }

    let mut buf = [0u8; 16];
    buf.copy_from_slice(uuid);
    Ok(Uuid::from_bytes(buf))
}
