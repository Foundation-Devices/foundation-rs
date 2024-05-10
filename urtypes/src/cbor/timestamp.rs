// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use minicbor::{
    data::{IanaTag, Int, Tag, Type},
    decode::Error,
    encode::Write,
    Decode, Decoder, Encode, Encoder,
};

/// Epoch-Based Date/Time.
///
/// See [RFC 8948](https://www.rfc-editor.org/rfc/rfc8949.html#section-3.4.2).
#[derive(Debug)]
pub enum Timestamp {
    /// Integer timestamp.
    Int(Int),
    /// Floating point timestamp.
    Float(f64),
}

#[rustfmt::skip]
impl<'b, C> Decode<'b, C> for Timestamp {
    fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, Error> {
        if d.tag()? != Tag::from(IanaTag::Timestamp) {
            return Err(Error::message("invalid timestamp tag"));
        }

        #[rustfmt::skip]
        let timestamp = match d.datatype()? {
            Type::U8 | Type::U16 | Type::U32 | Type::U64 |
            Type::I8 | Type::I16 | Type::I32 | Type::I64 |
            Type::Int => Timestamp::Int(d.int()?),
            Type::F16 | Type::F32 | Type::F64 => Timestamp::Float(d.f64()?),
            _ => return Err(Error::message("invalid timestamp")),
        };

        Ok(timestamp)
    }
}

impl<C> Encode<C> for Timestamp {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.tag(IanaTag::Timestamp)?;

        match self {
            Timestamp::Int(x) => e.int(*x)?,
            Timestamp::Float(x) => e.f64(*x)?,
        };

        Ok(())
    }
}
