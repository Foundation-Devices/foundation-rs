// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

//! ## CDDL for Passport Model
//!
//! ```cddl
//! passport-model = uint .size 4 .ne 0
//! passport-model-founders-edition = 1
//! passport-model-batch2 = 2
//! ```

use minicbor::data::Tag;
use minicbor::decode::Error;
use minicbor::encode::Write;
use minicbor::{Decode, Decoder, Encode, Encoder};

/// Passport model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Model {
    /// Founders Edition.
    FoundersEdition,
    /// Batch 2.
    Batch2,
}

impl Model {
    /// Tag for embedding [`Model`] in other types.
    pub const TAG: Tag = Tag::Unassigned(721);
}

impl<'b, C> Decode<'b, C> for Model {
    fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, Error> {
        Model::try_from(d.u32()?).map_err(|_| Error::message("invalid passport-model"))
    }
}

impl<C> Encode<C> for Model {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.u32((*self).into())?;
        Ok(())
    }
}

impl TryFrom<u32> for Model {
    type Error = InvalidModelError;

    fn try_from(number: u32) -> Result<Self, Self::Error> {
        match number {
            1 => Ok(Model::FoundersEdition),
            2 => Ok(Model::Batch2),
            _ => Err(InvalidModelError { number }),
        }
    }
}

impl From<Model> for u32 {
    fn from(model: Model) -> Self {
        match model {
            Model::FoundersEdition => 1,
            Model::Batch2 => 2,
        }
    }
}

/// Invalid Passport model error.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct InvalidModelError {
    /// Erroneous model number.
    pub number: u32,
}
