// SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use core::ops::RangeFrom;

use nom::error::ErrorKind;
use nom::error::FromExternalError;
use nom::error::ParseError;
use nom::multi::fill;
use nom::number::complete::u8;
use nom::Err;
use nom::IResult;
use nom::InputIter;
use nom::InputLength;
use nom::Slice;

use secp256k1::{schnorr, XOnlyPublicKey};

pub fn x_only_public_key<Input, Error>(i: Input) -> IResult<Input, XOnlyPublicKey, Error>
where
    Input: PartialEq + Clone + Slice<RangeFrom<usize>> + InputIter<Item = u8> + InputLength,
    Error: ParseError<Input> + FromExternalError<Input, secp256k1::Error>,
{
    let mut buf = [0; 32];

    let (next_i, ()) = fill(u8, &mut buf)(i.clone())?;
    let p = XOnlyPublicKey::from_slice(&buf)
        .map_err(|e| Err::Failure(Error::from_external_error(i, ErrorKind::Fail, e)))?;

    Ok((next_i, p))
}

pub fn schnorr_signature<Input, Error>(i: Input) -> IResult<Input, schnorr::Signature, Error>
where
    Input: PartialEq + Clone + Slice<RangeFrom<usize>> + InputIter<Item = u8> + InputLength,
    Error: ParseError<Input> + FromExternalError<Input, secp256k1::Error>,
{
    let mut buf = [0; 64];

    let (next_i, ()) = fill(u8, &mut buf)(i.clone())?;
    let s = schnorr::Signature::from_slice(&buf)
        .map_err(|e| Err::Failure(Error::from_external_error(i, ErrorKind::Fail, e)))?;

    Ok((next_i, s))
}
