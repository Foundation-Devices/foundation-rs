// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Parser for raw bitcoin transactions.
//!
//! FIXME: Currently the encoder could be optimized to take advantage of the
//! fact that we store the inputs and outputs as is in memory, e.g. we only
//! deserialize on demand, so for example, to serialize the transaction again
//! we could just write the values as is back.
//!
//! This is not possible as we only store the start of the inputs and outputs
//! and not the end.  We would need to first slice it correctly to do that and
//! is a bit complex.
//!
//! Can be an interesting optimization approach once this code is in prod.

use core::num::TryFromIntError;

use nom::{
    combinator::{map, map_res},
    error::{ErrorKind, FromExternalError, ParseError},
    multi::length_data,
    number::complete::{le_i32, le_i64, le_u32},
    sequence::tuple,
    Compare, Err, IResult, InputIter, InputLength, InputTake, Slice,
};

use crate::parser::compact_size::compact_size;
use crate::parser::hash::txid;
use crate::transaction::{Input, Inputs, Output, OutputPoint, Outputs, Transaction};

/// Parses a raw bitcoin transaction.
pub fn transaction<I, E>(i: I) -> IResult<I, Transaction<I>, E>
where
    I: for<'a> Compare<&'a [u8]>
        + Clone
        + PartialEq
        + InputLength
        + InputIter<Item = u8>
        + Slice<core::ops::RangeFrom<usize>>
        + InputTake,
    E: ParseError<I> + FromExternalError<I, TryFromIntError>,
{
    map(
        tuple((le_i32, inputs, outputs, le_u32)),
        |(version, inputs, outputs, lock_time)| Transaction {
            version,
            inputs,
            outputs,
            lock_time,
        },
    )(i)
}

pub fn inputs<I, E>(i: I) -> IResult<I, Inputs<I>, E>
where
    I: for<'a> Compare<&'a [u8]>
        + Clone
        + PartialEq
        + InputLength
        + InputIter<Item = u8>
        + Slice<core::ops::RangeFrom<usize>>
        + InputTake,
    E: ParseError<I> + FromExternalError<I, TryFromIntError>,
{
    let (inputs_start, len) = compact_size(i)?;

    let mut i = inputs_start.clone();
    for _ in 0..len {
        let i_ = i.clone();

        match input(i_) {
            Ok((next_i, _)) => {
                i = next_i;
            }
            Err(Err::Error(e)) => return Err(Err::Error(E::append(i, ErrorKind::Count, e))),
            Err(e) => return Err(e),
        }
    }

    Ok((
        i,
        Inputs {
            len,
            input: inputs_start,
        },
    ))
}

/// Parses a raw bitcoin transaction input.
pub fn input<I, E>(i: I) -> IResult<I, Input<I>, E>
where
    I: for<'a> Compare<&'a [u8]>
        + Clone
        + PartialEq
        + InputLength
        + InputIter<Item = u8>
        + Slice<core::ops::RangeFrom<usize>>
        + InputTake,
    E: ParseError<I> + FromExternalError<I, TryFromIntError>,
{
    let previous_output = output_point;
    let script_sig = length_data(map_res(compact_size, usize::try_from));
    let sequence = le_u32;
    let fields = tuple((previous_output, script_sig, sequence));

    let mut parser = map(fields, |(previous_output, script_sig, sequence)| Input {
        previous_output,
        script_sig,
        sequence,
    });

    parser(i)
}

pub fn outputs<I, E>(i: I) -> IResult<I, Outputs<I>, E>
where
    I: for<'a> Compare<&'a [u8]>
        + Clone
        + InputTake
        + InputLength
        + InputIter<Item = u8>
        + Slice<core::ops::RangeFrom<usize>>,
    E: ParseError<I>,
    E: FromExternalError<I, TryFromIntError>,
{
    let (outputs_start, len) = compact_size(i)?;

    let mut i = outputs_start.clone();
    for _ in 0..len {
        let i_ = i.clone();

        match output(i_) {
            Ok((next_i, _)) => {
                i = next_i;
            }
            Err(Err::Error(e)) => {
                return Err(Err::Error(E::append(i, ErrorKind::Count, e)));
            }
            Err(e) => return Err(e),
        }
    }

    Ok((
        i,
        Outputs {
            len,
            input: outputs_start,
        },
    ))
}

/// Parses a raw bitcoin transaction output.
pub fn output<I, E>(i: I) -> IResult<I, Output<I>, E>
where
    I: for<'a> Compare<&'a [u8]>
        + Clone
        + InputTake
        + InputLength
        + InputIter<Item = u8>
        + Slice<core::ops::RangeFrom<usize>>,
    E: ParseError<I>,
    E: FromExternalError<I, TryFromIntError>,
{
    let value = le_i64;
    let script_pubkey = length_data(map_res(compact_size, usize::try_from));
    let fields = tuple((value, script_pubkey));
    let mut parser = map(fields, |(value, script_pubkey)| Output {
        value,
        script_pubkey,
    });

    parser(i)
}

/// Parses a raw bitcoin transaction output point of a transaction input.
pub fn output_point<I, E>(i: I) -> IResult<I, OutputPoint, E>
where
    I: Clone + PartialEq + InputLength + InputIter<Item = u8> + Slice<core::ops::RangeFrom<usize>>,
    E: ParseError<I>,
{
    let hash = txid;
    let index = le_u32;
    let mut parser = map(tuple((hash, index)), |(hash, index)| OutputPoint {
        hash,
        index,
    });

    parser(i)
}
