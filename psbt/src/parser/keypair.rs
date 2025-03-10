// SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use core::{num::TryFromIntError, ops::RangeFrom};

use nom::{
    combinator::{map_res, rest, verify},
    error::{FromExternalError, ParseError},
    multi::length_value,
    sequence::tuple,
    IResult, InputIter, InputLength, InputTake, Parser, Slice,
};

use crate::parser::compact_size::compact_size;

/// Parse a `<key>`.
pub fn key<I, E>(i: I) -> IResult<I, (u64, I), E>
where
    I: Clone + InputTake + InputLength + InputIter<Item = u8> + Slice<RangeFrom<usize>>,
    E: ParseError<I> + FromExternalError<I, TryFromIntError>,
{
    // This verification makes sure that the length is not a separator of a map.
    let length = map_res(verify(compact_size, |&v| v != 0x00), usize::try_from);
    length_value(length, tuple((compact_size, rest)))(i)
}

/// Parse a `<value>`.
pub fn value<I, O, E, F>(f: F) -> impl FnMut(I) -> IResult<I, O, E>
where
    I: Clone + InputTake + InputLength + InputIter<Item = u8> + Slice<RangeFrom<usize>>,
    F: Parser<I, O, E>,
    E: ParseError<I> + FromExternalError<I, TryFromIntError>,
{
    length_value(map_res(compact_size, usize::try_from), f)
}
