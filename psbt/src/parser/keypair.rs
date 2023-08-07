// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use nom::combinator::{map, verify};
use nom::error::context;
use nom::error::{ContextError, ParseError};
use nom::multi::length_value;
use nom::sequence::tuple;
use nom::{Compare, IResult, InputIter, InputLength, InputTake, Parser, Slice};

use crate::parser::compact_size::compact_size;

/// TODO: Need to check for the map separator before hand in order to avoid
/// parsing without need.

/// Parse a `<keypair>`.
pub fn key_pair<I, F, G, K, V, E>(
    key_type: u64,
    key_data: F,
    value: G,
) -> impl FnMut(I) -> IResult<I, (K, V), E>
where
    I: for<'a> Compare<&'a [u8]>
        + Clone
        + InputTake
        + InputLength
        + InputIter<Item = u8>
        + Slice<core::ops::RangeFrom<usize>>,
    F: Parser<I, K, E>,
    G: Parser<I, V, E>,
    E: ParseError<I> + ContextError<I>,
{
    //println!("key pair: {key_type}");

    let value = length_value(
        verify(compact_size, |_v| {
            //println!("length {v}");
            true
        }),
        context("when parsing value", value),
    );

    tuple((key(key_type, key_data), value))
}

/// Parse a `<key>`.
pub fn key<I, K, F, E>(key_type: u64, key_data: F) -> impl FnMut(I) -> IResult<I, K, E>
where
    I: for<'a> Compare<&'a [u8]>
        + Clone
        + InputTake
        + InputLength
        + InputIter<Item = u8>
        + Slice<core::ops::RangeFrom<usize>>,
    F: Parser<I, K, E>,
    E: ParseError<I>,
{
    let key_type = verify(compact_size, move |&k| {
        //println!("key_type {k}");
        k == key_type
    });

    // This verification makes sure that the length is not a separator of a map.
    let length = verify(compact_size, |&v| {
        //println!("key_len {v}");
        v != 0x00
    });

    let fields = tuple((key_type, key_data));
    map(length_value(length, fields), |(_, o)| o)
}
