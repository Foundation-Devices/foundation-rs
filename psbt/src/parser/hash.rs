// SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use nom::{
    error::ParseError, multi::fill, number::complete::u8, IResult, InputIter, InputLength, Slice,
};

use bitcoin_hashes::Hash;
use bitcoin_primitives::{TapLeafHash, TapNodeHash, Txid};

/// Parses a [`bitcoin_hashes::Hash`].
pub fn hash<Input, Hash, Error, const N: usize>(i: Input) -> IResult<Input, Hash, Error>
where
    Input:
        Clone + PartialEq + InputLength + InputIter<Item = u8> + Slice<core::ops::RangeFrom<usize>>,
    Hash: bitcoin_hashes::Hash<Bytes = [u8; N]>,
    Error: ParseError<Input>,
{
    let mut buf = [0; N];
    let (next_i, ()) = fill(u8, &mut buf)(i)?;
    let hash = Hash::from_byte_array(buf);
    Ok((next_i, hash))
}

/// Define an alias for a hash parser.
///
/// This macro exists to reduce the boilerplate needed to defined an alias to the
/// generic [`hash`] function as Rust doesn't provide support for aliasing a
/// function. For example, one can dream of
/// `type ripemd160<'a, Error> = hash::<'a, ripemd160::Hash, Error>;`
macro_rules! define_hash_aliases {
    ($($name:ident),* $(,)?) => {
        $(
            pub fn $name<Input, Error>(
                i: Input,
            ) -> IResult<Input, ::bitcoin_hashes::$name::Hash, Error>
            where
                Input: Clone + PartialEq + InputLength + InputIter<Item = u8> + Slice<core::ops::RangeFrom<usize>>,
                Error: ParseError<Input>,
            {
                hash::<_, ::bitcoin_hashes::$name::Hash, Error, { ::bitcoin_hashes::$name::Hash::LEN }>(i)
            }
        )*
    };
}

define_hash_aliases! {
    ripemd160,
    sha256,
    sha256d,
    hash160,
}

pub fn taproot_leaf_hash<Input, Error>(i: Input) -> IResult<Input, TapLeafHash, Error>
where
    Input:
        Clone + PartialEq + InputLength + InputIter<Item = u8> + Slice<core::ops::RangeFrom<usize>>,
    Error: ParseError<Input>,
{
    hash::<_, TapLeafHash, Error, { TapLeafHash::LEN }>(i)
}

pub fn taproot_node_hash<Input, Error>(i: Input) -> IResult<Input, TapNodeHash, Error>
where
    Input:
        Clone + PartialEq + InputLength + InputIter<Item = u8> + Slice<core::ops::RangeFrom<usize>>,
    Error: ParseError<Input>,
{
    hash::<_, TapNodeHash, Error, { TapNodeHash::LEN }>(i)
}

pub fn txid<Input, Error>(i: Input) -> IResult<Input, Txid, Error>
where
    Input:
        Clone + PartialEq + InputLength + InputIter<Item = u8> + Slice<core::ops::RangeFrom<usize>>,
    Error: ParseError<Input>,
{
    hash::<_, Txid, Error, { Txid::LEN }>(i)
}
