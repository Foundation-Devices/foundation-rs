// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use nom::{
    error::ParseError, multi::fill, number::complete::u8, IResult, InputIter, InputLength, Slice,
};

use bitcoin_hashes::Hash;

use crate::{hash_types, taproot};

/// Parses a [`bitcoin_hashes::Hash`].
///
/// # Why N instead of [`bitcoin_hashes::Hash::LEN`].
///
/// NOTE(jeandudey): Using `N` because on Rust 1.70.0 it somehow can't use the
/// associated constant `LEN` of `bitcoin_hashes::Hash`` trait and shows the
/// following error:
///
/// ```text
/// error: generic parameters may not be used in const operations
///
///     let mut buf = [0; Hash::LEN];
/// ```
///
/// Maybe a bug, perhaps report this upstream, I think rustc is broken in
/// this edge case.
///
/// Ideally one would use fill with the aforementioned `buf` variable to
/// avoid this verbose loop.
pub fn hash<Input, Hash, Error, const N: usize>(i: Input) -> IResult<Input, Hash, Error>
where
    Input:
        Clone + PartialEq + InputLength + InputIter<Item = u8> + Slice<core::ops::RangeFrom<usize>>,
    Hash: bitcoin_hashes::Hash,
    Error: ParseError<Input>,
{
    let mut buf = [0; N];
    let (next_i, ()) = fill(u8, &mut buf)(i)?;
    let hash = Hash::from_slice(&buf).expect("should have the correct length");
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

pub fn taproot_leaf_hash<Input, Error>(i: Input) -> IResult<Input, taproot::LeafHash, Error>
where
    Input:
        Clone + PartialEq + InputLength + InputIter<Item = u8> + Slice<core::ops::RangeFrom<usize>>,
    Error: ParseError<Input>,
{
    hash::<_, taproot::LeafHash, Error, { taproot::LeafHash::LEN }>(i)
}

pub fn taproot_node_hash<Input, Error>(i: Input) -> IResult<Input, taproot::TapNodeHash, Error>
where
    Input:
        Clone + PartialEq + InputLength + InputIter<Item = u8> + Slice<core::ops::RangeFrom<usize>>,
    Error: ParseError<Input>,
{
    hash::<_, taproot::TapNodeHash, Error, { taproot::TapNodeHash::LEN }>(i)
}

pub fn txid<Input, Error>(i: Input) -> IResult<Input, hash_types::Txid, Error>
where
    Input:
        Clone + PartialEq + InputLength + InputIter<Item = u8> + Slice<core::ops::RangeFrom<usize>>,
    Error: ParseError<Input>,
{
    hash::<_, hash_types::Txid, Error, { hash_types::Txid::LEN }>(i)
}
