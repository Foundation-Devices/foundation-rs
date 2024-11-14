// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Parser combinators for parsing PSBTs.
//!
//! This library provides a PSBT parser for memory constrained devices by
//! using streaming parsers in order to not require memory allocations.
//!
//! The PSBT file will be parsed (and validated depending on the use case)
//! on the fly.
//!
//! The approach in this library may not be suitable for systems with lots
//! of memory as it is slower than usual, however for embedded devices it
//! may excel as it doesn't need the entire PSBT in memory, just the bits
//! needed.
//!
//! When more data is needed it can be simply read from a file.

pub mod compact_size;
pub mod global;
pub mod hash;
pub mod input;
pub mod keypair;
pub mod multi;
pub mod output;
// NOTE: Can't name this secp256k1 or else we can't refer to
// secp256k1::Error :-). might be a bug with Rust.
pub mod secp;
pub mod transaction;

use nom::{
    bytes::complete::tag,
    error::{context, ContextError, ErrorKind, FromExternalError, ParseError},
    Compare, Err, IResult, InputIter, InputLength, InputTake, Slice,
};

use foundation_bip32::{KeySource, Xpub};
use secp256k1::PublicKey;

use crate::transaction::Transaction;

/// Parse a Partially Signed Bitcoin Transaction (PSBT).
pub fn psbt<Input, GlobalXpubEvent, InputXpubEvent, Error>(
    global_xpub_event: GlobalXpubEvent,
    input_xpub_event: InputXpubEvent,
) -> impl FnMut(Input) -> IResult<Input, Psbt<Input>, Error>
where
    Input: for<'a> Compare<&'a [u8]>
        + Clone
        + PartialEq
        + InputTake
        + InputLength
        + InputIter<Item = u8>
        + Slice<core::ops::RangeFrom<usize>>,
    GlobalXpubEvent: FnMut(Xpub, KeySource<Input>),
    InputXpubEvent: FnMut(PublicKey, KeySource<Input>) + Copy,
    Error: core::fmt::Debug
        + ContextError<Input>
        + ParseError<Input>
        + FromExternalError<Input, secp256k1::Error>
        + FromExternalError<Input, bitcoin_hashes::FromSliceError>,
{
    let mut magic = context("magic bytes", tag::<_, Input, Error>(b"psbt\xff"));
    let mut global_map = global::global_map(global_xpub_event);
    move |i: Input| {
        let (i, _) = magic(i)?;
        let (i, global_map) = global_map(i)?;
        let mut input = i.clone();

        let input_count = global_map.input_count().unwrap_or(0);
        let output_count = global_map.input_count().unwrap_or(0);

        for _ in 0..input_count {
            let input_ = input.clone();

            match input::input_map(input_xpub_event)(input_) {
                Ok((i, _txin)) => {
                    input = i;
                }
                Err(Err::Error(e)) => {
                    return Err(Err::Error(Error::append(i, ErrorKind::Count, e)))
                }
                Err(e) => return Err(e),
            }
        }

        for _ in 0..output_count {
            let input_ = input.clone();

            match output::output_map(input_) {
                Ok((i, _o)) => {
                    input = i;
                }
                Err(Err::Error(e)) => {
                    return Err(Err::Error(Error::append(i, ErrorKind::Count, e)))
                }
                Err(e) => return Err(e),
            }
        }

        Ok((
            i,
            Psbt {
                transaction: global_map.transaction,
                version: global_map.version,
                transaction_version: global_map.transaction_version.unwrap_or(0),
                fallback_lock_time: global_map.fallback_locktime,
                tx_modifiable: global_map
                    .tx_modifiable
                    .unwrap_or_else(|| global::TxModifiable::empty()),
            },
        ))
    }
}

/// A Partially Signed Bitcoin Transaction (PSBT).
#[derive(Debug)]
pub struct Psbt<Input> {
    pub transaction: Option<Transaction<Input>>,
    /// Version of the PSBT file.
    pub version: u32,
    /// The version of the transaction.
    pub transaction_version: u32,
    /// The fallback lock time to use if no inputs specify a required lock
    /// time.
    pub fallback_lock_time: Option<u32>,
    /// Flags indicating which parts of the transaction that are modifiable.
    pub tx_modifiable: global::TxModifiable,
}

/*
#[cfg(test)]
mod tests {
    use super::*;
    use nom::error::VerboseError;

    //#[test]
    //#[cfg(feature = "std")]
    //fn invalid_18() {
    //    let test_vectors = foundation_test_vectors::psbt::TestVectors::new();
    //    let test_vector = &test_vectors.invalid[18];

    //    println!("Test vector 18: {}", test_vector.description);
    //    let mut psbt = psbt::<_, VerboseError<_>>(|_, _| ());
    //    let (_, map) = psbt(&test_vector.data).unwrap();
    //    panic!("{:?}", map.transaction);
    //}

    #[test]
    #[cfg(feature = "std")]
    fn parse_psbt_invalid_test_vectors() {
        let test_vectors = foundation_test_vectors::psbt::TestVectors::new();

        for (i, test_vector) in test_vectors.invalid.iter().enumerate() {
            println!("Test vector {i}: {}", test_vector.description);
            let mut psbt = psbt::<_, VerboseError<_>>(|_, _| ());
            psbt(&test_vector.data).unwrap_err();
        }
    }

    #[test]
    #[cfg(feature = "std")]
    fn parse_psbt_valid_test_vectors() {
        let test_vectors = foundation_test_vectors::psbt::TestVectors::new();

        for (i, test_vector) in test_vectors.valid.iter().enumerate() {
            println!("Test vector {i}: {}", test_vector.description);
            let mut psbt = psbt::<_, VerboseError<_>>(|_, _| ());
            match psbt(&test_vector.data) {
                Err(e) => panic!("{e}"),
                _ => (),
            }
        }
    }
}
*/
