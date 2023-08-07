// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use bitflags::bitflags;
use nom::{
    branch::alt,
    bytes::complete::tag,
    combinator::{eof, map, verify},
    error::{context, ContextError, FromExternalError, ParseError},
    multi::fold_many0,
    number::complete::le_u32,
    sequence::terminated,
    Compare, IResult, InputIter, InputLength, InputTake, Slice,
};

use foundation_bip32::{
    parser::{key_source, xpub},
    KeySource, Xpub,
};

use crate::parser::compact_size::compact_size;
use crate::parser::keypair::key_pair;
use crate::parser::transaction::transaction;
use crate::transaction::Transaction;

pub fn global_map<I, F, Error>(
    mut xpub_event: F,
) -> impl FnMut(I) -> IResult<I, GlobalMap<I>, Error>
where
    I: for<'a> Compare<&'a [u8]>
        + Default
        + PartialEq
        + Clone
        + InputTake
        + InputLength
        + InputIter<Item = u8>
        + Slice<core::ops::RangeFrom<usize>>,
    F: FnMut(Xpub, KeySource<I>),
    Error: ContextError<I> + ParseError<I> + FromExternalError<I, secp256k1::Error>,
{
    // println!("global map");
    let keypairs = fold_many0(
        context("on global key pair", global_key_pair()),
        GlobalMap::default,
        move |mut map, key_pair| {
            match key_pair {
                KeyPair::UnsignedTx(v) => map.transaction = Some(v),
                KeyPair::Xpub { key, source } => xpub_event(key, source),
                KeyPair::TxVersion(v) => map.transaction_version = Some(v),
                KeyPair::FallbackLocktime(v) => map.fallback_locktime = Some(v),
                KeyPair::InputCount(v) => map.input_count = Some(v),
                KeyPair::OutputCount(v) => map.output_count = Some(v),
                KeyPair::TxModifiable(v) => map.tx_modifiable = Some(v),
                KeyPair::Version(v) => map.version = v,
            };

            map
        },
    );

    verify(
        terminated(keypairs, context("separator", tag::<_, I, Error>(b"\x00"))),
        |map| {
            match map.version {
                0 => map.transaction.is_some(),
                // This doesn't exist, from BIP-174 to BIP-370 they jumped from 0 to 2,
                // so just pass validation.
                //
                // We pass the validation in the case that (I hope really not) this
                // version number is reused.
                1 => true,
                // Make sure that these fields exist and make sure that version 0 fields
                // are excluded.
                2 => {
                    map.transaction.is_none()
                        && map.input_count.is_some()
                        && map.output_count.is_some()
                }
                // Don't verify what we don't know.
                _ => true,
            }
        },
    )
}

fn global_key_pair<I, Error>() -> impl FnMut(I) -> IResult<I, KeyPair<I>, Error>
where
    I: for<'a> Compare<&'a [u8]>
        + PartialEq
        + Clone
        + InputTake
        + InputLength
        + InputIter<Item = u8>
        + Slice<core::ops::RangeFrom<usize>>,
    Error: ContextError<I> + ParseError<I> + FromExternalError<I, secp256k1::Error>,
{
    // println!("global key pair");

    let unsigned_tx = context("utx", key_pair(0x00, eof, transaction));
    let xpub = key_pair(0x01, xpub, key_source);
    let xpub = context(
        "xpub",
        verify(xpub, |(k, v)| usize::from(k.depth) == v.path.len()),
    );
    let tx_version = context("tx ver", key_pair(0x02, eof, le_u32));
    let fallback_locktime = context("fallback locktime", key_pair(0x03, eof, le_u32));
    let input_count = context("input cnt", key_pair(0x04, eof, compact_size));
    let output_count = context("output cnt", key_pair(0x05, eof, compact_size));
    let tx_modifiable = context("tx modifiable", key_pair(0x06, eof, tx_modifiable));
    let version = context("version", key_pair(0xFB, eof, le_u32));

    alt((
        map(unsigned_tx, |(_, v)| KeyPair::UnsignedTx(v)),
        map(xpub, |(k, v)| KeyPair::Xpub { key: k, source: v }),
        map(tx_version, |(_, v)| KeyPair::TxVersion(v)),
        map(fallback_locktime, |(_, v)| KeyPair::FallbackLocktime(v)),
        map(input_count, |(_, v)| KeyPair::InputCount(v)),
        map(output_count, |(_, v)| KeyPair::OutputCount(v)),
        map(tx_modifiable, |(_, v)| KeyPair::TxModifiable(v)),
        map(version, |(_, v)| KeyPair::Version(v)),
    ))
}

fn tx_modifiable<I, Error>(i: I) -> IResult<I, TxModifiable, Error>
where
    I: InputLength + Slice<core::ops::RangeFrom<usize>> + InputIter<Item = u8>,
    Error: ParseError<I>,
{
    map(nom::number::complete::u8, TxModifiable::from_bits_retain)(i)
}

#[derive(Debug, Default)]
pub struct GlobalMap<I> {
    pub transaction: Option<Transaction<I>>,
    pub input_count: Option<u64>,
    pub output_count: Option<u64>,
    pub transaction_version: Option<u32>,
    pub fallback_locktime: Option<u32>,
    pub tx_modifiable: Option<TxModifiable>,
    pub version: u32,
}

impl<I> GlobalMap<I> {
    pub fn input_count(&self) -> Option<u64> {
        match self.version {
            0 => self.transaction.as_ref().map(|tx| tx.inputs.len()),
            // No way to handle this.
            1 => None,
            // n >= 2
            _ => self.input_count,
        }
    }

    pub fn output_count(&self) -> Option<u64> {
        match self.version {
            0 => self.transaction.as_ref().map(|tx| tx.outputs.len()),
            // No way to handle this.
            1 => None,
            // n >= 2
            _ => self.output_count,
        }
    }
}

/// Entry type for the PSBT global map.
#[derive(Debug)]
enum KeyPair<I> {
    /// The unsigned transaction.
    UnsignedTx(Transaction<I>),
    /// Extended public key entry.
    Xpub {
        /// The extended public key.
        key: Xpub,
        /// The key source information.
        source: KeySource<I>,
    },
    TxVersion(u32),
    FallbackLocktime(u32),
    InputCount(u64),
    OutputCount(u64),
    TxModifiable(TxModifiable),
    Version(u32),
}

bitflags! {
    /// Bit flags indicating which parts of the PSBT are modifiable.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct TxModifiable: u8 {
        /// Inputs of the PSBT are modifiable.
        const INPUTS_MODIFIABLE = (1 << 0);
        /// Outputs of the PSBT are modifiable.
        const OUTPUTS_MODIFIABLE = (1 << 1);
        /// Indicates that the transaction has a SIGHASH_SINGLE
        /// signature who's input and output must be preserved.
        const SIGHASH_SINGLE = (1 << 2);
    }
}
