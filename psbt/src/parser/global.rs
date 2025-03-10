// SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use core::num::TryFromIntError;

use bitflags::bitflags;
use nom::{
    bytes::complete::tag,
    combinator::{map, rest, verify},
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

use crate::{
    parser::{
        compact_size::compact_size,
        keypair::{key, value},
        transaction::transaction,
    },
    transaction::Transaction,
};

pub fn global_map<I, F, Error>(
    mut xpub_event: F,
) -> impl FnMut(I) -> IResult<I, GlobalMap<I>, Error>
where
    I: for<'a> Compare<&'a [u8]>
        + PartialEq
        + Clone
        + InputTake
        + InputLength
        + InputIter<Item = u8>
        + Slice<core::ops::RangeFrom<usize>>,
    F: FnMut(Xpub, KeySource<I>),
    Error: ContextError<I>
        + ParseError<I>
        + FromExternalError<I, secp256k1::Error>
        + FromExternalError<I, TryFromIntError>,
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
                KeyPair::Unknown(_, _) => (),
            };

            map
        },
    );

    verify(
        terminated(
            keypairs,
            context("global separator", tag::<_, I, Error>(b"\x00")),
        ),
        |map| {
            match map.version {
                0 => map.transaction.is_some(),
                // This doesn't exist, from BIP-174 to BIP-370 they jumped from 0 to 2,
                // so just fail validation.
                1 => false,
                // Make sure that these fields exist and make sure that version 0 fields
                // are excluded.
                2 => {
                    map.transaction.is_none()
                        && map.input_count.is_some()
                        && map.output_count.is_some()
                }
                // Don't verify what we don't know.
                _ => false,
            }
        },
    )
}

fn global_key_pair<I, Error>() -> impl FnMut(I) -> IResult<I, KeyPair<I>, Error>
where
    I: PartialEq
        + Clone
        + InputTake
        + InputLength
        + InputIter<Item = u8>
        + Slice<core::ops::RangeFrom<usize>>,
    Error: ContextError<I>
        + ParseError<I>
        + FromExternalError<I, secp256k1::Error>
        + FromExternalError<I, TryFromIntError>,
{
    move |i| {
        let (i, (key, keydata)) = key(i)?;

        match key {
            0x00 => map(value(transaction), KeyPair::UnsignedTx)(i),
            0x01 => {
                let (_, xpub) = xpub(keydata)?;
                let (i, source) = value(key_source)(i)?;

                Ok((i, KeyPair::Xpub { key: xpub, source }))
            }
            0x02 => map(value(le_u32), KeyPair::TxVersion)(i),
            0x03 => map(value(le_u32), KeyPair::FallbackLocktime)(i),
            0x04 => map(value(compact_size), KeyPair::InputCount)(i),
            0x05 => map(value(compact_size), KeyPair::OutputCount)(i),
            0x06 => map(value(tx_modifiable), KeyPair::TxModifiable)(i),
            0xFB => map(value(le_u32), KeyPair::Version)(i),
            _ => {
                let (i, v) = value(rest)(i)?;
                Ok((i, KeyPair::Unknown(keydata, v)))
            }
        }
    }
}

fn tx_modifiable<I, Error>(i: I) -> IResult<I, TxModifiable, Error>
where
    I: InputLength + Slice<core::ops::RangeFrom<usize>> + InputIter<Item = u8>,
    Error: ParseError<I>,
{
    map(nom::number::complete::u8, TxModifiable::from_bits_retain)(i)
}

#[derive(Debug)]
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

// This has to be implemented manually because the automatic
// derive would add a `I: Default` requirement when that is not
// necessary.
//
// And we can't implement Default for the input.
impl<I> Default for GlobalMap<I> {
    fn default() -> Self {
        Self {
            transaction: None,
            input_count: None,
            output_count: None,
            transaction_version: None,
            fallback_locktime: None,
            tx_modifiable: None,
            version: 0,
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
    Unknown(I, I),
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
