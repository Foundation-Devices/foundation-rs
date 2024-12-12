// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use core::num::TryFromIntError;

use nom::branch::alt;
use nom::bytes::complete::tag;
use nom::combinator::{eof, map, rest, verify};
use nom::error::{context, ContextError, FromExternalError, ParseError};
use nom::multi::fold_many0;
use nom::number::complete::le_u64;
use nom::sequence::terminated;
use nom::{Compare, IResult, InputIter, InputLength, InputTake, Slice};

use secp256k1::{PublicKey, XOnlyPublicKey};

use foundation_bip32::{
    parser::{key_source, public_key},
    KeySource,
};

use crate::parser::global::GlobalMap;
use crate::parser::keypair::key_pair;
use crate::parser::secp::x_only_public_key;
use crate::transaction;

#[rustfmt::skip]
pub fn output_map<B, C, Input, Error>(
    version: u32,
    mut bip32_derivation: B,
    mut tap_bip32_derivation: C,
) -> impl FnMut(Input) -> IResult<Input, OutputMap<Input>, Error>
where
    B: FnMut(PublicKey, KeySource<Input>),
    C: FnMut(XOnlyPublicKey, Input),
    Input: for<'a> Compare<&'a [u8]>
        + Clone
        + PartialEq
        + InputTake
        + InputLength
        + InputIter<Item = u8>
        + Slice<core::ops::RangeFrom<usize>>,
    Error: ContextError<Input>,
    Error: ParseError<Input> + FromExternalError<Input, secp256k1::Error> + FromExternalError<Input, TryFromIntError>,
{
    let keypairs = fold_many0(
        output_key_pair,
        OutputMap::default,
        move |mut map, key_pair| {
            match key_pair {
                KeyPair::RedeemScript(v)          => map.redeem_script = Some(v),
                KeyPair::WitnessScript(v)         => map.witness_script = Some(v),
                KeyPair::Bip32Derivation(p, s)    => bip32_derivation(p, s),
                KeyPair::Amount(v)                => map.amount = Some(v),
                KeyPair::Script(v)                => map.script = Some(v),
                KeyPair::TapInternalKey(v)        => map.tap_internal_key = Some(v),
                KeyPair::TapTree(v)               => map.tap_tree = Some(v),
                KeyPair::TapBip32Derivation(p, s) => tap_bip32_derivation(p, s),
            };

            map
        },
    );

    verify(
        terminated(
            keypairs,
            context("output separator", tag::<_, Input, Error>(b"\x00"))
        ),
        move |map| {
            match version {
                0 => true,
                2 => map.script.is_some() && map.amount.is_some(),
                _ => false,
            }
        }
    )
}

#[rustfmt::skip]
fn output_key_pair<Input, Error>(i: Input) -> IResult<Input, KeyPair<Input>, Error>
where
    Input: for<'a> Compare<&'a [u8]>
        + Clone
        + PartialEq
        + InputTake
        + InputLength
        + InputIter<Item = u8>
        + Slice<core::ops::RangeFrom<usize>>,
    Error: ContextError<Input>,
    Error: ParseError<Input>,
    Error: FromExternalError<Input, secp256k1::Error>,
    Error: FromExternalError<Input, TryFromIntError>,
{
    let redeem_script        = context("redeem script", key_pair(0x00, eof, rest));
    let witness_script       = context("witness script", key_pair(0x01, eof, rest));
    let bip32_derivation     = context("bip32 derivation", key_pair(0x02, context("output public key", public_key), key_source));
    let amount               = context("amount", key_pair(0x03, eof, context("output amount", le_u64)));
    let script               = context("script", key_pair(0x04, eof, rest));
    let tap_internal_key     = context("tap internal key", key_pair(0x05, eof, context("tap internal key", x_only_public_key)));
    let tap_tree             = context("tap tree", key_pair(0x06, eof, rest));
    let tap_bip32_derivation = context("tap bip32 derivation", key_pair(0x06, context("x only public key", x_only_public_key), rest));

    alt((
        map(redeem_script,        |(_, v)| KeyPair::RedeemScript(v)),
        map(witness_script,       |(_, v)| KeyPair::WitnessScript(v)),
        map(bip32_derivation,     |(k, v)| KeyPair::Bip32Derivation(k, v)),
        map(amount,               |(_, v)| KeyPair::Amount(v)),
        map(script,               |(_, v)| KeyPair::Script(v)),
        map(tap_internal_key,     |(_, v)| KeyPair::TapInternalKey(v)),
        map(tap_tree,             |(_, v)| KeyPair::TapTree(v)),
        map(tap_bip32_derivation, |(k, v)| KeyPair::TapBip32Derivation(k, v)),
    ))(i)
}

#[derive(Debug)]
pub struct OutputMap<Input> {
    pub redeem_script: Option<Input>,
    pub witness_script: Option<Input>,
    pub amount: Option<u64>,
    pub script: Option<Input>,
    pub tap_internal_key: Option<XOnlyPublicKey>,
    pub tap_tree: Option<Input>,
}

impl<Input> OutputMap<Input>
where
    Input: for<'a> nom::Compare<&'a [u8]>
        + Clone
        + PartialEq
        + core::fmt::Debug
        + nom::InputTake
        + nom::InputIter<Item = u8>
        + nom::InputLength
        + nom::Slice<core::ops::RangeFrom<usize>>,
{
    /// Return the transaction output of this PSBT output (aka. amount and
    /// scriptPubKey).
    pub fn transaction_output(
        &self,
        global: &GlobalMap<Input>,
        index: usize,
    ) -> Option<transaction::Output<Input>> {
        match global.version {
            0 => global
                .transaction
                .as_ref()
                .map(|tx| tx.outputs.iter().nth(index))
                .flatten(),
            2 => {
                match (self.amount, self.script.clone()) {
                    (Some(amount), Some(script)) => {
                        // TODO: Report error when converting from u64 to i64 instead.
                        if let Ok(amount) = i64::try_from(amount) {
                            Some(transaction::Output {
                                value: amount,
                                script_pubkey: script,
                            })
                        } else {
                            None
                        }
                    }
                    _ => None,
                }
            }
            _ => None,
        }
    }
}

impl<Input> Default for OutputMap<Input> {
    fn default() -> Self {
        Self {
            redeem_script: None,
            witness_script: None,
            amount: None,
            script: None,
            tap_internal_key: None,
            tap_tree: None,
        }
    }
}

enum KeyPair<Input> {
    RedeemScript(Input),
    WitnessScript(Input),
    Bip32Derivation(PublicKey, KeySource<Input>),
    Amount(u64),
    Script(Input),
    TapInternalKey(XOnlyPublicKey),
    TapTree(Input),
    TapBip32Derivation(XOnlyPublicKey, Input),
}
