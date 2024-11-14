// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use nom::branch::alt;
use nom::bytes::complete::tag;
use nom::combinator::{eof, map, rest};
use nom::error::{ContextError, FromExternalError, ParseError};
use nom::multi::fold_many0;
use nom::number::complete::le_u64;
use nom::sequence::terminated;
use nom::{Compare, IResult, InputIter, InputLength, InputTake, Slice};

use secp256k1::{PublicKey, XOnlyPublicKey};

use foundation_bip32::{
    parser::{key_source, public_key},
    KeySource,
};

use crate::parser::keypair::key_pair;
use crate::parser::secp::x_only_public_key;

#[rustfmt::skip]
pub fn output_map<Input, Error>(i: Input) -> IResult<Input, OutputMap<Input>, Error>
where
    Input: for<'a> Compare<&'a [u8]>
        + Clone
        + PartialEq
        + InputTake
        + InputLength
        + InputIter<Item = u8>
        + Slice<core::ops::RangeFrom<usize>>,
    Error: ContextError<Input>,
    Error: ParseError<Input> + FromExternalError<Input, secp256k1::Error>,
{
    let keypairs = fold_many0(
        output_key_pair,
        OutputMap::default,
        |mut map, key_pair| {
            match key_pair {
                KeyPair::RedeemScript(v)          => map.redeem_script = Some(v),
                KeyPair::WitnessScript(v)         => map.witness_script = Some(v),
                KeyPair::Bip32Derivation(_, _)    => (), // TODO
                KeyPair::Amount(v)                => map.amount = Some(v),
                KeyPair::Script(v)                => map.script = Some(v),
                KeyPair::TapInternalKey(v)        => map.tap_internal_key = Some(v),
                KeyPair::TapTree(v)               => map.tap_tree = Some(v),
                KeyPair::TapBip32Derivation(_, _) => (), // TODO
            };

            map
        },
    );

    terminated(keypairs, tag::<_, Input, Error>(b"\x00"))(i)
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
{
    let redeem_script        = key_pair(0x00, eof, rest);
    let witness_script       = key_pair(0x01, eof, rest);
    let bip32_derivation     = key_pair(0x02, public_key, key_source);
    let amount               = key_pair(0x03, eof, le_u64);
    let script               = key_pair(0x04, eof, rest);
    let tap_internal_key     = key_pair(0x05, eof, x_only_public_key);
    let tap_tree             = key_pair(0x06, eof, rest);
    let tap_bip32_derivation = key_pair(0x06, x_only_public_key, rest);

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
