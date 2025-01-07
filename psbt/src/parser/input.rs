// SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use core::num::TryFromIntError;

use bitcoin_hashes::{hash160, ripemd160, sha256, sha256d};

use nom::branch::alt;
use nom::bytes::complete::tag;
use nom::combinator::{eof, map, map_res, rest};
use nom::error::{context, ContextError, ErrorKind, FromExternalError, ParseError};
use nom::multi::length_value;
use nom::number::complete::{le_u32, le_u64};
use nom::sequence::tuple;
use nom::{Compare, Err, IResult, InputIter, InputLength, InputTake, Slice};

use secp256k1::{schnorr, PublicKey, XOnlyPublicKey};

use foundation_bip32::{
    parser::{key_source, public_key},
    KeySource,
};

use bitcoin_primitives::{TapNodeHash, Txid};

use crate::parser::compact_size::compact_size;
use crate::parser::hash::{
    hash160, ripemd160, sha256, sha256d, taproot_leaf_hash, taproot_node_hash, txid,
};
use crate::parser::keypair::key_pair;
use crate::parser::secp::{schnorr_signature, x_only_public_key};
use crate::parser::transaction::transaction;
use crate::taproot::TaprootScriptSignature;
use crate::transaction::{Transaction, SIGHASH_ALL};

/// Insert `value` into `option` if it's not set already, if already set
/// return an error.
fn insert<I, T, E>(option: &mut Option<T>, value: T, input: I) -> Result<(), Err<E>>
where
    E: ParseError<I>,
{
    match option {
        Some(_) => Err(Err::Failure(E::from_error_kind(input, ErrorKind::Fail))),
        None => {
            *option = Some(value);
            Ok(())
        }
    }
}

pub fn input_map<B, Input, Error>(
    mut bip32_derivation: B,
) -> impl FnMut(Input) -> IResult<Input, InputMap<Input>, Error>
where
    B: FnMut(PublicKey, KeySource<Input>),
    Input: for<'a> Compare<&'a [u8]>
        + Clone
        + PartialEq
        + InputTake
        + InputLength
        + InputIter<Item = u8>
        + Slice<core::ops::RangeFrom<usize>>,
    Error: core::fmt::Debug,
    Error: ContextError<Input>,
    Error: ParseError<Input>,
    Error: FromExternalError<Input, secp256k1::Error>,
    Error: FromExternalError<Input, TryFromIntError>,
{
    move |i: Input| {
        let mut map = InputMap::default();
        let mut input = i;

        loop {
            let i_ = input.clone();
            let len = input.input_len();

            let key_pair = match input_key_pair(i_.clone()) {
                Ok((i, k)) => {
                    // infinite loop check: the parser must always consume.
                    if i.input_len() == len {
                        return Err(Err::Error(Error::from_error_kind(input, ErrorKind::Many0)));
                    }

                    input = i;
                    k
                }
                Err(Err::Error(_)) => {
                    break;
                }
                Err(e) => {
                    return Err(e);
                }
            };

            match key_pair {
                KeyPair::NonWitnessUtxo(v) => insert(&mut map.non_witness_utxo, v, i_)?,
                KeyPair::WitnessUtxo(v) => insert(&mut map.witness_utxo, v, i_)?,
                KeyPair::PartialSig(_) => (), // TODO
                KeyPair::SighashType(v) => insert(&mut map.sighash_type, v, i_)?,
                KeyPair::RedeemScript(v) => insert(&mut map.redeem_script, v, i_)?,
                KeyPair::WitnessScript(v) => insert(&mut map.witness_script, v, i_)?,
                KeyPair::Bip32Derivation(p, s) => bip32_derivation(p, s),
                KeyPair::FinalScriptsig(v) => insert(&mut map.final_scriptsig, v, i_)?,
                KeyPair::FinalScriptwitness(v) => insert(&mut map.final_scriptwitness, v, i_)?,
                KeyPair::PorCommitment(v) => insert(&mut map.por_commitment, v, i_)?,
                KeyPair::Ripemd160(_) => (), // TODO
                KeyPair::Sha256(_) => (),    // TODO
                KeyPair::Hash160(_) => (),   // TODO
                KeyPair::Hash256(_) => (),   // TODO
                KeyPair::PreviousTxid(v) => insert(&mut map.previous_txid, v, i_)?,
                KeyPair::OutputIndex(v) => insert(&mut map.output_index, v, i_)?,
                KeyPair::Sequence(v) => insert(&mut map.sequence, v, i_)?,
                KeyPair::RequiredTimeLocktime(v) => insert(&mut map.required_time_locktime, v, i_)?,
                KeyPair::RequiredHeightLocktime(v) => {
                    insert(&mut map.required_height_locktime, v, i_)?
                }
                KeyPair::TapKeySig(v) => insert(&mut map.tap_key_sig, v, i_)?,
                KeyPair::TapScriptSig(_, _) => (),       // TODO
                KeyPair::TapLeafScript(_, _) => (),      // TODO
                KeyPair::TapBip32Derivation(_, _) => (), // TODO
                KeyPair::TapInternalKey(v) => insert(&mut map.tap_internal_key, v, i_)?,
                KeyPair::TapMerkleRoot(v) => insert(&mut map.tap_merkle_root, v, i_)?,
            };
        }

        // match the terminator.
        let (input, _) = tag::<_, Input, Error>(b"\x00")(input)?;

        Ok((input, map))
    }
}

fn input_key_pair<Input, Error>(i: Input) -> IResult<Input, KeyPair<Input>, Error>
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
    let non_witness_utxo = key_pair(0x00, eof, transaction);
    let witness_utxo = key_pair(0x01, eof, witness_utxo);
    let partial_sig = key_pair(0x02, public_key, rest);
    let sighash_type = key_pair(0x03, eof, le_u32);
    let redeem_script = key_pair(0x04, eof, rest);
    let witness_script = key_pair(0x05, eof, rest);
    let bip32_derivation = key_pair(0x06, public_key, key_source);
    let final_scriptsig = key_pair(0x07, eof, rest);
    let final_scriptwitness = key_pair(0x08, eof, rest);
    let por_commitment = key_pair(0x09, eof, rest);
    let ripemd160 = key_pair(0x0a, ripemd160, rest);
    let sha256 = key_pair(0x0b, sha256, rest);
    let hash160 = key_pair(0x0c, hash160, rest);
    let hash256 = key_pair(0x0d, sha256d, rest);
    let previous_txid = key_pair(0x0e, eof, txid);
    let output_index = key_pair(0x0f, eof, le_u32);
    let sequence = key_pair(0x10, eof, le_u32);
    let required_time_locktime = key_pair(0x11, eof, le_u32);
    let required_height_locktime = key_pair(0x12, eof, le_u32);
    let tap_key_sig = key_pair(0x13, eof, schnorr_signature);
    let tap_script_sig = key_pair(0x14, tap_script_sig, schnorr_signature);
    let tap_leaf_script = key_pair(0x15, rest, rest); // TODO
    let tap_bip32_derivation = key_pair(0x16, x_only_public_key, rest); // TODO
    let tap_internal_key = key_pair(0x17, eof, x_only_public_key);
    let tap_merkle_root = key_pair(0x18, eof, taproot_node_hash);

    alt((
        map(non_witness_utxo, |(_, v)| KeyPair::NonWitnessUtxo(v)),
        map(witness_utxo, |(_, v)| KeyPair::WitnessUtxo(v)),
        map(partial_sig, |(k, _)| KeyPair::PartialSig(k)),
        map(sighash_type, |(_, v)| KeyPair::SighashType(v)),
        map(redeem_script, |(_, v)| KeyPair::RedeemScript(v)),
        map(witness_script, |(_, v)| KeyPair::WitnessScript(v)),
        map(bip32_derivation, |(k, v)| KeyPair::Bip32Derivation(k, v)),
        map(final_scriptsig, |(_, v)| KeyPair::FinalScriptsig(v)),
        map(final_scriptwitness, |(_, v)| KeyPair::FinalScriptwitness(v)),
        map(por_commitment, |(_, v)| KeyPair::PorCommitment(v)),
        map(ripemd160, |(k, _)| KeyPair::Ripemd160(k)), // TODO
        map(sha256, |(k, _)| KeyPair::Sha256(k)),       // TODO
        map(hash160, |(k, _)| KeyPair::Hash160(k)),     // TODO
        map(hash256, |(k, _)| KeyPair::Hash256(k)),     // TODO
        map(previous_txid, |(_, v)| KeyPair::PreviousTxid(v)),
        map(output_index, |(_, v)| KeyPair::OutputIndex(v)),
        map(sequence, |(_, v)| KeyPair::Sequence(v)),
        map(required_time_locktime, |(_, v)| {
            KeyPair::RequiredTimeLocktime(v)
        }),
        map(required_height_locktime, |(_, v)| {
            KeyPair::RequiredHeightLocktime(v)
        }),
        map(tap_key_sig, |(_, v)| KeyPair::TapKeySig(v)),
        // This nesting is needed because `Alt` can only handle tuples up to
        // 21 elements.
        alt((
            map(tap_script_sig, |(k, v)| KeyPair::TapScriptSig(k, v)),
            map(tap_leaf_script, |(k, v)| KeyPair::TapLeafScript(k, v)),
            map(tap_bip32_derivation, |(k, v)| {
                KeyPair::TapBip32Derivation(k, v)
            }),
            map(tap_internal_key, |(_, v)| KeyPair::TapInternalKey(v)),
            map(tap_merkle_root, |(_, v)| KeyPair::TapMerkleRoot(v)),
        )),
    ))(i)
}

fn witness_utxo<Input, Error>(i: Input) -> IResult<Input, WitnessUtxo<Input>, Error>
where
    Input: for<'a> Compare<&'a [u8]>
        + Clone
        + InputTake
        + InputLength
        + InputIter<Item = u8>
        + Slice<core::ops::RangeFrom<usize>>,
    Error: ParseError<Input>,
    Error: ContextError<Input>,
    Error: FromExternalError<Input, TryFromIntError>,
{
    let amount = context("amount", le_u64);
    let script_pubkey = context(
        "script pubkey",
        length_value(
            context(
                "script pubkey length",
                map_res(compact_size, usize::try_from),
            ),
            rest,
        ),
    );

    map(tuple((amount, script_pubkey)), |(amount, script_pubkey)| {
        WitnessUtxo {
            amount,
            script_pubkey,
        }
    })(i)
}

fn tap_script_sig<Input, Error>(i: Input) -> IResult<Input, TaprootScriptSignature, Error>
where
    Input:
        Clone + PartialEq + InputLength + InputIter<Item = u8> + Slice<core::ops::RangeFrom<usize>>,
    Error: ParseError<Input> + FromExternalError<Input, secp256k1::Error>,
{
    let fields = tuple((x_only_public_key, taproot_leaf_hash));
    let mut parser = map(fields, |(x_only_public_key, leaf_hash)| {
        TaprootScriptSignature {
            x_only_public_key,
            leaf_hash,
        }
    });

    parser(i)
}

#[derive(Debug)]
pub struct InputMap<Input> {
    pub non_witness_utxo: Option<Transaction<Input>>,
    pub witness_utxo: Option<WitnessUtxo<Input>>,
    pub sighash_type: Option<u32>,
    pub redeem_script: Option<Input>,
    pub witness_script: Option<Input>,
    pub final_scriptsig: Option<Input>,
    pub final_scriptwitness: Option<Input>,
    pub por_commitment: Option<Input>,
    pub previous_txid: Option<Txid>,
    pub output_index: Option<u32>,
    pub sequence: Option<u32>,
    pub required_time_locktime: Option<u32>,
    pub required_height_locktime: Option<u32>,
    pub tap_key_sig: Option<schnorr::Signature>,
    pub tap_internal_key: Option<XOnlyPublicKey>,
    pub tap_merkle_root: Option<TapNodeHash>,
}

impl<Input> InputMap<Input> {
    pub fn sighash_type(&self) -> u32 {
        self.sighash_type.unwrap_or(SIGHASH_ALL)
    }
}

impl<Input> Default for InputMap<Input> {
    fn default() -> Self {
        Self {
            non_witness_utxo: None,
            witness_utxo: None,
            sighash_type: None,
            redeem_script: None,
            witness_script: None,
            final_scriptsig: None,
            final_scriptwitness: None,
            por_commitment: None,
            previous_txid: None,
            output_index: None,
            sequence: None,
            required_time_locktime: None,
            required_height_locktime: None,
            tap_key_sig: None,
            tap_internal_key: None,
            tap_merkle_root: None,
        }
    }
}

#[derive(Debug)]
enum KeyPair<Input> {
    NonWitnessUtxo(Transaction<Input>),
    WitnessUtxo(WitnessUtxo<Input>),
    PartialSig(PublicKey),
    SighashType(u32),
    RedeemScript(Input),
    WitnessScript(Input),
    Bip32Derivation(PublicKey, KeySource<Input>),
    FinalScriptsig(Input),
    FinalScriptwitness(Input),
    PorCommitment(Input),
    Ripemd160(ripemd160::Hash),
    Sha256(sha256::Hash),
    Hash160(hash160::Hash),
    Hash256(sha256d::Hash),
    PreviousTxid(Txid),
    OutputIndex(u32),
    Sequence(u32),
    RequiredTimeLocktime(u32),
    RequiredHeightLocktime(u32),
    TapKeySig(schnorr::Signature),
    TapScriptSig(TaprootScriptSignature, schnorr::Signature),
    TapLeafScript(Input, Input),
    TapBip32Derivation(XOnlyPublicKey, Input),
    TapInternalKey(XOnlyPublicKey),
    TapMerkleRoot(TapNodeHash),
}

#[derive(Debug)]
pub struct WitnessUtxo<Input> {
    pub amount: u64,
    pub script_pubkey: Input,
}
