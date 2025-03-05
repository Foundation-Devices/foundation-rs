// SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use core::num::TryFromIntError;
use core::ops::RangeFrom;

use bitcoin_hashes::{hash160, ripemd160, sha256, sha256d};

use nom::{
    bytes::complete::tag,
    combinator::{map, rest},
    error::{ContextError, ErrorKind, FromExternalError, ParseError},
    number::complete::le_u32,
    sequence::tuple,
    Compare, Err, IResult, InputIter, InputLength, InputTake, Slice,
};

use secp256k1::{PublicKey, XOnlyPublicKey};

use foundation_bip32::{
    parser::{key_source, public_key},
    KeySource,
};

use bitcoin_primitives::{TapNodeHash, Txid};

use crate::{
    parser::{
        global::GlobalMap,
        hash::{hash160, ripemd160, sha256, sha256d, taproot_leaf_hash, taproot_node_hash, txid},
        keypair::{key, value},
        secp::x_only_public_key,
        transaction::{output, transaction},
    },
    taproot::TaprootScriptSignature,
    transaction,
    transaction::{Transaction, SIGHASH_ALL},
};

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

            let key_pair = match input_key_pair()(i_.clone()) {
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
                KeyPair::PartialSig(_, _) => (), // TODO
                KeyPair::SighashType(v) => insert(&mut map.sighash_type, v, i_)?,
                KeyPair::RedeemScript(v) => insert(&mut map.redeem_script, v, i_)?,
                KeyPair::WitnessScript(v) => insert(&mut map.witness_script, v, i_)?,
                KeyPair::Bip32Derivation(p, s) => bip32_derivation(p, s),
                KeyPair::FinalScriptsig(v) => insert(&mut map.final_scriptsig, v, i_)?,
                KeyPair::FinalScriptwitness(v) => insert(&mut map.final_scriptwitness, v, i_)?,
                KeyPair::PorCommitment(v) => insert(&mut map.por_commitment, v, i_)?,
                KeyPair::Ripemd160(_, _) => (), // TODO
                KeyPair::Sha256(_, _) => (),    // TODO
                KeyPair::Hash160(_, _) => (),   // TODO
                KeyPair::Hash256(_, _) => (),   // TODO
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

fn input_key_pair<Input, Error>() -> impl FnMut(Input) -> IResult<Input, KeyPair<Input>, Error>
where
    Input: Clone
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
    move |i| {
        let (i, (key, keydata)) = key(i)?;

        match key {
            0x00 => map(value(transaction), KeyPair::NonWitnessUtxo)(i),
            0x01 => map(value(output), KeyPair::WitnessUtxo)(i),
            0x02 => {
                let (_, pk) = public_key(keydata)?;
                let (i, sig) = value(rest)(i)?;

                Ok((i, KeyPair::PartialSig(pk, sig)))
            }
            0x03 => map(value(le_u32), KeyPair::SighashType)(i),
            0x04 => map(value(rest), KeyPair::RedeemScript)(i),
            0x05 => map(value(rest), KeyPair::WitnessScript)(i),
            0x06 => {
                let (_, pk) = public_key(keydata)?;
                let (i, source) = value(key_source)(i)?;

                Ok((i, KeyPair::Bip32Derivation(pk, source)))
            }
            0x07 => map(value(rest), KeyPair::FinalScriptsig)(i),
            0x08 => map(value(rest), KeyPair::FinalScriptwitness)(i),
            0x09 => map(value(rest), KeyPair::PorCommitment)(i),
            0x0a => {
                let (_, h) = ripemd160(keydata)?;
                let (i, preimage) = value(rest)(i)?;

                Ok((i, KeyPair::Ripemd160(h, preimage)))
            }
            0x0b => {
                let (_, h) = sha256(keydata)?;
                let (i, preimage) = value(rest)(i)?;

                Ok((i, KeyPair::Sha256(h, preimage)))
            }
            0x0c => {
                let (_, h) = hash160(keydata)?;
                let (i, preimage) = value(rest)(i)?;

                Ok((i, KeyPair::Hash160(h, preimage)))
            }
            0x0d => {
                let (_, h) = sha256d(keydata)?;
                let (i, preimage) = value(rest)(i)?;

                Ok((i, KeyPair::Hash256(h, preimage)))
            }
            0x0e => map(value(txid), KeyPair::PreviousTxid)(i),
            0x0f => map(value(le_u32), KeyPair::OutputIndex)(i),
            0x10 => map(value(le_u32), KeyPair::Sequence)(i),
            0x11 => map(value(le_u32), KeyPair::RequiredTimeLocktime)(i),
            0x12 => map(value(le_u32), KeyPair::RequiredHeightLocktime)(i),
            // TODO: Parse Schnorr signature.
            0x13 => map(value(rest), KeyPair::TapKeySig)(i),
            0x14 => {
                let (_, scriptsig) = tap_script_sig(keydata)?;
                let (i, sig) = value(rest)(i)?;

                Ok((i, KeyPair::TapScriptSig(scriptsig, sig)))
            }
            // TODO: Parse fields
            0x15 => {
                let (i, v) = value(rest)(i)?;
                Ok((i, KeyPair::TapLeafScript(keydata, v)))
            }
            // TODO: Parse value.
            0x16 => {
                let (_, pk) = x_only_public_key(keydata)?;
                let (i, v) = value(rest)(i)?;

                Ok((i, KeyPair::TapBip32Derivation(pk, v)))
            }
            0x17 => map(value(x_only_public_key), KeyPair::TapInternalKey)(i),
            0x18 => map(value(taproot_node_hash), KeyPair::TapMerkleRoot)(i),
            _ => todo!(),
        }
    }
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
    pub witness_utxo: Option<transaction::Output<Input>>,
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
    pub tap_key_sig: Option<Input>,
    pub tap_internal_key: Option<XOnlyPublicKey>,
    pub tap_merkle_root: Option<TapNodeHash>,
}

impl<Input> InputMap<Input> {
    pub fn sighash_type(&self) -> u32 {
        self.sighash_type.unwrap_or(SIGHASH_ALL)
    }

    /// Return the output point for this input.
    pub fn output_point(
        &self,
        global: &GlobalMap<Input>,
        index: usize,
    ) -> Option<transaction::OutputPoint>
    where
        Input: core::fmt::Debug
            + Clone
            + PartialEq
            + InputTake
            + InputIter<Item = u8>
            + InputLength
            + Slice<RangeFrom<usize>>,
    {
        match global.version {
            0 => global.transaction.as_ref().and_then(|tx| {
                tx.inputs
                    .iter()
                    .nth(index)
                    .map(|i| i.previous_output.clone())
            }),
            2 => match (self.previous_txid, self.output_index) {
                (Some(hash), Some(index)) => Some(transaction::OutputPoint { hash, index }),
                _ => None,
            },
            _ => None,
        }
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
    WitnessUtxo(transaction::Output<Input>),
    PartialSig(PublicKey, Input),
    SighashType(u32),
    RedeemScript(Input),
    WitnessScript(Input),
    Bip32Derivation(PublicKey, KeySource<Input>),
    FinalScriptsig(Input),
    FinalScriptwitness(Input),
    PorCommitment(Input),
    Ripemd160(ripemd160::Hash, Input),
    Sha256(sha256::Hash, Input),
    Hash160(hash160::Hash, Input),
    Hash256(sha256d::Hash, Input),
    PreviousTxid(Txid),
    OutputIndex(u32),
    Sequence(u32),
    RequiredTimeLocktime(u32),
    RequiredHeightLocktime(u32),
    TapKeySig(Input),
    TapScriptSig(TaprootScriptSignature, Input),
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
