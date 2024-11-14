// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use nom::bytes::complete::tag;
use nom::error::ErrorKind;
use nom::Err;

use secp256k1::PublicKey;

use foundation_bip32::{Fingerprint, KeySource, Xpriv};

use crate::{
    parser::{global, input, input::InputMap, output, output::OutputMap},
    transaction::SIGHASH_ALL,
};

pub fn validate<Input, C, E>(
    i: Input,
    secp: &secp256k1::Secp256k1<C>,
    master_key: Xpriv,
) -> Result<(), Error<E>>
where
    Input: for<'a> nom::Compare<&'a [u8]>
        + core::fmt::Debug
        + Clone
        + PartialEq
        + nom::InputTake
        + nom::InputLength
        + nom::InputIter<Item = u8>
        + nom::Slice<core::ops::RangeFrom<usize>>,
    C: secp256k1::Signing,
    E: core::fmt::Debug
        + nom::error::ContextError<Input>
        + nom::error::ParseError<Input>
        + nom::error::FromExternalError<Input, secp256k1::Error>
        + nom::error::FromExternalError<Input, bitcoin_hashes::FromSliceError>,
{
    let (i, _) = tag::<_, Input, E>(b"psbt\xff")(i)?;
    let (i, global_map) = global::global_map(|_, _| ())(i)?;

    let input_count = global_map.input_count().unwrap_or(0);
    let output_count = global_map.output_count().unwrap_or(0);

    let wallet_fingerprint = master_key.fingerprint(secp);

    let mut input = i.clone();
    for _ in 0..input_count {
        let input_ = input.clone();

        match input::input_map(input_derivation_is_valid(wallet_fingerprint))(input_) {
            Ok((i, txin)) => {
                input_is_valid(&txin, global_map.version)?;

                input = i;
            }
            Err(Err::Error(e)) => return Err(Err::Error(E::append(i, ErrorKind::Count, e)).into()),
            Err(e) => return Err(e.into()),
        }
    }

    for _ in 0..output_count {
        let input_ = input.clone();

        match output::output_map(input_) {
            Ok((i, txout)) => {
                output_is_valid(&txout)?;

                input = i;
            }
            Err(Err::Error(e)) => return Err(Err::Error(E::append(i, ErrorKind::Count, e)).into()),
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}

pub fn input_is_valid<Input>(
    map: &InputMap<Input>,
    psbt_version: u32,
) -> Result<(), ValidationError>
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
    // FIXME: We should not be doing any script validation here, this instead
    // should be parsed properly and validated properly at parsing time.
    //
    // We do this because this was the way we did it in Passport.

    if let Some(ref script) = map.witness_script {
        // Equivalent to: script[1] < 30.
        if script.iter_elements().nth(1).filter(|&v| v >= 30).is_none() {
            return Err(ValidationError::InvalidWitnessScript);
        }
    }

    if let Some(ref script) = map.redeem_script {
        // Equivalent to: script[1] < 22.
        if script.iter_elements().nth(1).filter(|&v| v >= 22).is_none() {
            return Err(ValidationError::InvalidRedeemScript);
        }
    }

    if map.sighash_type() != SIGHASH_ALL {
        return Err(ValidationError::UnsupportedSighash);
    }

    // FIXME: Check for set of signatures to see if input is completely signed?

    // Validate the UTXO against the provided TXID if present.
    match (psbt_version, &map.non_witness_utxo, map.previous_txid) {
        (n, Some(utxo), Some(previous_txid)) if n >= 2 => {
            if utxo.txid() != previous_txid {
                return Err(ValidationError::TxidMismatch);
            }
        }
        (n, _, None) if n >= 2 => {
            return Err(ValidationError::MissingPreviousTxid);
        }
        // If on PSBTv1 don't check for previous TXID as it's only contained in the
        // non_witness_utxo field.
        _ => (),
    }

    Ok(())
}

pub fn input_derivation_is_valid<Input>(
    wallet_fingerprint: Fingerprint,
) -> impl FnMut(PublicKey, KeySource<Input>) {
    // FIXME(jeandudey): In the Passport code we only checked for the
    // fingerprint to be valid, we should also be checking for the
    // extended public key to match ours as well.
    //
    // I can't think of an attack or abuse here but might as well do it,
    // it can impact performance though.
    //
    // I see this being reconsidered when the BIP-0032 code supports
    // hardware acceleration.
    move |_public_key, source| {
        if source.fingerprint == wallet_fingerprint {}
    }
}

pub fn output_is_valid<Input>(_map: &OutputMap<Input>) -> Result<(), ValidationError>
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
    Ok(())
}

#[derive(Debug, Clone)]
pub enum Error<E> {
    ParseError(nom::Err<E>),
    ValidationError(ValidationError),
}

impl<E> From<nom::Err<E>> for Error<E> {
    fn from(value: nom::Err<E>) -> Self {
        Self::ParseError(value)
    }
}

impl<E> From<ValidationError> for Error<E> {
    fn from(value: ValidationError) -> Self {
        Self::ValidationError(value)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ValidationError {
    InvalidWitnessScript,
    InvalidRedeemScript,
    UnsupportedSighash,
    TxidMismatch,
    MissingPreviousTxid,
}
