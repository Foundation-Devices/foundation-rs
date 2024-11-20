// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use core::fmt;

use nom::bytes::complete::tag;
use nom::error::ErrorKind;
use nom::Err;

use secp256k1::PublicKey;

use foundation_bip32::{Fingerprint, KeySource, Xpriv};

use crate::{
    parser::{global, global::GlobalMap, input, input::InputMap, output, output::OutputMap},
    transaction::SIGHASH_ALL,
};

use heapless::Vec;

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
        + nom::Slice<core::ops::Range<usize>>
        + nom::Slice<core::ops::RangeFrom<usize>>,
    C: secp256k1::Signing,
    E: core::fmt::Debug
        + nom::error::ContextError<Input>
        + nom::error::ParseError<Input>
        + nom::error::FromExternalError<Input, secp256k1::Error>
        + nom::error::FromExternalError<Input, bitcoin_hashes::FromSliceError>,
{
    log::debug!("validating PSBT");

    let (i, _) = tag::<_, Input, E>(b"psbt\xff")(i)?;
    let (i, global_map) = global::global_map(|_, _| ())(i)?;

    let input_count = global_map.input_count().unwrap_or(0);
    let output_count = global_map.output_count().unwrap_or(0);
    log::debug!("input count #{}", input_count);
    log::debug!("output count #{}", output_count);

    let wallet_fingerprint = master_key.fingerprint(secp);
    log::debug!("wallet fingerprint {:?}", wallet_fingerprint);

    log::debug!("validating inputs");
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

    log::debug!("validating outputs");
    for output_index in 0..output_count {
        let input_ = input.clone();

        let mut output_keys: Vec<PublicKey, 10> = Vec::new();

        let collect_keys = move |key, source: KeySource<Input>| {
            log::debug!("collecting key (fingerprint {:?})", source.fingerprint);

            if source.fingerprint == wallet_fingerprint {
                output_keys.push(key).ok();
            }
        };

        match output::output_map(global_map.version, collect_keys)(input_) {
            Ok((i, txout)) => {
                output_is_valid(&global_map, &txout, output_index)?;

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
    log::debug!("validating input");

    // TODO(jeandudey): For the future, we should not be doing any script
    // validation here, this instead should be parsed properly and validated
    // properly at parsing time.
    //
    // We do this because this was the way we did it in Passport.
    //
    // Doing validation would require using libbitcoinscript though.

    if let Some(ref script) = map.witness_script {
        if script.iter_elements().nth(1).filter(|&v| v >= 30).is_none() {
            return Err(ValidationError::InvalidWitnessScript);
        }
    } else {
        log::debug!("no witness script");
    }

    if let Some(ref script) = map.redeem_script {
        if script.iter_elements().nth(1).filter(|&v| v >= 22).is_none() {
            return Err(ValidationError::InvalidRedeemScript);
        }
    } else {
        log::debug!("no redeem script");
    }

    // In the future we may others.
    if map.sighash_type() != SIGHASH_ALL {
        return Err(ValidationError::UnsupportedSighash);
    }

    // FIXME: Check for set of signatures to see if input is completely signed?

    // Validate the UTXO against the provided TXID if present.
    //
    // This avoids signing an un-related UTXO.
    match (psbt_version, &map.non_witness_utxo, map.previous_txid) {
        (n, Some(utxo), Some(previous_txid)) if n >= 2 => {
            if utxo.txid() != previous_txid {
                return Err(ValidationError::TxidMismatch);
            } else {
                log::debug!("TXID of UTXO matches the one calculated");
            }
        }
        (n, _, None) if n >= 2 => {
            return Err(ValidationError::MissingPreviousTxid);
        }
        // If on PSBTv1 don't check for previous TXID as there's no previous
        // TXID field, can be only calculated from non_witness_utxo.
        _ => (),
    }

    log::debug!("input is valid!");

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
        log::debug!("input derivation validation");
        if source.fingerprint == wallet_fingerprint {}
    }
}

pub fn output_is_valid<Input>(
    global_map: &GlobalMap<Input>,
    output_map: &OutputMap<Input>,
    index: u64,
) -> Result<(), ValidationError>
where
    Input: for<'a> nom::Compare<&'a [u8]>
        + Clone
        + PartialEq
        + core::fmt::Debug
        + nom::InputTake
        + nom::InputIter<Item = u8>
        + nom::InputLength
        + nom::Slice<core::ops::Range<usize>>
        + nom::Slice<core::ops::RangeFrom<usize>>,
{
    log::debug!("validating output #{index}");

    // Make sure we can convert u64 to usize, if not then we can't really
    // handle this transaction anyway.
    //
    // (And this would be highly unlikely to happen).
    let index_usize = match usize::try_from(index) {
        Ok(v) => v,
        Err(_) => return Err(ValidationError::TooManyOutputs),
    };

    // Retrieve the output from the unserialized transaction or craft it
    // on PSBTv2 from the available data.
    //
    // This should never return None as the global_map and output_map parsers
    // make sure of it, but return an error in any case.
    let txout = match output_map.transaction_output(&global_map, index_usize) {
        Some(v) => v,
        None => return Err(ValidationError::MissingOutput { index }),
    };

    // Validate the address of the output, so, parse the scriptPubKey and
    // determine the type, this allows us to check that the scriptPubKey
    // matches our keys, so we need to determine the script type.
    let _ = match txout.address() {
        Some(v) => v,
        None => {
            return Err(ValidationError::UnknownOutputScript { index });
        }
    };

    // TODO: Verify here that it matches our keys.

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

impl<E: fmt::Debug> fmt::Display for Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::ParseError(e) => fmt::Display::fmt(e, f),
            Error::ValidationError(e) => write!(f, "validation error: {e}"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ValidationError {
    InvalidWitnessScript,
    InvalidRedeemScript,
    UnsupportedSighash,
    TxidMismatch,
    MissingPreviousTxid,
    TooManyOutputs,
    MissingOutput { index: u64 },
    UnknownOutputScript { index: u64 },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::InvalidWitnessScript => write!(f, "invalid witness script"),
            ValidationError::InvalidRedeemScript => write!(f, "invalid redeem script"),
            ValidationError::UnsupportedSighash => write!(f, "unsupported sighash"),
            ValidationError::TxidMismatch => write!(f, "TXID mismatch"),
            ValidationError::MissingPreviousTxid => write!(f, "missing previous TXID"),
            ValidationError::TooManyOutputs => write!(
                f,
                "there's more outputs in this transaction than the system can handle"
            ),
            ValidationError::MissingOutput { index } => write!(f, "missing output {index}"),
            ValidationError::UnknownOutputScript { index } => write!(
                f,
                "could not determine script type the of output number {index}"
            ),
        }
    }
}
