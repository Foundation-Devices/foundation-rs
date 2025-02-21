// SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use bech32::primitives::segwit::MAX_STRING_LENGTH;
use core::{cmp::Ordering, fmt};

use nom::bytes::complete::tag;
use nom::error::ErrorKind;
use nom::Err;

use secp256k1::{PublicKey, Scalar, XOnlyPublicKey};

use foundation_bip32::{Fingerprint, KeySource, Xpriv};

use crate::{
    address,
    address::{AddressType, Network, RenderAddressError},
    parser::{global, global::GlobalMap, input, input::InputMap, output, output::OutputMap},
    transaction::SIGHASH_ALL,
};

use bitcoin_hashes::{hash160, sha256t, HashEngine};
use bitcoin_primitives::{TapTweakHash, TapTweakTag};

use heapless::{String, Vec};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionDetails {
    pub total_with_change: i64,
    pub total_change: i64,
}

impl TransactionDetails {
    /// Total amount sent to external wallets.
    pub fn total(&self) -> i64 {
        // This operation should always yield a positive number or zero as
        // total_change is less than or equal to total_with_change.
        (self.total_with_change - self.total_change).max(0)
    }

    /// Returns true if total amount spent is all change.
    pub fn is_self_send(&self) -> bool {
        self.total() == 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Validation progress percentage update.
    Progress(u64),
    /// Output address.
    OutputAddress {
        amount: i64,
        address: String<MAX_STRING_LENGTH>,
    },
    /// Change address.
    ChangeAddress {
        amount: i64,
        address: String<MAX_STRING_LENGTH>,
    },
}

pub fn validate<Input, C, F, E, const N: usize>(
    network: Network,
    i: Input,
    secp: &secp256k1::Secp256k1<C>,
    master_key: Xpriv,
    mut event_handler: F,
) -> Result<TransactionDetails, Error<E>>
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
    C: secp256k1::Signing + secp256k1::Verification,
    F: FnMut(Event),
    E: core::fmt::Debug
        + nom::error::ContextError<Input>
        + nom::error::ParseError<Input>
        + nom::error::FromExternalError<Input, secp256k1::Error>
        + nom::error::FromExternalError<Input, bitcoin_hashes::FromSliceError>
        + nom::error::FromExternalError<Input, core::num::TryFromIntError>,
{
    event_handler(Event::Progress(0));

    log::debug!("validating PSBT");

    let (i, _) = tag::<_, Input, E>(b"psbt\xff")(i)?;

    log::trace!("parsing global map");

    let (i, global_map) = global::global_map(|_, _| ())(i)?;

    let input_count = global_map.input_count().unwrap_or(0);
    let output_count = global_map.output_count().unwrap_or(0);
    log::debug!("input count #{}", input_count);
    log::debug!("output count #{}", output_count);

    let wallet_fingerprint = master_key.fingerprint(secp);
    log::debug!("wallet fingerprint {:?}", wallet_fingerprint);

    let total_items = input_count + output_count;
    let mut processed_items = 0;

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

        processed_items += 1;
        event_handler(Event::Progress((processed_items * 100) / total_items));
    }

    log::debug!("validating outputs");
    let mut total_with_change = 0;
    let mut total_change = 0;
    for output_index in 0..output_count {
        let input_ = input.clone();

        let master_key = master_key.clone();
        let mut output_keys: Vec<PublicKey, N> = Vec::new();
        let mut key_count = 0;
        let mut keys_error = Ok(());

        let result = {
            let output_keys = &mut output_keys;
            let key_count = &mut key_count;
            let keys_error = &mut keys_error;

            let collect_keys = move |key, source: KeySource<Input>| {
                log::debug!("collecting key {:?}", source.fingerprint);

                if keys_error.is_err() {
                    log::debug!("we failed to validate a previous key");
                    return;
                }

                if source.fingerprint == wallet_fingerprint {
                    log::debug!("matches our key");

                    let our_xpriv = master_key.derive_xpriv(secp, source.path.iter());
                    let our_public_key = PublicKey::from_secret_key(secp, &our_xpriv.private_key);
                    if key == our_public_key {
                        if let Err(_) = output_keys.push(key) {
                            *keys_error = Err(ValidationError::TooManyOutputKeys {
                                index: output_index,
                            });
                        }

                        *key_count += 1;
                    } else {
                        *keys_error = Err(ValidationError::FraudulentOutputPublicKey {
                            index: output_index,
                        });
                    }
                }
            };

            output::output_map(global_map.version, collect_keys, |_, _| {})(input_)
        };

        match result {
            Ok((i, txout)) => {
                if let Err(e) = keys_error {
                    return Err(Error::Validation(e));
                }

                let output_details = output_is_valid(
                    secp,
                    &global_map,
                    &txout,
                    &output_keys,
                    key_count,
                    output_index,
                )?;

                total_with_change += output_details.amount;
                if output_details.is_change {
                    total_change += output_details.amount;
                }

                let mut address = String::new();
                address::render(
                    network,
                    output_details.address_type,
                    &output_details.data,
                    &mut address,
                )?;

                if output_details.is_change {
                    log::debug!("rendered change address: {address}");
                    event_handler(Event::ChangeAddress {
                        amount: output_details.amount,
                        address,
                    })
                } else {
                    log::debug!("rendered output address: {address}");
                    event_handler(Event::OutputAddress {
                        amount: output_details.amount,
                        address,
                    })
                }

                input = i;
            }
            Err(Err::Error(e)) => return Err(Err::Error(E::append(i, ErrorKind::Count, e)).into()),
            Err(e) => return Err(e.into()),
        };

        processed_items += 1;
        event_handler(Event::Progress((processed_items * 100) / total_items));
    }

    log::debug!("total with total_change: {total_with_change} sats");
    log::debug!("total change: {total_change} sats");

    Ok(TransactionDetails {
        total_with_change,
        total_change,
    })
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

pub struct OutputDetails {
    /// The output amount, in satoshis.
    pub amount: i64,
    /// Is this a change output?
    pub is_change: bool,
    /// Address type.
    pub address_type: AddressType,
    /// Address data.
    pub data: Vec<u8, 35>,
}

/// Validate the output.
///
/// # Return
///
/// This function returns the `Ok()` if validation succeeds with
/// `amount` being the value in satoshis of this output.
pub fn output_is_valid<C, Input>(
    secp: &secp256k1::Secp256k1<C>,
    global_map: &GlobalMap<Input>,
    output_map: &OutputMap<Input>,
    our_keys: &[PublicKey],
    key_count: usize,
    index: u64,
) -> Result<OutputDetails, ValidationError>
where
    C: secp256k1::Verification,
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
    // This should be unreachable, make sure the code calling this is aware.
    if our_keys.len() < key_count {
        return Err(ValidationError::InternalError);
    }

    log::debug!("validating output #{index}");

    // Make sure we can convert u64 to usize, if not then we can't really
    // handle this transaction anyway.
    //
    // (And this would be highly unlikely to happen).
    let index_usize = match usize::try_from(index) {
        Ok(v) => v,
        Err(_) => return Err(ValidationError::TooManyOutputs),
    };

    // Retrieve the output from the already deserialized transaction or craft
    // it on PSBTv2 from the available data.
    //
    // This should never return None as the global_map and output_map parsers
    // make sure of it, but return an error in any case.
    let txout = match output_map.transaction_output(&global_map, index_usize) {
        Some(v) => v,
        None => return Err(ValidationError::MissingOutput { index }),
    };

    log::debug!("output amount: {} sats", txout.value);

    // Validate the address of the output, so, parse the scriptPubKey and
    // determine the type, this allows us to check that the scriptPubKey
    // matches our keys, so we need to determine the script type.
    //
    // Also used to render the address for the user interface.
    let (address_type, key) = match txout.address() {
        Some(v) => v,
        None => {
            return Err(ValidationError::UnknownOutputScript { index });
        }
    };

    // A normal spend, we can't really validate anything else.
    if our_keys.len() == 0 {
        return Ok(OutputDetails {
            amount: txout.value,
            is_change: false,
            address_type,
            data: key,
        });
    }

    log::debug!("output address type {:?}", address_type);

    match address_type {
        // Pay to Witness Public Key Hash.
        //
        // Public Key is always compressed.
        AddressType::P2WPKH => {
            if key_count != 1 {
                return Err(ValidationError::MultipleKeysNotExpected { index });
            }

            let pk = our_keys[0].serialize();
            let pkh = hash160::Hash::hash(&pk);
            if key != pkh.as_byte_array() {
                return Err(ValidationError::FraudulentOutputPublicKey { index });
            }

            log::debug!("public key hash matches");
        }
        // Pay to Public Key.
        //
        // Can be a compressed or uncompressed public key, not hashed.
        AddressType::P2PK => {
            if key_count != 1 {
                return Err(ValidationError::MultipleKeysNotExpected { index });
            }

            match key.len() {
                33 => {
                    let pk = our_keys[0].serialize();
                    if key != pk {
                        return Err(ValidationError::FraudulentOutputPublicKey { index });
                    }
                }
                65 => {
                    let pk = our_keys[0].serialize_uncompressed();
                    if key != pk {
                        return Err(ValidationError::FraudulentOutputPublicKey { index });
                    }
                }
                // This should be unreachable as the Output::address function constraints
                // the length.
                _ => {
                    return Err(ValidationError::InternalError);
                }
            }
        }
        AddressType::P2TR => {
            if key_count != 1 {
                return Err(ValidationError::MultipleKeysNotExpected { index });
            }

            // The tweaked key from the taproot output.
            let psbt_tweaked = {
                // Output::address already makes sure of this.
                debug_assert!(key.len() == 32);

                let mut psbt_tweaked_buf = [0; 32];
                psbt_tweaked_buf.copy_from_slice(&key);
                match XOnlyPublicKey::from_byte_array(&psbt_tweaked_buf) {
                    Ok(v) => v,
                    Err(_) => return Err(ValidationError::TaprootOutputInvalidPublicKey { index }),
                }
            };

            // Our derived internal key.
            let internal_key = our_keys[0].x_only_public_key().0;

            // Verify that PSBT provided internal key is the same as ours.
            if let Some(psbt_internal_key) = output_map.tap_internal_key {
                if internal_key.cmp(&psbt_internal_key) != Ordering::Equal {
                    return Err(ValidationError::FraudulentOutputPublicKey { index });
                }
            }

            // Calculate the tweak.
            let tweak = {
                let mut eng = sha256t::Hash::<TapTweakTag>::engine();
                eng.input(&internal_key.serialize());
                let inner = sha256t::Hash::<TapTweakTag>::from_engine(eng);
                let hash = TapTweakHash::from_byte_array(inner.to_byte_array());

                // Is the hash is out of range we can't do anything here.
                //
                // Should not happen, statistically.
                match Scalar::from_be_bytes(hash.to_byte_array()) {
                    Ok(v) => v,
                    Err(_) => return Err(ValidationError::InternalError),
                }
            };

            let tweaked = match internal_key.add_tweak(secp, &tweak) {
                Ok(v) => v.0,
                // The resulting key is invalid after adding the tweak.
                //
                // Should not happen, statistically.
                Err(_) => return Err(ValidationError::InternalError),
            };

            if psbt_tweaked.cmp(&tweaked) != Ordering::Equal {
                return Err(ValidationError::FraudulentOutputPublicKey { index });
            }
        }
        AddressType::P2SH => {
            let redeem_script = match &output_map.redeem_script {
                Some(v) => v,
                None => return Err(ValidationError::MissingRedeemWitnessScript { index }),
            };

            // Handle P2WPKH nested in P2SH.
            if redeem_script.input_len() == 22 {
                let mut iter = redeem_script.iter_elements();
                let b0 = iter.next();
                let b1 = iter.next();
                if b0 == Some(0x00) && b1 == Some(0x14) {
                    if key_count != 1 {
                        return Err(ValidationError::MultipleKeysNotExpected { index });
                    }

                    let nested_pkh = redeem_script.slice(2..22);

                    let pk = our_keys[0].serialize();
                    let pkh = hash160::Hash::hash(&pk);
                    if nested_pkh.compare(pkh.as_ref()) != nom::CompareResult::Ok {
                        return Err(ValidationError::FraudulentOutputPublicKey { index });
                    }

                    // TODO: HASH160 of redeem script and compare with key.
                }
            }

            // TODO: Multisig
        }
        // TODO: Other address types.
        _ => {
            return Err(ValidationError::UnknownOutputScript { index });
        }
    }

    Ok(OutputDetails {
        amount: txout.value,
        is_change: true,
        address_type,
        data: key,
    })
}

#[derive(Debug, Clone)]
pub enum Error<E> {
    Parse(nom::Err<E>),
    Validation(ValidationError),
    AddressRender(RenderAddressError),
}

impl<E> From<nom::Err<E>> for Error<E> {
    fn from(value: nom::Err<E>) -> Self {
        Self::Parse(value)
    }
}

impl<E> From<ValidationError> for Error<E> {
    fn from(value: ValidationError) -> Self {
        Self::Validation(value)
    }
}

impl<E> From<RenderAddressError> for Error<E> {
    fn from(e: RenderAddressError) -> Self {
        Self::AddressRender(e)
    }
}

impl<E: fmt::Debug> fmt::Display for Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Parse(e) => fmt::Display::fmt(e, f),
            Error::Validation(e) => write!(f, "validation error: {e}"),
            Error::AddressRender(e) => write!(f, "failed to render output address: {e}"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ValidationError {
    InternalError,
    InvalidWitnessScript,
    InvalidRedeemScript,
    UnsupportedSighash,
    TxidMismatch,
    MissingPreviousTxid,
    /// Redeem/Witness script missing for P2SH output.
    MissingRedeemWitnessScript {
        index: u64,
    },
    /// The x-only public key of the taproot output `{index}` is not valid.
    TaprootOutputInvalidPublicKey {
        index: u64,
    },
    TooManyOutputs,
    TooManyOutputKeys {
        index: u64,
    },
    /// The PSBT output `{index}` specified more keys than necessary for a
    /// given output script.
    ///
    /// For example, providing 2 keys in the PSBT output while the
    /// scriptPubKey is actually P2PK, P2PKH, P2WPKH, etc.
    MultipleKeysNotExpected {
        index: u64,
    },
    /// The output number `{index}` contains a fraudulent public key.
    ///
    /// For example, uses our fingerprint but the public key we calculate
    /// does not match the one provided by the PSBT.
    FraudulentOutputPublicKey {
        index: u64,
    },
    MissingOutput {
        index: u64,
    },
    UnknownOutputScript {
        index: u64,
    },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::InternalError => write!(f, "internal error"),
            ValidationError::InvalidWitnessScript => write!(f, "invalid witness script"),
            ValidationError::InvalidRedeemScript => write!(f, "invalid redeem script"),
            ValidationError::UnsupportedSighash => write!(f, "unsupported sighash"),
            ValidationError::TxidMismatch => write!(f, "TXID mismatch"),
            ValidationError::MissingPreviousTxid => write!(f, "missing previous TXID"),
            ValidationError::MissingRedeemWitnessScript { index } => {
                write!(f, "missing redeem/witness script for output {index}")
            }
            ValidationError::TaprootOutputInvalidPublicKey { index } => {
                write!(f, "x-only public key of taproot output {index} is invalid")
            }
            ValidationError::TooManyOutputs => write!(
                f,
                "there's more outputs in this transaction than the system can handle"
            ),
            ValidationError::TooManyOutputKeys { index } => write!(
                f,
                "there's more keys in output {index} in this transaction than the system can handle"
            ),
            ValidationError::MultipleKeysNotExpected { index } => write!(
                f,
                "there's more keys in output {index} than the descriptor specifies"
            ),
            ValidationError::FraudulentOutputPublicKey { index } => {
                write!(f, "output {index} is fraudulent, public keys don't match",)
            }
            ValidationError::MissingOutput { index } => write!(f, "missing output {index}"),
            ValidationError::UnknownOutputScript { index } => write!(
                f,
                "could not determine script type the of output number {index}"
            ),
        }
    }
}
