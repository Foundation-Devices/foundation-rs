// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use bitcoin_hashes::Hash;
use embedded_io::Write;

use crate::address::AddressType;
use crate::encoder::{
    hash_engine::HashEngine,
    transaction::{encode_inputs, encode_outputs},
};
use crate::hash_types::Txid;

/// A raw segwit bitcoin transaction.
#[derive(Debug, Clone)]
pub struct SegwitTransaction<I> {
    /// Version of the transaction.
    pub version: i32,
    /// The inputs of the transaction.
    pub inputs: Inputs<I>,
    /// The outputs of the transaction.
    pub outputs: Outputs<I>,
    /// The witness structure serialized as bytes.
    pub script_witnesses: I,
    /// The lock time.
    pub lock_time: u32,
}

/// A raw bitcoin transaction.
#[derive(Debug, Clone)]
pub struct Transaction<I> {
    /// Version of the transaction.
    pub version: i32,
    /// The inputs of the transaction.
    pub inputs: Inputs<I>,
    /// The outputs of the transaction.
    pub outputs: Outputs<I>,
    /// The lock time.
    pub lock_time: u32,
}

impl<I> Transaction<I> {
    pub fn txid(&self) -> Txid
    where
        I: for<'a> nom::Compare<&'a [u8]>
            + Clone
            + PartialEq
            + core::fmt::Debug
            + nom::InputTake
            + nom::InputIter<Item = u8>
            + nom::InputLength
            + nom::Slice<core::ops::RangeFrom<usize>>,
    {
        let mut enc = HashEngine::from(Txid::engine());

        enc.write(&self.version.to_le_bytes()).unwrap();
        encode_inputs(&mut enc, &self.inputs).unwrap();
        encode_outputs(&mut enc, &self.outputs).unwrap();
        enc.write(&self.lock_time.to_le_bytes()).unwrap();

        Txid::from_engine(enc.into_inner())
    }
}

/// A transaction input.
#[derive(Debug)]
pub struct Input<I> {
    pub previous_output: OutputPoint,
    pub script_sig: I,
    pub sequence: u32,
}

/// A transaction output.
#[derive(Debug)]
pub struct Output<I> {
    /// Number of satoshis this output is worth.
    pub value: i64,
    /// Script with the conditions to spend this output.
    pub script_pubkey: I,
}

impl<I> Output<I>
where
    I: nom::InputLength,
    I: nom::InputIter<Item = u8>,
    I: nom::Slice<core::ops::Range<usize>>,
    I: nom::Slice<core::ops::RangeFrom<usize>>,
{
    // NOTE: This procedure is written in this way as to reduce accesses to
    // script_pubkey as much as possible as in Passport this means accessing
    // the storage device.
    //
    // So, written for performance, not readability. That is also the reason
    // of the nested ifs.
    pub fn address(&self) -> Option<(AddressType, I)> {
        let len = self.script_pubkey.input_len();
        let mut iter = self.script_pubkey.iter_elements();
        let b0 = iter.next();
        let b1 = iter.next();

        // P2WPKH (BIP-0141).
        //
        // 0x0014 and the rest is the RIPEMD-160 hash of the public key.
        if len == 22 && b0 == Some(0x00) && b1 == Some(0x14) {
            return Some((AddressType::P2WPKH, self.script_pubkey.slice(2..22)));
        }

        // P2WSH (BIP-0141).
        //
        // 0x0014 and the rest is the SHA-256 hash of the public key.
        if len == 34 && b0 == Some(0x00) && b1 == Some(0x20) {
            return Some((AddressType::P2WSH, self.script_pubkey.slice(2..34)));
        }

        // P2SH (BIP-16).
        if len == 23 && b0 == Some(0xA9) && b1 == Some(0x14) {
            let b22 = self.script_pubkey.slice(22..).iter_elements().nth(0);
            if b22 == Some(0x87) {
                return Some((AddressType::P2SH, self.script_pubkey.slice(2..22)));
            }
        }

        // P2PK.
        if (len == 25 || len == 67) && (b0 == Some(0x21) || b0 == Some(0x41)) {
            let blast = self.script_pubkey.slice(len - 1..).iter_elements().nth(0);
            if blast == Some(0xAC) {
                return Some((AddressType::P2PK, self.script_pubkey.slice(2..35)));
            }
        }

        let b2 = iter.next();

        // P2PKH.
        if len == 25 && b0 == Some(0x76) && b1 == Some(0xA9) && b2 == Some(0x14) {
            let b23 = self.script_pubkey.slice(23..).iter_elements().nth(0);
            if b23 == Some(0x88) {
                let b24 = self.script_pubkey.slice(24..).iter_elements().nth(0);
                if b24 == Some(0xAC) {
                    return Some((AddressType::P2PKH, self.script_pubkey.slice(3..23)));
                }
            }
        }

        None
    }
}

/// Points to the output of a transaction.
#[derive(Debug)]
pub struct OutputPoint {
    /// The transaction ID of the transaction holding the output to spend.
    pub hash: Txid,
    /// The output index number of the transaction to spend from the
    /// transaction.
    pub index: u32,
}

#[derive(Debug, Clone)]
pub struct Inputs<I> {
    pub(crate) len: u64,
    pub(crate) input: I,
}

impl<I> Inputs<I> {
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Returns an iterator over the [`Input`]s.
    pub fn iter(&self) -> InputsIter<I>
    where
        I: Clone,
    {
        InputsIter {
            count: 0,
            len: self.len,
            input: self.input.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct InputsIter<I> {
    count: u64,
    len: u64,
    input: I,
}

impl<I> Iterator for InputsIter<I>
where
    I: for<'a> nom::Compare<&'a [u8]>
        + Clone
        + PartialEq
        + core::fmt::Debug
        + nom::InputTake
        + nom::InputIter<Item = u8>
        + nom::InputLength
        + nom::Slice<core::ops::RangeFrom<usize>>,
{
    type Item = Input<I>;

    fn next(&mut self) -> Option<Self::Item> {
        use crate::parser::transaction;

        if self.count >= self.len {
            return None;
        }

        let (next_input, input) = transaction::input::<I, nom::error::Error<I>>(self.input.clone())
            .expect("inputs iterator data should be valid at this point");
        self.input = next_input;
        self.count += 1;

        Some(input)
    }
}

#[derive(Debug, Clone)]
pub struct Outputs<I> {
    pub(crate) len: u64,
    pub(crate) input: I,
}

impl<I> Outputs<I> {
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Returns an iterator over the [`Output`]s.
    pub fn iter(&self) -> OutputsIter<I>
    where
        I: Clone,
    {
        OutputsIter {
            count: 0,
            len: self.len,
            input: self.input.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct OutputsIter<I> {
    count: u64,
    len: u64,
    input: I,
}

impl<I> Iterator for OutputsIter<I>
where
    I: for<'a> nom::Compare<&'a [u8]>
        + Clone
        + PartialEq
        + core::fmt::Debug
        + nom::InputTake
        + nom::InputIter<Item = u8>
        + nom::InputLength
        + nom::Slice<core::ops::RangeFrom<usize>>,
{
    type Item = Output<I>;

    fn next(&mut self) -> Option<Self::Item> {
        use crate::parser::transaction;

        if self.count >= self.len {
            return None;
        }

        let (next_input, output) =
            transaction::output::<I, nom::error::Error<I>>(self.input.clone())
                .expect("inputs iterator data should be valid at this point");
        self.input = next_input;
        self.count += 1;

        Some(output)
    }
}

pub const SIGHASH_ALL: u32 = 1;
