// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Bitcoin BIP-32 implementation.
//!
//! This crate implements deserialization for Bitcoin BIP-32 data structures
//! using Nom parser combinators.

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]

use nom::number::complete::le_u32;
use secp256k1::PublicKey;

pub mod parser;

/// A fingerprint.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Fingerprint(pub [u8; 4]);

/// Extended public key.
///
/// This contains the key derivation information about a public key.
#[derive(Debug, Clone)]
pub struct Xpub {
    /// The version of the extended public key.
    pub version: [u8; 4],
    /// The depth of the extended public key.
    pub depth: u8,
    /// The fingerprint of the extended public key parent.
    pub parent_fingerprint: Fingerprint,
    /// The child number of the extended public key.
    pub child_number: u32,
    /// The chain code of the extended public key.
    pub chain_code: [u8; 32],
    /// The public key.
    pub public_key: PublicKey,
}

/// Borrowed buffer containing a derivation path encoded as little-endian
/// integers.
///
/// The intended use case for this type is to avoid creating a new buffer
/// to store the derivation path when parsing a Partially Signed Bitcoin
/// Transaction (PSBT).
///
/// The buffer contained in the type should be always valid.
#[derive(Debug, Clone)]
pub struct DerivationPathLe<Input> {
    buf: Input,
    len: usize,
}

impl<Input> DerivationPathLe<Input> {
    /// Returns the number of elements in the derivation path.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns an iterator over the elements of the derivation path.
    pub fn iter(&self) -> DerivationPathLeIter<Input>
    where
        Input: Clone,
    {
        DerivationPathLeIter {
            count: 0,
            len: self.len,
            buf: self.buf.clone(),
        }
    }
}

/// Iterator over the derivation path elements.
pub struct DerivationPathLeIter<Input> {
    count: usize,
    len: usize,
    buf: Input,
}

impl<Input> Iterator for DerivationPathLeIter<Input>
where
    Input: Clone
        + core::fmt::Debug
        + nom::InputLength
        + nom::InputIter<Item = u8>
        + nom::Slice<core::ops::RangeFrom<usize>>,
{
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count >= self.len {
            return None;
        }

        let (buf, item) = le_u32::<_, nom::error::Error<_>>(self.buf.clone())
            .expect("element should be valid at this point");
        self.buf = buf;

        Some(item)
    }
}

/// Information about an extended public key was derived.
#[derive(Debug)]
pub struct KeySource<Input> {
    /// Fingerprint of the master key.
    pub fingerprint: Fingerprint,
    /// Derivation path of the key.
    pub path: DerivationPathLe<Input>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_path_le_iteration() {
        const INPUT: &[u8] = &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80];

        let path = DerivationPathLe { buf: INPUT, len: 2 };

        let mut iter = path.iter();
        assert_eq!(iter.next(), Some(0));
        assert_eq!(iter.next(), Some(0x8000_0000));
    }
}
