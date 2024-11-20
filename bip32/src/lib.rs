// SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-FileCopyrightText: © 2024 The Rust Bitcoin Developers
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Based on the code from rust-bitcoin, adapted for no_std and zero-copy
// parsers.

//! Bitcoin BIP-32 implementation.
//!
//! This crate implements deserialization for Bitcoin BIP-32 data structures
//! using Nom parser combinators.

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]

use core::str::Split;

use bitcoin_hashes::{hash160, hash_newtype, sha512, Hash, HashEngine, Hmac, HmacEngine};
use nom::number::complete::le_u32;
use secp256k1::{PublicKey, Secp256k1, SecretKey};

pub mod parser;

/// xpub.
pub const VERSION_XPUB: [u8; 4] = [0x04, 0x88, 0xb2, 0x1e];
/// ypub.
pub const VERSION_YPUB: [u8; 4] = [0x04, 0x9d, 0x7c, 0xb2];
/// zpub.
pub const VERSION_ZPUB: [u8; 4] = [0x04, 0xb2, 0x47, 0x46];
/// Ypub.
pub const VERSION_MULTISIG_YPUB: [u8; 4] = [0x02, 0x95, 0xb4, 0x3f];
/// Zpub.
pub const VERSION_MULTISIG_ZPUB: [u8; 4] = [0x02, 0xaa, 0x7e, 0xd3];
/// xprv
pub const VERSION_XPRV: [u8; 4] = [0x04, 0x88, 0xAD, 0xE4];
/// tprv
pub const VERSION_TPRV: [u8; 4] = [0x04, 0x35, 0x83, 0x94];
/// tpub.
pub const VERSION_TPUB: [u8; 4] = [0x04, 0x35, 0x87, 0xcf];
/// upub.
pub const VERSION_UPUB: [u8; 4] = [0x04, 0x4a, 0x52, 0x62];
/// vpub.
pub const VERSION_VPUB: [u8; 4] = [0x04, 0x5f, 0x1c, 0xf6];
/// Upub.
pub const VERSION_MULTISIG_UPUB: [u8; 4] = [0x02, 0x42, 0x89, 0xef];
/// Vpub.
pub const VERSION_MULTISIG_VPUB: [u8; 4] = [0x02, 0x57, 0x54, 0x83];

/// A fingerprint.
#[derive(Debug, Default, Clone, Copy, Eq, PartialEq, Hash)]
pub struct Fingerprint(pub [u8; 4]);

impl TryFrom<&[u8]> for Fingerprint {
    type Error = InvalidFingerprintLen;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 4 {
            return Err(InvalidFingerprintLen);
        }

        let mut buf = [0; 4];
        buf.copy_from_slice(value);
        Ok(Self(buf))
    }
}

/// Error when converting from a byte slice to a [`Fingerprint`].
#[derive(Debug)]
pub struct InvalidFingerprintLen;

/// The chain code.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ChainCode(pub [u8; 32]);

impl ChainCode {
    fn from_hmac(hmac: Hmac<sha512::Hash>) -> Self {
        hmac[32..]
            .try_into()
            .expect("half of hmac is guaranteed to be 32 bytes")
    }
}

impl<I> core::ops::Index<I> for ChainCode
where
    [u8]: core::ops::Index<I>,
{
    type Output = <[u8] as core::ops::Index<I>>::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        &self.0[index]
    }
}

impl TryFrom<&[u8]> for ChainCode {
    type Error = InvalidChainCodeLen;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != 32 {
            return Err(InvalidChainCodeLen);
        }

        let mut buf = [0; 32];
        buf.copy_from_slice(value);
        Ok(Self(buf))
    }
}

/// Error when converting from a byte slice to a [`Fingerprint`].
#[derive(Debug)]
pub struct InvalidChainCodeLen;

hash_newtype! {
    /// Extended key identifier as defined in BIP-32.
    pub struct XKeyIdentifier(hash160::Hash);
}

/// Extended private key.
#[derive(Debug, Clone)]
pub struct Xpriv {
    /// The version of the extended public key.
    pub version: [u8; 4],
    /// The depth of the extended public key.
    pub depth: u8,
    /// The fingerprint of the extended public key parent.
    pub parent_fingerprint: Fingerprint,
    /// The child number of the extended public key.
    pub child_number: u32,
    /// The chain code of the extended public key.
    pub chain_code: ChainCode,
    /// The private key.
    pub private_key: SecretKey,
}

impl Xpriv {
    /// Construct a new master key from a seed value
    pub fn new_master(version: [u8; 4], seed: &[u8]) -> Result<Xpriv, secp256k1::Error> {
        let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(b"Bitcoin seed");
        hmac_engine.input(seed);
        let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);

        Ok(Xpriv {
            version,
            depth: 0,
            parent_fingerprint: Default::default(),
            child_number: 0,
            private_key: secp256k1::SecretKey::from_slice(&hmac_result[..32])?,
            chain_code: ChainCode::from_hmac(hmac_result),
        })
    }

    /// Attempts to derive an extended private key from a path.
    pub fn derive_xpriv<C: secp256k1::Verification, P: Iterator<Item = u32>>(
        &self,
        secp: &Secp256k1<C>,
        path: P,
    ) -> Xpriv {
        let mut sk: Xpriv = self.clone();
        for cnum in path {
            sk = sk.ckd_priv(secp, cnum);
        }
        sk
    }

    /// Private->Private child key derivation
    fn ckd_priv<C: secp256k1::Verification>(&self, secp: &Secp256k1<C>, i: u32) -> Xpriv {
        let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(&self.chain_code[..]);

        let is_hardened = i & (1 << 31) != 0;
        if !is_hardened {
            // Non-hardened key: compute public data and use that
            hmac_engine.input(
                &secp256k1::PublicKey::from_secret_key(secp, &self.private_key).serialize()[..],
            );
        } else {
            // Hardened key: use only secret data to prevent public derivation
            hmac_engine.input(&[0u8]);
            hmac_engine.input(&self.private_key[..]);
        }

        hmac_engine.input(&u32::to_be_bytes(i));
        let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);
        let sk = secp256k1::SecretKey::from_slice(&hmac_result[..32])
            .expect("statistically impossible to hit");
        let tweaked = sk
            .add_tweak(&self.private_key.into())
            .expect("statistically impossible to hit");

        Xpriv {
            version: self.version,
            depth: self.depth + 1,
            parent_fingerprint: self.fingerprint(secp),
            child_number: i,
            private_key: tweaked,
            chain_code: ChainCode::from_hmac(hmac_result),
        }
    }

    /// Returns the HASH160 of the public key belonging to the xpriv
    pub fn identifier<C: secp256k1::Signing>(&self, secp: &Secp256k1<C>) -> XKeyIdentifier {
        Xpub::from_priv(secp, self).identifier()
    }

    /// Returns the first four bytes of the identifier
    pub fn fingerprint<C: secp256k1::Signing>(&self, secp: &Secp256k1<C>) -> Fingerprint {
        self.identifier(secp)[0..4]
            .try_into()
            .expect("4 is the fingerprint length")
    }
}

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
    pub chain_code: ChainCode,
    /// The public key.
    pub public_key: PublicKey,
}

impl Xpub {
    /// Derives a public key from a private key
    pub fn from_priv<C: secp256k1::Signing>(secp: &Secp256k1<C>, sk: &Xpriv) -> Xpub {
        Xpub {
            version: sk.version,
            depth: sk.depth,
            parent_fingerprint: sk.parent_fingerprint,
            child_number: sk.child_number,
            public_key: secp256k1::PublicKey::from_secret_key(secp, &sk.private_key),
            chain_code: sk.chain_code.clone(),
        }
    }

    /// Attempts to derive a extended public key.
    pub fn derive_xpub<C: secp256k1::Verification, P: Iterator<Item = u32>>(
        &self,
        secp: &Secp256k1<C>,
        path: P,
    ) -> Xpub {
    }

    /// Compute the scalar tweak added to this key to get a child key
    pub fn ckd_pub_tweak(
        &self,
        i: u32,
    ) -> Result<(secp256k1::SecretKey, ChainCode), Error> {
        if i >= 0x8000_0000 {
            return Err(todo!());
        }

        let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(&self.chain_code[..]);
        hmac_engine.input(&self.public_key.serialize()[..]);
        hmac_engine.input(&i.to_be_bytes());

        let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);

        let private_key = secp256k1::SecretKey::from_slice(&hmac_result[..32])?;
        let chain_code = ChainCode::from_hmac(hmac_result);
        Ok((private_key, chain_code))
    }

    /// Public->Public child key derivation
    pub fn ckd_pub<C: secp256k1::Verification>(
        &self,
        secp: &Secp256k1<C>,
        i: ChildNumber,
    ) -> Result<Xpub, Error> {
        let (sk, chain_code) = self.ckd_pub_tweak(i)?;
        let tweaked = self.public_key.add_exp_tweak(secp, &sk.into())?;

        Ok(Xpub {
            network: self.network,
            depth: self.depth + 1,
            parent_fingerprint: self.fingerprint(),
            child_number: i,
            public_key: tweaked,
            chain_code,
        })
    }

    /// Returns the HASH160 of the chaincode
    pub fn identifier(&self) -> XKeyIdentifier {
        let mut engine = XKeyIdentifier::engine();
        engine.input(&self.public_key.serialize());
        XKeyIdentifier::from_engine(engine)
    }
}

/// Borrowed string containing a text derivation path.
pub struct DerivationPathStr<'a>(&'a str);

impl<'a> DerivationPathStr<'a> {
    /// Parse a derivation path.
    pub fn from_str(path: &'a str) -> Result<Self, ParseDerivationPathStringError> {
        let mut parts = path.split('/');

        // First parts must be `m`.
        if parts.next().unwrap() != "m" {
            return Err(ParseDerivationPathStringError);
        }

        for part in parts {
            if parser::child_number::<nom::error::Error<_>>(part).is_err() {
                return Err(ParseDerivationPathStringError);
            }
        }

        Ok(Self(path))
    }

    /// Return an iterator over this derivation path.
    pub fn iter(&self) -> DerivationPathStrIter {
        let mut iter = self.0.split('/');
        // Skip m.
        iter.next();
        DerivationPathStrIter(iter)
    }
}

/// Iterator over a text derivation path.
pub struct DerivationPathStrIter<'a>(Split<'a, char>);

impl<'a> Iterator for DerivationPathStrIter<'a> {
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|v| {
            parser::child_number::<nom::error::Error<_>>(v)
                .map(|(_i, v)| v)
                .expect("values in the iterator should be always valid")
        })
    }
}

/// Error that occurs when parsing a derivation path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseDerivationPathStringError;

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
