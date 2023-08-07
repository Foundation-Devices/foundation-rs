// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Parser combinators for BIP-32 serialization formats.

use core::ops::RangeFrom;

use nom::{
    branch::alt,
    bytes::complete::tag,
    combinator::{map, verify},
    error::{ErrorKind, FromExternalError, ParseError},
    multi::{fill, many0_count},
    number::complete::{be_u32, le_u32, u8},
    sequence::tuple,
    Compare, Err, IResult, InputIter, InputLength, InputTake, Slice,
};
use secp256k1::PublicKey;

use crate::{DerivationPathLe, Fingerprint, KeySource, Xpub};

fn to_fixed_bytes<Input, const N: usize>(i: Input) -> [u8; N]
where
    Input: InputIter<Item = u8>,
{
    let mut slice = [0; N];
    for (i, byte) in i.iter_indices() {
        slice[i] = byte;
    }
    slice
}

fn bitcoin_mainnet_xpub<Input, Error>(i: Input) -> IResult<Input, Input, Error>
where
    Input: for<'a> Compare<&'a [u8]> + InputTake + Clone,
    Error: ParseError<Input>,
{
    let tag = tag::<_, Input, Error>;

    let xpub = tag(&[0x04, 0x88, 0xb2, 0x1e]);
    let ypub = tag(&[0x04, 0x9d, 0x7c, 0xb2]);
    let zpub = tag(&[0x04, 0xb2, 0x47, 0x46]);
    let multisig_ypub = tag(&[0x02, 0x95, 0xb4, 0x3f]); // Ypub
    let multisig_zpub = tag(&[0x02, 0xaa, 0x7e, 0xd3]); // Zpub

    let mut parser = alt((xpub, ypub, zpub, multisig_ypub, multisig_zpub));
    parser(i)
}

fn bitcoin_testnet_xpub<Input, Error>(i: Input) -> IResult<Input, Input, Error>
where
    Input: for<'a> Compare<&'a [u8]> + InputTake + Clone,
    Error: ParseError<Input>,
{
    let tag = tag::<_, Input, Error>;

    let tpub = tag(&[0x04, 0x35, 0x87, 0xcf]);
    let upub = tag(&[0x04, 0x4a, 0x52, 0x62]);
    let vpub = tag(&[0x04, 0x5f, 0x1c, 0xf6]);
    let multisig_upub = tag(&[0x02, 0x42, 0x89, 0xef]); // Upub
    let multisig_vpub = tag(&[0x02, 0x57, 0x54, 0x83]); // Vpub

    let mut parser = alt((tpub, upub, vpub, multisig_upub, multisig_vpub));
    parser(i)
}

fn xpub_version<Input, Error>(i: Input) -> IResult<Input, [u8; 4], Error>
where
    Input: for<'a> Compare<&'a [u8]> + InputTake + Clone + InputIter<Item = u8>,
    Error: ParseError<Input>,
{
    let bitcoin_xpub = alt((
        bitcoin_mainnet_xpub::<Input, Error>,
        bitcoin_testnet_xpub::<Input, Error>,
    ));

    let mut version = map(bitcoin_xpub, to_fixed_bytes::<Input, 4>);

    version(i)
}

/// Parse an extended public key.
pub fn xpub<Input, Error>(i: Input) -> IResult<Input, Xpub, Error>
where
    Input: for<'a> Compare<&'a [u8]>
        + PartialEq
        + InputTake
        + Clone
        + InputIter<Item = u8>
        + InputLength
        + Slice<RangeFrom<usize>>,
    Error: ParseError<Input>,
    Error: FromExternalError<Input, secp256k1::Error>,
{
    let depth = u8;
    let child_number = be_u32;

    let parser = tuple((
        xpub_version,
        depth,
        fingerprint,
        child_number,
        chain_code,
        public_key,
    ));

    let parser = map(
        parser,
        |(version, depth, parent_fingerprint, child_number, chain_code, public_key)| Xpub {
            version,
            depth,
            parent_fingerprint,
            child_number,
            chain_code,
            public_key,
        },
    );

    let mut parser = verify(parser, |key| {
        // When the depth is 0 (master key) the parent fingerprint should be 0 and
        // child number should be 0 as well as it doesn't apply here.
        if key.depth == 0
            && (key.parent_fingerprint != Fingerprint([0; 4]) || key.child_number != 0)
        {
            false
        } else {
            true
        }
    });

    parser(i)
}

/// Parse a BIP-32 derivation path encoded as little-endian 32-bit unsigned
/// integers.
///
/// `<derivation_path_le> := <le_u32>*`
pub fn derivation_path_le<Input, Error>(
    input: Input,
) -> IResult<Input, DerivationPathLe<Input>, Error>
where
    Input: Clone + Slice<RangeFrom<usize>> + InputIter<Item = u8> + InputLength,
    Error: ParseError<Input>,
{
    let (next_input, len) = many0_count(le_u32)(input.clone())?;
    Ok((next_input, DerivationPathLe { buf: input, len }))
}

/// Parses a BIP-32 fingerprint.
pub fn fingerprint<Input, Error>(i: Input) -> IResult<Input, Fingerprint, Error>
where
    Input: PartialEq + Clone + Slice<RangeFrom<usize>> + InputIter<Item = u8> + InputLength,
    Error: ParseError<Input>,
{
    let mut buf = [0; 4];
    let (i, ()) = fill(u8, &mut buf)(i)?;
    Ok((i, Fingerprint(buf)))
}

/// Parses a BIP-32 chain code.
pub fn chain_code<Input, Error>(i: Input) -> IResult<Input, [u8; 32], Error>
where
    Input: PartialEq + Clone + Slice<RangeFrom<usize>> + InputIter<Item = u8> + InputLength,
    Error: ParseError<Input>,
{
    let mut buf = [0; 32];
    let (i, ()) = fill(u8, &mut buf)(i)?;
    Ok((i, buf))
}

/// Parses a [`secp256k1`] compressed [`secp256k1::PublicKey`].
pub fn public_key<Input, Error>(i: Input) -> IResult<Input, PublicKey, Error>
where
    Input: PartialEq + Clone + Slice<RangeFrom<usize>> + InputIter<Item = u8> + InputLength,
    Error: ParseError<Input> + FromExternalError<Input, secp256k1::Error>,
{
    let mut buf = [0; 33];
    let (next_i, ()) = fill(u8, &mut buf)(i.clone())?;
    let p = PublicKey::from_slice(&buf)
        .map_err(|e| Err::Failure(Error::from_external_error(i, ErrorKind::Fail, e)))?;
    Ok((next_i, p))
}

/// Parses a [`KeySource`].
pub fn key_source<Input, Error>(i: Input) -> IResult<Input, KeySource<Input>, Error>
where
    Input: PartialEq + Clone + Slice<RangeFrom<usize>> + InputIter<Item = u8> + InputLength,
    Error: ParseError<Input>,
{
    let fields = tuple((fingerprint, derivation_path_le));
    let mut parser = map(fields, |(fingerprint, path)| KeySource {
        fingerprint,
        path,
    });
    parser(i)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "std")]
    fn parse_test_vectors() {
        let vectors = foundation_test_vectors::bip32::TestVectors::new();

        for test_vector in vectors.valid {
            println!("Test vector: {}", test_vector.name);
            for chain in &test_vector.chains {
                let buf = chain.xpub.as_slice();
                xpub::<_, nom::error::Error<_>>(buf).unwrap();
            }
        }
    }

    #[test]
    #[cfg(feature = "std")]
    fn parse_invalid_test_vectors() {
        let vectors = foundation_test_vectors::bip32::TestVectors::new();

        for test_vector in vectors.invalid {
            println!("Test vector: {}", test_vector.name);
            for (i, key) in test_vector.extended_keys.iter().enumerate() {
                println!("Index: {}", i);
                xpub::<_, nom::error::Error<_>>(key.as_slice()).unwrap_err();
            }
        }
    }

    #[test]
    fn parse_derivation_path_le() {
        const INPUT: &[u8] = &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80];

        let (i, path) = derivation_path_le::<_, nom::error::Error<_>>(INPUT).unwrap();
        assert!(i.is_empty());
        assert_eq!(path.buf, INPUT);
    }

    #[test]
    fn parse_key_source() {
        const INPUT: &[u8] = &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xEE, 0xFF, 0xFF];

        let (i, source) = key_source::<_, nom::error::Error<_>>(INPUT).unwrap();
        assert!(i.is_empty());
        assert_eq!(source.fingerprint, Fingerprint([0xAA, 0xBB, 0xCC, 0xDD]));
        assert_eq!(source.path.iter().next().unwrap(), 0xFFFF_EEEE);
    }
}
