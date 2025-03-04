// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Parser combinators for BIP-32 serialization formats.

use core::ops::RangeFrom;

use nom::{
    character::complete::char,
    combinator::{map, opt, verify},
    error::{ErrorKind, FromExternalError, ParseError},
    multi::{fill, many0_count},
    number::complete::{be_u32, le_u32, u8},
    sequence::tuple,
    Err, IResult, InputIter, InputLength, Slice,
};
use secp256k1::{PublicKey, SecretKey};

use crate::{
    ChainCode, DerivationPathLe, Fingerprint, KeySource, Xpriv, Xpub, VERSION_MULTISIG_UPUB,
    VERSION_MULTISIG_VPUB, VERSION_MULTISIG_YPUB, VERSION_MULTISIG_ZPUB, VERSION_TPRV,
    VERSION_TPUB, VERSION_UPUB, VERSION_VPUB, VERSION_XPRV, VERSION_XPUB, VERSION_YPUB,
    VERSION_ZPUB,
};

fn xpub_version<Input, Error>(i: Input) -> IResult<Input, [u8; 4], Error>
where
    Input: PartialEq + Clone + InputLength + InputIter<Item = u8> + Slice<RangeFrom<usize>>,
    Error: ParseError<Input>,
{
    let mut buf = [0; 4];
    let (rest, _) = fill(u8, &mut buf)(i.clone())?;

    if buf != VERSION_XPUB
        && buf != VERSION_YPUB
        && buf != VERSION_ZPUB
        && buf != VERSION_MULTISIG_YPUB
        && buf != VERSION_MULTISIG_ZPUB
        && buf != VERSION_TPUB
        && buf != VERSION_UPUB
        && buf != VERSION_VPUB
        && buf != VERSION_MULTISIG_UPUB
        && buf != VERSION_MULTISIG_VPUB
    {
        return Err(Err::Failure(Error::from_error_kind(i, ErrorKind::Alt)));
    }

    Ok((rest, buf))
}

fn xprv_version<Input, Error>(i: Input) -> IResult<Input, [u8; 4], Error>
where
    Input: PartialEq + Clone + InputLength + InputIter<Item = u8> + Slice<RangeFrom<usize>>,
    Error: ParseError<Input>,
{
    let mut buf = [0; 4];
    let (rest, _) = fill(u8, &mut buf)(i.clone())?;

    if buf != VERSION_XPRV && buf != VERSION_TPRV {
        return Err(Err::Failure(Error::from_error_kind(i, ErrorKind::Alt)));
    }

    Ok((rest, buf))
}

/// Parse an extended public key.
pub fn xpub<Input, Error>(i: Input) -> IResult<Input, Xpub, Error>
where
    Input: PartialEq + Clone + InputIter<Item = u8> + InputLength + Slice<RangeFrom<usize>>,
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

/// Parse an extended private key.
pub fn xprv<Input, Error>(i: Input) -> IResult<Input, Xpriv, Error>
where
    Input: PartialEq + Clone + InputIter<Item = u8> + InputLength + Slice<RangeFrom<usize>>,
    Error: ParseError<Input>,
    Error: FromExternalError<Input, secp256k1::Error>,
{
    let depth = u8;
    let child_number = be_u32;

    let parser = tuple((
        xprv_version,
        depth,
        fingerprint,
        child_number,
        chain_code,
        secret_key,
    ));

    let parser = map(
        parser,
        |(version, depth, parent_fingerprint, child_number, chain_code, private_key)| Xpriv {
            version,
            depth,
            parent_fingerprint,
            child_number,
            chain_code,
            private_key,
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

/// Parse a BIP-32 derivation path child number string.
pub fn child_number<'a, Error>(i: &'a str) -> IResult<&'a str, u32, Error>
where
    Error: ParseError<&'a str>,
{
    let child_number = nom::character::complete::u32;
    let is_hardened = map(opt(char('\'')), |v| v.is_some());
    let mut parser = map(
        tuple((child_number, is_hardened)),
        |(child_number, is_hardened)| {
            if is_hardened {
                0x8000_0000 + child_number
            } else {
                child_number
            }
        },
    );

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
pub fn chain_code<Input, Error>(i: Input) -> IResult<Input, ChainCode, Error>
where
    Input: PartialEq + Clone + Slice<RangeFrom<usize>> + InputIter<Item = u8> + InputLength,
    Error: ParseError<Input>,
{
    let mut buf = [0; 32];
    let (i, ()) = fill(u8, &mut buf)(i)?;
    Ok((i, ChainCode(buf)))
}

/// Parses a [`secp256k1`] compressed [`secp256k1::PublicKey`].
pub fn public_key<Input, Error>(i: Input) -> IResult<Input, PublicKey, Error>
where
    Input: PartialEq + Clone + Slice<RangeFrom<usize>> + InputIter<Item = u8> + InputLength,
    Error: ParseError<Input> + FromExternalError<Input, secp256k1::Error>,
{
    let mut buf = [0; 33];
    let (rest, ()) = fill(u8, &mut buf)(i.clone())?;
    let p = PublicKey::from_slice(&buf)
        .map_err(|e| Err::Failure(Error::from_external_error(i, ErrorKind::Fail, e)))?;
    Ok((rest, p))
}

/// Parses a [`secp256k1::SecretKey`].
pub fn secret_key<Input, Error>(i: Input) -> IResult<Input, SecretKey, Error>
where
    Input: PartialEq + Clone + Slice<RangeFrom<usize>> + InputIter<Item = u8> + InputLength,
    Error: ParseError<Input> + FromExternalError<Input, secp256k1::Error>,
{
    let mut buf = [0; 33];
    let (rest, ()) = fill(u8, &mut buf)(i.clone())?;
    let p = SecretKey::from_slice(&buf[1..])
        .map_err(|e| Err::Failure(Error::from_external_error(i, ErrorKind::Fail, e)))?;
    Ok((rest, p))
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
