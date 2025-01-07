// SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use nom::{
    branch::alt,
    bytes::complete::tag,
    combinator::{cut, map, verify},
    error::ParseError,
    number::complete::{le_u16, le_u32, le_u64, u8},
    sequence::preceded,
    Compare, IResult, InputIter, InputLength, InputTake, Slice,
};

/// Parse a Bitcoin protocol variable length integer.
///
/// # Errors
///
/// This function will return an error if the encoded variable length integer
/// is not canonical, for example, if the value is specifying a bigger
/// encoding than actually needed, like using 9 bytes to store a value that
/// fits in 1 byte.
pub fn compact_size<I, E>(i: I) -> IResult<I, u64, E>
where
    I: for<'a> Compare<&'a [u8]>
        + Clone
        + InputTake
        + InputLength
        + InputIter<Item = u8>
        + Slice<core::ops::RangeFrom<usize>>,
    E: ParseError<I>,
{
    let tag = tag::<_, I, E>;

    let parse_u8 = map(u8, u64::from);
    let parse_u16 = preceded(
        tag(b"\xFD"),
        cut(verify(map(le_u16, u64::from), |&n| n > 0xFD)),
    );
    let parse_u32 = preceded(
        tag(b"\xFE"),
        cut(verify(map(le_u32, u64::from), |&n| n > 0xFFFF)),
    );
    let parse_u64 = preceded(
        tag(b"\xFF"),
        cut(verify(map(le_u64, u64::from), |&n| n > 0xFFFF_FFFF)),
    );
    let mut parser = alt((parse_u64, parse_u32, parse_u16, parse_u8));

    parser(i)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nom::error::Error;

    #[test]
    fn parse_compact_size() {
        assert_eq!(
            compact_size::<&'_ [u8], Error<_>>(&[0xFC]).unwrap(),
            (&[] as &[u8], 0xFC)
        );
        assert_eq!(
            compact_size::<&'_ [u8], Error<_>>(&[0xFD, 0xFF, 0xFF]).unwrap(),
            (&[] as &[u8], 0xFFFF)
        );
        assert_eq!(
            compact_size::<&'_ [u8], Error<_>>(&[0xFE, 0xFF, 0xFF, 0xFF, 0xFF]).unwrap(),
            (&[] as &[u8], 0xFFFF_FFFF)
        );
        assert_eq!(
            compact_size::<&'_ [u8], Error<_>>(&[
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
            ])
            .unwrap(),
            (&[] as &[u8], 0xFFFF_FFFF_FFFF_FFFF)
        );
    }

    #[test]
    #[should_panic]
    fn non_canonical_u16() {
        compact_size::<&'_ [u8], Error<_>>(&[0xFD, 0xFC, 0x00]).unwrap();
    }

    #[test]
    #[should_panic]
    fn non_canonical_u32() {
        compact_size::<&'_ [u8], Error<_>>(&[0xFE, 0xFF, 0xFF, 0x00, 0x00]).unwrap();
    }

    #[test]
    #[should_panic]
    fn non_canonical_u64() {
        compact_size::<&'_ [u8], Error<_>>(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00])
            .unwrap();
    }
}
