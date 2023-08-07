// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Nom combinators applying their child parser multiple times.
//!
//! This provides `alloc` free alternatives to some [`nom`] combinators.

// FIXME: Remove this code or send it to nom upstream cool code but we didn't use it.

use nom::{
    error::{ErrorKind, ParseError},
    Err, IResult, Parser, ToUsize,
};

/// Gets a number from the first parser, then applies the second parser that many
/// times calling `acc` to gather the results.
///
/// This is a non-`alloc` version of [`nom::multi::length_count`].
///
/// # Arguments
///
/// - `count`: The parser to apply to obtain the count from.
/// - `child_parser`: The parser to apply repeatedly.
/// - `init`: A function returning the initial value.
/// - `acc`: The accumulator function that will be repeatedly called with the
/// previous values and `child_parser` output.
///
/// # Notes
///
/// Consider contributing this to the [`nom`] crate.
pub fn length_count_fold<Input, Count, ChildParser, Output, N, Init, Accumulator, Error, Result>(
    mut count: Count,
    mut child_parser: ChildParser,
    mut init: Init,
    mut acc: Accumulator,
) -> impl FnMut(Input) -> IResult<Input, Result, Error>
where
    Input: Clone,
    Count: Parser<Input, N, Error>,
    ChildParser: Parser<Input, Output, Error>,
    N: ToUsize,
    Init: FnMut() -> Result,
    Accumulator: FnMut(Result, Output) -> Result,
    Error: ParseError<Input>,
{
    move |i: Input| {
        let (i, count) = count.parse(i)?;
        let mut input = i.clone();
        let mut res = init();

        for _ in 0..count.to_usize() {
            let input_ = input.clone();

            match child_parser.parse(input_) {
                Ok((i, o)) => {
                    res = acc(res, o);
                    input = i;
                }
                Err(Err::Error(e)) => {
                    return Err(Err::Error(Error::append(i, ErrorKind::Count, e)))
                }
                Err(e) => return Err(e),
            }
        }

        Ok((input, res))
    }
}

#[cfg(test)]
mod tests {
    use crate::parser::multi::length_count_fold;
    use nom::number::complete::u8;
    use nom::IResult;

    #[test]
    #[cfg(feature = "std")]
    fn length_count_fold_zero() {
        const INPUT: &[u8] = &[0];

        let mut parser = length_count_fold(u8, u8, || 0, |_, _| unreachable!());

        let res: IResult<_, _> = parser(INPUT);
        let (i, n) = res.unwrap();

        assert!(i.is_empty());
        assert_eq!(n, 0);
    }

    #[test]
    #[cfg(feature = "std")]
    fn length_count_fold_bytes() {
        const INPUT: &[u8] = &[5, 1, 2, 3, 4, 5];

        let mut parser = length_count_fold(
            u8,
            u8,
            || 0,
            |mut index, n| {
                index += 1;
                assert_eq!(INPUT[index], n);
                index
            },
        );

        let res: IResult<_, _> = parser(INPUT);
        let (i, n) = res.unwrap();
        assert!(i.is_empty());
        assert_eq!(n, INPUT.len() - 1);
    }
}
