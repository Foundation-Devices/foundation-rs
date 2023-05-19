// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-FileCopyrightText: © 2020 Dominik Spicher <dominikspicher@gmail.com>
// SPDX-License-Identifier: MIT

//! Encode and decode byte payloads according to the [`bytewords`](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-012-bytewords.md) scheme.
//!
//! The [`bytewords`](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-012-bytewords.md) encoding
//! scheme defines three styles how byte payloads can be encoded.
//!
//! # Standard style
//! ```
//! use ur::bytewords::{decode, encode, Style};
//! let data = "Some bytes".as_bytes();
//! let encoded = encode(data, Style::Standard);
//! assert_eq!(
//!     encoded,
//!     "guru jowl join inch crux iced kick jury inch junk taxi aqua kite limp"
//! );
//! assert_eq!(data, decode(&encoded, Style::Standard).unwrap());
//! ```
//!
//! # URI style
//! ```
//! use ur::bytewords::{decode, encode, Style};
//! let data = "Some bytes".as_bytes();
//! let encoded = encode(data, Style::Uri);
//! assert_eq!(
//!     encoded,
//!     "guru-jowl-join-inch-crux-iced-kick-jury-inch-junk-taxi-aqua-kite-limp"
//! );
//! assert_eq!(data, decode(&encoded, Style::Uri).unwrap());
//! ```
//!
//! # Minimal style
//! ```
//! use ur::bytewords::{decode, encode, Style};
//! let data = "Some binary data".as_bytes();
//! let encoded = encode(data, Style::Minimal);
//! assert_eq!(encoded, "gujljnihcxidinjthsjpkkcxiehsjyhsnsgdmkht");
//! assert_eq!(data, decode(&encoded, Style::Minimal).unwrap());
//! ```

pub mod minicbor;

mod constants;

use crate::{
    bytewords::constants::{MINIMALS, MINIMAL_IDXS, WORDS, WORD_IDXS},
    CRC32,
};

use core::fmt;
use itertools::Either;

/// The three different `bytewords` encoding styles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum Style {
    /// Four-letter words, separated by spaces.
    Standard,
    /// Four-letter words, separated by dashes.
    Uri,
    /// Two-letter words, concatenated without separators.
    Minimal,
}

impl Style {
    const fn separator_str(self) -> &'static str {
        match self {
            Style::Standard => " ",
            Style::Uri => "-",
            _ => panic!("minimal style does not use separators"),
        }
    }
}

/// The different errors that can be returned when decoding.
#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Usually indicates a wrong encoding [`Style`] was passed.
    InvalidWord {
        /// Position where the invalid word was encountered.
        position: Option<usize>,
    },
    /// The CRC32 checksum doesn't validate.
    InvalidChecksum {
        /// The expected checksum from the last bytes of the bytewords string.
        expected: [u8; 4],
        /// The calculated checksum from the payload bytes of the bytewords string.
        calculated: [u8; 4],
    },
    /// The CRC32 checksum is not present.
    ChecksumNotPresent,
    /// Invalid bytewords string length.
    InvalidLength,
    /// The bytewords string contains non-ASCII characters.
    NonAscii,
    /// Not enough space to decode the bytewords into.
    NotEnoughSpace {
        /// Available space to decode the bytewords.
        available: usize,
        /// Needed space to decode the bytewords.
        needed: usize,
    },
}

impl<'a> fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::InvalidWord {
                position: Some(position),
            } => write!(f, "Invalid word found at position {position}"),
            DecodeError::InvalidWord { position: None } => write!(f, "Invalid word found"),
            DecodeError::InvalidChecksum {
                expected,
                calculated,
            } => write!(
                f,
                "Expected checksum '{}' is different than the calculated '{}'",
                u32::from_be_bytes(*expected),
                u32::from_be_bytes(*calculated)
            ),
            DecodeError::ChecksumNotPresent => write!(f, "Checksum is not present"),
            DecodeError::InvalidLength => write!(f, "Invalid length"),
            DecodeError::NonAscii => {
                write!(f, "Bytewords string contains non-ASCII characters")
            }
            DecodeError::NotEnoughSpace { needed, available } => {
                write!(f, "Not enough space to decode the bytewords, needed {needed} but only {available} bytes available")
            }
        }
    }
}

/// The errors that can be returned when encoding.
#[derive(Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// Not enough space to decode the bytewords into.
    NotEnoughSpace,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncodeError::NotEnoughSpace => {
                write!(f, "Not enough space to encode the bytewords into")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for EncodeError {}

/// Decodes a `bytewords`-encoded String back into a byte payload. The encoding
/// must contain a four-byte checksum.
///
/// # Examples
///
/// ```
/// use ur::bytewords::{decode, Style};
/// assert_eq!(
///     decode("able tied also webs lung", Style::Standard).unwrap(),
///     vec![0]
/// );
/// assert_eq!(
///     decode("able-tied-also-webs-lung", Style::Uri).unwrap(),
///     vec![0]
/// );
/// // Notice how the minimal encoding consists of the start and end letters of the bytewords
/// assert_eq!(decode("aetdaowslg", Style::Minimal).unwrap(), vec![0]);
/// ```
///
/// # Errors
///
/// If the encoded string contains unrecognized words, is inconsistent with
/// the provided `style`, or contains an invalid checksum, an error will be
/// returned.
#[cfg(feature = "alloc")]
pub fn decode(encoded: &str, style: Style) -> Result<alloc::vec::Vec<u8>, DecodeError> {
    let (bytes, expected_checksum) = decoder(encoded, style)?;
    let bytes = bytes
        .enumerate()
        .map(|(i, b)| b.ok_or(DecodeError::InvalidWord { position: Some(i) }))
        .collect::<Result<alloc::vec::Vec<u8>, _>>()?;

    let calculated_checksum = CRC32.checksum(&bytes).to_be_bytes();
    if calculated_checksum != expected_checksum {
        return Err(DecodeError::InvalidChecksum {
            expected: expected_checksum,
            calculated: calculated_checksum,
        });
    }

    Ok(bytes)
}

/// Try to validate a bytewords encoded string and calculate its length in
/// bytes.
pub fn validate(encoded: &str, style: Style) -> Result<usize, DecodeError> {
    let (bytes, expected_checksum) = decoder(encoded, style)?;
    let mut digest = CRC32.digest();

    let mut n = 0;
    for maybe_byte in bytes {
        digest.update(&[maybe_byte.ok_or(DecodeError::InvalidWord { position: Some(n) })?]);
        n += 1;
    }

    let calculated_checksum = digest.finalize().to_be_bytes();
    if calculated_checksum != expected_checksum {
        return Err(DecodeError::InvalidChecksum {
            expected: expected_checksum,
            calculated: calculated_checksum,
        });
    }

    Ok(n)
}

/// Decodes a `bytewords`-encoded string back into a byte payload onto an
/// existing slice. The encoding must contain a four-byte checksum.
///
/// If the return value of this method is `Ok(n)`, then `n` is the number of
/// bytes written into `result`.
///
/// # Errors
///
/// This function returns an error if the `bytewords`-encoded string is larger
/// than `result`.
pub fn decode_to_slice(
    encoded: &str,
    result: &mut [u8],
    style: Style,
) -> Result<usize, DecodeError> {
    let (mut bytes, expected_checksum) = decoder(encoded, style)?;

    let mut n = 0;
    while let Some(maybe_byte) = bytes.next() {
        if n >= result.len() {
            while let Some(maybe_byte) = bytes.next() {
                maybe_byte.ok_or(DecodeError::InvalidWord { position: Some(n) })?;

                n += 1;
            }

            return Err(DecodeError::NotEnoughSpace {
                available: result.len(),
                needed: n,
            });
        }

        result[n] = maybe_byte.ok_or(DecodeError::InvalidWord { position: Some(n) })?;
        n += 1;
    }

    let calculated_checksum = CRC32.checksum(&result[..n]).to_be_bytes();
    if calculated_checksum != expected_checksum {
        return Err(DecodeError::InvalidChecksum {
            expected: expected_checksum,
            calculated: calculated_checksum,
        });
    }

    Ok(n)
}

fn decoder(
    encoded: &str,
    style: Style,
) -> Result<(impl Iterator<Item = Option<u8>> + '_, [u8; 4]), DecodeError> {
    if !encoded.is_ascii() {
        return Err(DecodeError::NonAscii);
    }

    if encoded.is_empty() {
        return Err(DecodeError::ChecksumNotPresent);
    }

    let (keys, indexes) = match style {
        Style::Standard => (Either::Left(encoded.split(' ')), &WORD_IDXS),
        Style::Uri => (Either::Left(encoded.split('-')), &WORD_IDXS),
        Style::Minimal => {
            if encoded.len() % 2 != 0 {
                return Err(DecodeError::InvalidLength);
            }

            let keys = Either::Right(
                (0..encoded.len())
                    .step_by(2)
                    .map(|idx| &encoded[idx..idx + 2]),
            );

            (keys, &MINIMAL_IDXS)
        }
    };

    let mut bytes = keys.map(|k| indexes.get(k).copied());

    // Consume checksum bytes before anything else.
    let mut checksum = [0u8; 4];
    for b in checksum.iter_mut().rev() {
        match bytes.next_back() {
            Some(Some(byte)) => *b = byte,
            Some(None) => return Err(DecodeError::InvalidWord { position: None }),
            None => return Err(DecodeError::ChecksumNotPresent),
        }
    }

    Ok((bytes, checksum))
}

fn encoder<'a>(
    data: &'a [u8],
    checksum: &'a [u8],
    style: Style,
) -> impl Iterator<Item = &'static str> + 'a {
    let table = match style {
        Style::Standard | Style::Uri => &WORDS,
        Style::Minimal => &MINIMALS,
    };

    data.iter()
        .chain(checksum.iter())
        .map(|&b| table[b as usize])
}

/// Encodes a byte payload into a `bytewords` encoded String.
///
/// # Examples
///
/// ```
/// use ur::bytewords::{encode, Style};
/// assert_eq!(encode(&[0], Style::Standard), "able tied also webs lung");
/// assert_eq!(encode(&[0], Style::Uri), "able-tied-also-webs-lung");
/// // Notice how the minimal encoding consists of the start and end letters of the bytewords
/// assert_eq!(encode(&[0], Style::Minimal), "aetdaowslg");
/// ```
#[must_use]
#[cfg(feature = "alloc")]
pub fn encode(data: &[u8], style: Style) -> alloc::string::String {
    #[cfg(not(feature = "std"))]
    use alloc::string::ToString;

    Bytewords(data, style).to_string()
}

/// Encodes a byte payload into a `bytewords` encoded string on an existing slice.
///
/// The return value of this method is `n` and is the number of bytes written
/// into `result`.
pub fn encode_to_slice(data: &[u8], result: &mut [u8], style: Style) -> Result<usize, EncodeError> {
    let checksum = CRC32.checksum(data).to_be_bytes();

    let mut encoder = encoder(data, &checksum, style).map(|w| w.as_bytes());
    let mut n = 0;

    if style == Style::Minimal {
        for word in encoder {
            debug_assert!(word.len() == 2);

            if n >= result.len() {
                return Err(EncodeError::NotEnoughSpace);
            }
            result[n..n + 2].copy_from_slice(word);
            n += 2;
        }

        Ok(n)
    } else {
        let separator = match style {
            Style::Standard => b' ',
            Style::Uri => b'-',
            _ => unreachable!(),
        };

        if let Some(first_word) = encoder.next() {
            debug_assert!(first_word.len() == 4);

            result[0..4].copy_from_slice(first_word);
            n += 4;
        } else {
            return Ok(n);
        }

        for word in encoder {
            debug_assert!(word.len() == 4);

            if n + 5 >= result.len() {
                return Err(EncodeError::NotEnoughSpace);
            }

            result[n] = separator;
            result[n + 1..n + 5].copy_from_slice(word);
            n += 5;
        }

        Ok(n)
    }
}

/// Structure to format bytewords using [`Display`](fmt::Display).
///
/// The implementation does not allocate and writes bytewords
/// directly to the formatter.
///
/// # Examples
///
/// Printing bytewords to stdout:
///
/// ```
/// use ur::bytewords::{Bytewords, Style};
///
/// let data = b"bytewords encodable message :)";
/// println!("{}", Bytewords(data, Style::Minimal));
/// ```
pub struct Bytewords<'a>(pub &'a [u8], pub Style);

impl<'a> fmt::Display for Bytewords<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let &Bytewords(data, style) = self;
        let checksum = CRC32.checksum(data).to_be_bytes();

        let mut encoder = encoder(data, &checksum, style);
        if style == Style::Minimal {
            for word in encoder {
                write!(f, "{word}")?;
            }
        } else {
            if let Some(first_word) = encoder.next() {
                write!(f, "{first_word}")?;
            } else {
                return Ok(());
            }

            let separator = style.separator_str();
            for word in encoder {
                write!(f, "{separator}{word}")?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytewords() {
        let input = vec![0, 1, 2, 128, 255];
        assert_eq!(
            encode(&input, Style::Standard),
            "able acid also lava zoom jade need echo taxi"
        );
        assert_eq!(
            encode(&input, Style::Uri),
            "able-acid-also-lava-zoom-jade-need-echo-taxi"
        );
        assert_eq!(encode(&input, Style::Minimal), "aeadaolazmjendeoti");

        decode("lpayaacfaddscypyuesfqzhdgeetldfzhywslusacppddspsdwgefyrdlsfzaadrdtlrdatlbbgyfyuydygrwewyjyolvtsphhmkgowdamvowfmhbnwkimrndepebtwnrpwzintihgsffznyvshftyqzoylftybykthlgerdolbwfpzoltghrd", Style::Minimal).unwrap();
        assert_eq!(
            decode(
                "able acid also lava zoom jade need echo taxi",
                Style::Standard
            )
            .unwrap(),
            input
        );
        assert_eq!(
            decode("able-acid-also-lava-zoom-jade-need-echo-taxi", Style::Uri).unwrap(),
            input
        );
        assert_eq!(decode("aeadaolazmjendeoti", Style::Minimal).unwrap(), input);

        // empty payload is allowed
        decode(&encode(&[], Style::Minimal), Style::Minimal).unwrap();

        // bad checksum
        assert_eq!(
            decode(
                "able acid also lava zero jade need echo wolf",
                Style::Standard
            )
            .unwrap_err(),
            DecodeError::InvalidChecksum {
                expected: [107, 155, 51, 243],
                calculated: [108, 246, 247, 201]
            }
        );
        assert_eq!(
            decode("able-acid-also-lava-zero-jade-need-echo-wolf", Style::Uri).unwrap_err(),
            DecodeError::InvalidChecksum {
                expected: [107, 155, 51, 243],
                calculated: [108, 246, 247, 201]
            }
        );
        assert_eq!(
            decode("aeadaolazojendeowf", Style::Minimal).unwrap_err(),
            DecodeError::InvalidChecksum {
                expected: [107, 155, 51, 243],
                calculated: [108, 246, 247, 201]
            }
        );

        // too short
        assert_eq!(
            decode("wolf", Style::Standard).unwrap_err(),
            DecodeError::ChecksumNotPresent
        );
        assert_eq!(
            decode("", Style::Standard).unwrap_err(),
            DecodeError::ChecksumNotPresent
        );

        // invalid length
        assert_eq!(
            decode("aea", Style::Minimal).unwrap_err(),
            DecodeError::InvalidLength
        );

        // non ASCII
        assert_eq!(
            decode("₿", Style::Standard).unwrap_err(),
            DecodeError::NonAscii
        );
        assert_eq!(decode("₿", Style::Uri).unwrap_err(), DecodeError::NonAscii);
        assert_eq!(
            decode("₿", Style::Minimal).unwrap_err(),
            DecodeError::NonAscii
        );
    }

    #[test]
    fn test_encoding() {
        let input: [u8; 100] = [
            245, 215, 20, 198, 241, 235, 69, 59, 209, 205, 165, 18, 150, 158, 116, 135, 229, 212,
            19, 159, 17, 37, 239, 240, 253, 11, 109, 191, 37, 242, 38, 120, 223, 41, 156, 189, 242,
            254, 147, 204, 66, 163, 216, 175, 191, 72, 169, 54, 32, 60, 144, 230, 210, 137, 184,
            197, 33, 113, 88, 14, 157, 31, 177, 46, 1, 115, 205, 69, 225, 150, 65, 235, 58, 144,
            65, 240, 133, 69, 113, 247, 63, 53, 242, 165, 160, 144, 26, 13, 79, 237, 133, 71, 82,
            69, 254, 165, 138, 41, 85, 24,
        ];

        let encoded = "yank toys bulb skew when warm free fair tent swan \
                       open brag mint noon jury list view tiny brew note \
                       body data webs what zinc bald join runs data whiz \
                       days keys user diet news ruby whiz zone menu surf \
                       flew omit trip pose runs fund part even crux fern \
                       math visa tied loud redo silk curl jugs hard beta \
                       next cost puma drum acid junk swan free very mint \
                       flap warm fact math flap what limp free jugs yell \
                       fish epic whiz open numb math city belt glow wave \
                       limp fuel grim free zone open love diet gyro cats \
                       fizz holy city puff";

        let encoded_minimal = "yktsbbswwnwmfefrttsnonbgmtnnjyltvwtybwne\
                               bydawswtzcbdjnrsdawzdsksurdtnsrywzzemusf\
                               fwottppersfdptencxfnmhvatdldroskcljshdba\
                               ntctpadmadjksnfevymtfpwmftmhfpwtlpfejsyl\
                               fhecwzonnbmhcybtgwwelpflgmfezeonledtgocs\
                               fzhycypf";

        assert_eq!(decode(encoded, Style::Standard).unwrap(), input.to_vec());
        assert_eq!(
            decode(encoded_minimal, Style::Minimal).unwrap(),
            input.to_vec()
        );
        assert_eq!(encode(&input, Style::Standard), encoded);
        assert_eq!(encode(&input, Style::Minimal), encoded_minimal);
    }
}
