pub mod decoder;
pub mod encoder;

#[cfg(feature = "alloc")]
pub use self::decoder::Decoder;
pub use self::decoder::{BaseDecoder, HeaplessDecoder};

#[cfg(feature = "alloc")]
pub use self::encoder::Encoder;
pub use self::encoder::{BaseEncoder, HeaplessEncoder};

use crate::{
    bytewords::{Bytewords, Style},
    fountain::part::Part,
};
use core::{fmt, num::ParseIntError};

/// An uniform resource.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum UR<'a> {
    /// A single-part resource.
    SinglePart {
        /// The type.
        ur_type: &'a str,
        /// The message.
        message: &'a str,
    },
    /// A deserialized single-part resource.
    SinglePartDeserialized {
        /// The type.
        ur_type: &'a str,
        /// The message.
        message: &'a [u8],
    },
    /// A multiple-part resource.
    MultiPart {
        /// The type.
        ur_type: &'a str,
        /// The fragment.
        fragment: &'a str,
        /// The sequence number.
        sequence: u32,
        /// The total sequence count.
        sequence_count: u32,
    },
    /// A deserialized multiple-part resource.
    MultiPartDeserialized {
        /// The type.
        ur_type: &'a str,
        /// The fragment.
        fragment: Part<'a>,
    },
}

impl<'a> UR<'a> {
    /// Construct a new single-part [`UR`].
    pub fn new(ur_type: &'a str, message: &'a [u8]) -> Self {
        UR::SinglePartDeserialized { ur_type, message }
    }

    /// Parses an uniform resource string.
    ///
    /// Keep in mind, this does not deserialize the `bytewords` payload,
    /// deserialization is performed separately, for example, by the
    /// [decoder](BaseDecoder).
    pub fn parse(s: &'a str) -> Result<Self, ParseURError> {
        let (ur_type, rest) = s
            .strip_prefix("ur:")
            .ok_or(ParseURError::InvalidScheme)?
            .split_once('/')
            .ok_or(ParseURError::TypeUnspecified)?;

        if !ur_type
            .trim_start_matches(|c: char| c.is_ascii_alphanumeric() || c == '-')
            .is_empty()
        {
            return Err(ParseURError::InvalidCharacters);
        }

        match rest.rsplit_once('/') {
            None => Ok(UR::SinglePart {
                ur_type,
                message: rest,
            }),
            Some((indices, fragment)) => {
                let (sequence, sequence_count) = indices
                    .split_once('-')
                    .ok_or(ParseURError::InvalidIndices)?;

                Ok(UR::MultiPart {
                    ur_type,
                    fragment,
                    sequence: sequence.parse()?,
                    sequence_count: sequence_count.parse()?,
                })
            }
        }
    }

    /// Returns true if the Uniform Resource is single-part.
    #[inline]
    pub fn is_single_part(&self) -> bool {
        matches!(
            self,
            UR::SinglePart { .. } | UR::SinglePartDeserialized { .. }
        )
    }

    /// Returns `true` if the Uniform Resource is multi-part.
    #[inline]
    pub fn is_multi_part(&self) -> bool {
        matches!(
            self,
            UR::MultiPart { .. } | UR::MultiPartDeserialized { .. }
        )
    }

    /// Returns `true` if this Uniform Resource is multi-part and deserialized.
    #[inline]
    pub fn is_deserialized(&self) -> bool {
        matches!(
            self,
            UR::SinglePartDeserialized { .. } | UR::MultiPartDeserialized { .. }
        )
    }

    /// Returns the UR type.
    pub fn as_type(&self) -> &str {
        match self {
            UR::SinglePart { ur_type, .. } => ur_type,
            UR::SinglePartDeserialized { ur_type, .. } => ur_type,
            UR::MultiPart { ur_type, .. } => ur_type,
            UR::MultiPartDeserialized { ur_type, .. } => ur_type,
        }
    }

    /// Returns `Some(bytewords)` if the Uniform Resource is serialized.
    pub fn as_bytewords(&self) -> Option<&str> {
        match self {
            UR::SinglePart { message, .. } => Some(message),
            UR::MultiPart { fragment, .. } => Some(fragment),
            _ => None,
        }
    }

    /// Returns `Some(part)` if the Uniform Resource is multi-part and is
    /// deserialized.
    pub fn as_part(&self) -> Option<&Part> {
        match self {
            UR::MultiPartDeserialized { fragment, .. } => Some(fragment),
            _ => None,
        }
    }

    /// Returns `Some(n)` where `n` is the sequence number if the Uniform
    /// Resource is multi part.
    pub fn sequence(&self) -> Option<u32> {
        match self {
            UR::MultiPart { sequence, .. } => Some(*sequence),
            UR::MultiPartDeserialized { fragment, .. } => Some(fragment.sequence),
            _ => None,
        }
    }

    /// Returns `Some(n)` where `n` is the sequence count if the Uniform
    /// Resource is multi part.
    pub fn sequence_count(&self) -> Option<u32> {
        match self {
            UR::MultiPart { sequence_count, .. } => Some(*sequence_count),
            UR::MultiPartDeserialized { fragment, .. } => Some(fragment.sequence_count),
            _ => None,
        }
    }
}

impl<'a> fmt::Display for UR<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UR::SinglePart { ur_type, message } => {
                write!(f, "ur:{ur_type}/{message}")
            }
            UR::SinglePartDeserialized { ur_type, message } => {
                let message = Bytewords(message, Style::Minimal);
                write!(f, "ur:{ur_type}/{message}")
            }
            UR::MultiPart {
                ur_type,
                fragment,
                sequence,
                sequence_count,
            } => {
                write!(f, "ur:{ur_type}/{sequence}-{sequence_count}/{fragment}")
            }
            UR::MultiPartDeserialized { ur_type, fragment } => {
                let (sequence, sequence_count) = (fragment.sequence, fragment.sequence_count);
                write!(f, "ur:{ur_type}/{sequence}-{sequence_count}/{fragment}",)
            }
        }
    }
}

/// Errors that can happen during parsing of Uniform Resources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseURError {
    /// Invalid scheme.
    InvalidScheme,
    /// No type specified.
    TypeUnspecified,
    /// Invalid characters.
    InvalidCharacters,
    /// Invalid indices in multi-part UR.
    InvalidIndices,
    /// Could not parse indices integers.
    ParseInt(ParseIntError),
}

impl fmt::Display for ParseURError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseURError::InvalidScheme => write!(f, "Invalid Uniform Resource scheme"),
            ParseURError::TypeUnspecified => write!(f, "No type was specified for the Uniform Resource"),
            ParseURError::InvalidCharacters => {
                write!(f, "Uniform Resource type contains invalid characters")
            }
            ParseURError::InvalidIndices => write!(f, "Uniform Resource indices are invalid"),
            ParseURError::ParseInt(e) => {
                write!(f, "Could not parse Uniform Resource indices: {e}")
            }
        }
    }
}

impl From<ParseIntError> for ParseURError {
    fn from(e: ParseIntError) -> Self {
        Self::ParseInt(e)
    }
}

/// Encode a single part UR to a string.
#[cfg(feature = "alloc")]
pub fn to_string(ur_type: &str, message: &[u8]) -> alloc::string::String {
    let ur = UR::SinglePartDeserialized { ur_type, message };

    ur.to_string()
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::bytewords;
    use crate::registry::crypto_request::{Body, CryptoRequest, RequestSeed};
    use std::num::IntErrorKind;
    use uuid::Uuid;

    pub fn make_message_ur(length: usize, seed: &str) -> Vec<u8> {
        let message = crate::xoshiro::test_utils::make_message(seed, length);
        minicbor::to_vec(minicbor::bytes::ByteVec::from(message)).unwrap()
    }

    #[test]
    fn test_single_part_ur() {
        const EXPECTED: &str = "ur:bytes/hdeymejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtgwdpfnsboxgwlbaawzuefywkdplrsrjynbvygabwjldapfcsdwkbrkch";

        let encoded = UR::new("bytes", &make_message_ur(50, "Wolf")).to_string();
        assert_eq!(&encoded, EXPECTED);

        let parsed = UR::parse(&encoded).unwrap();
        assert!(matches!(parsed, UR::SinglePart {
            ur_type: "bytes",
            message: "hdeymejtswhhylkepmykhhtsytsnoyoyaxaedsuttydmmhhpktpmsrjtgwdpfnsboxgwlbaawzuefywkdplrsrjynbvygabwjldapfcsdwkbrkch",
        }));
    }

    #[test]
    fn test_ur_encoder_decoder_bc_crypto_request() {
        // https://github.com/BlockchainCommons/crypto-commons/blob/67ea252f4a7f295bb347cb046796d5b445b3ad3c/Docs/ur-99-request-response.md#the-seed-request

        const UUID: &str = "020C223A86F7464693FC650EF3CAC047";
        const SEED_DIGEST: &str =
            "E824467CAFFEAF3BBC3E0CA095E660A9BAD80DDB6A919433A37161908B9A3986";
        const EXPECTED: &str = "ur:crypto-request/oeadtpdagdaobncpftlnylfgfgmuztihbawfsgrtflaotaadwkoyadtaaohdhdcxvsdkfgkepezepefrrffmbnnbmdvahnptrdtpbtuyimmemweootjshsmhlunyeslnameyhsdi";

        let transaction_id = Uuid::from_slice(&hex::decode(UUID).unwrap()).unwrap();

        let mut seed_digest = [0u8; 32];
        seed_digest.copy_from_slice(&hex::decode(SEED_DIGEST).unwrap());

        let crypto_request = CryptoRequest {
            transaction_id,
            body: Body::RequestSeed(RequestSeed { seed_digest }),
            description: None,
        };

        let data = minicbor::to_vec(crypto_request).unwrap();
        let ur = UR::new("crypto-request", &data).to_string();
        assert_eq!(ur, EXPECTED);

        // Decoding should yield the same data
        let parsed_ur = UR::parse(&ur).unwrap();
        assert!(parsed_ur.is_single_part());

        let decoded = bytewords::decode(parsed_ur.as_bytewords().unwrap(), Style::Minimal).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_ur_roundtrip() {
        let ur = make_message_ur(32767, "Wolf");
        let mut encoder = Encoder::new();
        encoder.start("bytes", &ur, 1000);

        let mut decoder = Decoder::default();
        while !decoder.is_complete() {
            assert_eq!(decoder.message().unwrap(), None);
            decoder.receive(encoder.next_part()).unwrap();
        }
        assert_eq!(decoder.message().unwrap(), Some(ur.as_slice()));
    }

    #[test]
    fn test_parser() {
        UR::parse("ur:bytes/aeadaolazmjendeoti").unwrap();
        UR::parse("ur:whatever-12/aeadaolazmjendeoti").unwrap();
    }

    #[test]
    fn test_parser_errors() {
        const TEST_VECTORS: &[(&str, ParseURError)] = &[
            ("uhr:bytes/aeadaolazmjendeoti", ParseURError::InvalidScheme),
            ("ur:aeadaolazmjendeoti", ParseURError::TypeUnspecified),
            (
                "ur:bytes#4/aeadaolazmjendeoti",
                ParseURError::InvalidCharacters,
            ),
            (
                "ur:bytes/1 1/aeadaolazmjendeoti",
                ParseURError::InvalidIndices,
            ),
        ];

        for (input, error) in TEST_VECTORS {
            assert_eq!(UR::parse(&input).unwrap_err(), error.clone());
        }

        match UR::parse("ur:bytes/1-1/toomuch/aeadaolazmjendeoti") {
            Err(ParseURError::ParseInt(e)) => {
                assert_eq!(*e.kind(), IntErrorKind::InvalidDigit)
            }
            _ => panic!(),
        }

        match UR::parse("ur:bytes/1-1a/aeadaolazmjendeoti") {
            Err(ParseURError::ParseInt(e)) => {
                assert_eq!(*e.kind(), IntErrorKind::InvalidDigit)
            }
            _ => panic!(),
        }
    }
}
