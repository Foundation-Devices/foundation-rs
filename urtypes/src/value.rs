// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

//! An Uniform Resource value.
//!
//! The [`Value`] type aggregates every known UR type (by this crate) into a
//! single enumeration variant containing those.
//!
//! This can be used to parse a Uniform Resource by checking on the UR type
//! and then calling the corresponding decoder.
//!
//! # Example
//!
//! Parsing a UR:
//!
//! ```rust
//! // As a UR: ur:bytes/gdaebycpeofygoiyktlonlpkrksfutwyzmwmfyeozs
//! use foundation_urtypes::value::Value;
//! const PAYLOAD: &[u8] = &[
//!     0x50, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
//!     0xEE, 0xFF,
//! ];
//! const UR_TYPE: &str = "bytes";
//!
//! let value = Value::from_ur(UR_TYPE, PAYLOAD).unwrap();
//! println!("{:?}", value);
//! ```

use core::fmt::{Display, Formatter};

use minicbor::{bytes::ByteSlice, encode::Write, Encode, Encoder};

use crate::registry::{HDKeyRef, PassportRequest, PassportResponse, Terminal, TerminalContext};

#[derive(Debug, PartialEq)]
pub enum Value<'a> {
    /// bytes.
    Bytes(&'a [u8]),
    /// crypto-hdkey.
    HDKey(HDKeyRef<'a>),
    /// crypto-psbt.
    Psbt(&'a [u8]),
    /// crypto-request for Passport.
    PassportRequest(PassportRequest),
    /// crypto-response for Passport.
    PassportResponse(PassportResponse<'a>),
}

impl<'a> Value<'a> {
    /// Construct a new [`Value`] from the type and the CBOR payload.
    pub fn from_ur(ur_type: &str, payload: &'a [u8]) -> Result<Self, Error> {
        let value = match ur_type {
            "bytes" => Self::Bytes(minicbor::decode::<&ByteSlice>(payload)?),
            "hdkey" | "crypto-hdkey" => Self::HDKey(minicbor::decode(payload)?),
            "psbt" | "crypto-psbt" => Self::Psbt(minicbor::decode::<&ByteSlice>(payload)?),
            // TODO: Remove crypto-request and crypto-response, these have
            // been removed from the UR registry standard (BCR-2020-006).
            "x-passport-request" | "crypto-request" => {
                Self::PassportRequest(minicbor::decode(payload)?)
            }
            "x-passport-response" | "crypto-response" => {
                Self::PassportResponse(minicbor::decode(payload)?)
            }
            _ => return Err(Error::UnsupportedResource),
        };

        Ok(value)
    }

    /// Whether `ur_type` is the legacy `crypto-output` UR type (BCR-2020-010).
    ///
    /// This is the flavor still emitted by e.g. Sparrow: a recursive CBOR
    /// tree rooted at one of the script-type tags (400..=410) that decodes
    /// into [`Terminal`].
    ///
    /// The newer BCR-2023-010 `output-descriptor` UR (CBOR tag 40308 map
    /// wrapping a text descriptor) is NOT the same wire format and is not
    /// accepted here; feeding its payload through [`decode_output_descriptor`]
    /// would produce `InvalidCbor(invalid tag)`.
    pub fn is_output_descriptor(ur_type: &str) -> bool {
        matches!(ur_type, "crypto-output")
    }

    /// Return the type of this value as a string.
    ///
    /// # Notes
    ///
    /// This will return the _deprecated_ types as some implementers of UR
    /// still don't support the newer ones.
    ///
    /// When changing this to use the newer types also change
    /// [`Value::from_ur`].
    pub fn ur_type(&self) -> &'static str {
        match self {
            Value::Bytes(_) => "bytes",
            Value::HDKey(_) => "hdkey",
            Value::Psbt(_) => "crypto-psbt",
            Value::PassportRequest(_) => "crypto-request",
            Value::PassportResponse(_) => "crypto-response",
        }
    }
}

/// Decode a legacy `crypto-output` UR payload (BCR-2020-010) into a [`Terminal`].
///
/// [`Terminal`] is a recursive data structure, so its sub-nodes are allocated
/// into the caller-provided [`TerminalContext`] arena. `N` must be large
/// enough to hold every nested `Terminal` node in the descriptor (e.g. a
/// `wsh(sortedmulti(...))` needs at least 2 slots).
///
/// Dispatches on the UR type string so callers can route from a generic
/// "got a UR" entry point. Only `crypto-output` is accepted; the newer
/// BCR-2023-010 `output-descriptor` (tag 40308) uses a different CBOR shape
/// and is not supported by this helper. See [`Value::is_output_descriptor`].
pub fn decode_output_descriptor<'a, 'b, const N: usize>(
    ur_type: &str,
    payload: &'b [u8],
    arena: &'a TerminalContext<'a, 'b, N>,
) -> Result<Terminal<'a, 'b>, Error> {
    if !Value::is_output_descriptor(ur_type) {
        return Err(Error::UnsupportedResource);
    }
    let mut ctx: &'a TerminalContext<'a, 'b, N> = arena;
    minicbor::decode_with::<_, Terminal>(payload, &mut ctx).map_err(Into::into)
}

impl<'a, C> Encode<C> for Value<'a> {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            Value::Bytes(v) => minicbor::bytes::encode(v, e, ctx),
            Value::HDKey(v) => v.encode(e, ctx),
            Value::Psbt(v) => minicbor::bytes::encode(v, e, ctx),
            Value::PassportRequest(v) => v.encode(e, ctx),
            Value::PassportResponse(v) => v.encode(e, ctx),
        }
    }
}

/// Errors that can occur when parsing a value.
#[derive(Debug)]
pub enum Error {
    /// Unsupported Uniform Resource type.
    UnsupportedResource,
    /// Failed to decode CBOR payload.
    InvalidCbor(minicbor::decode::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedResource => write!(f, "unsupported Uniform Resource type"),
            Self::InvalidCbor(_) => write!(f, "failed to decode CBOR payload"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidCbor(e) => Some(e),
            _ => None,
        }
    }
}

impl From<minicbor::decode::Error> for Error {
    fn from(error: minicbor::decode::Error) -> Self {
        Self::InvalidCbor(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::registry::{ECKey, Key, Multikey, Terminal, TerminalContext};
    use foundation_arena::boxed::Box as ArenaBox;

    #[test]
    fn test_is_output_descriptor() {
        assert!(Value::is_output_descriptor("crypto-output"));
        // `output-descriptor` is a distinct BCR-2023-010 UR (tag 40308 map,
        // not the tag-400..410 tree) and must NOT be accepted by this helper
        // — the reviewer on PR #54 reproduced `InvalidCbor(invalid tag)`
        // when a spec-compliant `output-descriptor` payload was routed here.
        assert!(!Value::is_output_descriptor("output-descriptor"));
        // Bare `output` is not a registered UR type at all.
        assert!(!Value::is_output_descriptor("output"));
        assert!(!Value::is_output_descriptor("hdkey"));
        assert!(!Value::is_output_descriptor("crypto-hdkey"));
        assert!(!Value::is_output_descriptor(""));
    }

    fn sample_wsh_sortedmulti_cbor() -> alloc::vec::Vec<u8> {
        // wsh(sorted_multi(2 of 2)) — the flavor Sparrow emits for BIP48
        // P2WSH multisigs. Same keys as `output_descriptor::test_example_3`.
        let a: TerminalContext<8> = TerminalContext::new();
        let key1 = Key::ECKey(ECKey {
            curve: ECKey::SECP256K1,
            is_private: false,
            data: &[
                0x02, 0x2f, 0x01, 0xe5, 0xe1, 0x5c, 0xca, 0x35, 0x1d, 0xaf, 0xf3, 0x84, 0x3f, 0xb7,
                0x0f, 0x3c, 0x2f, 0x0a, 0x1b, 0xdd, 0x05, 0xe5, 0xaf, 0x88, 0x8a, 0x67, 0x78, 0x4e,
                0xf3, 0xe1, 0x0a, 0x2a, 0x01,
            ],
        });
        let key2 = Key::ECKey(ECKey {
            curve: ECKey::SECP256K1,
            is_private: false,
            data: &[
                0x03, 0xac, 0xd4, 0x84, 0xe2, 0xf0, 0xc7, 0xf6, 0x53, 0x09, 0xad, 0x17, 0x8a, 0x9f,
                0x55, 0x9a, 0xbd, 0xe0, 0x97, 0x96, 0x97, 0x4c, 0x57, 0xe7, 0x14, 0xc3, 0x5f, 0x11,
                0x0d, 0xfc, 0x27, 0xcc, 0xbe,
            ],
        });
        let keys: &[Key] = &[key1, key2];
        let sortedmulti = ArenaBox::new_in(
            Terminal::SortedMultisig(Multikey {
                threshold: 2,
                keys: keys.into(),
            }),
            &a,
        )
        .unwrap();
        let descriptor = Terminal::WitnessScriptHash(sortedmulti);
        minicbor::to_vec(&descriptor).unwrap()
    }

    #[test]
    fn test_decode_output_descriptor_crypto_output_alias() {
        let cbor = sample_wsh_sortedmulti_cbor();
        let arena: TerminalContext<8> = TerminalContext::new();
        let decoded = decode_output_descriptor("crypto-output", &cbor, &arena).unwrap();
        assert!(matches!(decoded, Terminal::WitnessScriptHash(_)));
    }

    #[test]
    fn test_decode_output_descriptor_retains_nested_arena_nodes() {
        const CBOR: &[u8] = &[
            0xd9, 0x01, 0x90, // script-hash
            0xd9, 0x01, 0x90, // script-hash
            0xd9, 0x01, 0x91, // witness-script-hash
            0xd9, 0x01, 0x98, // raw-script
            0x41, 0x42, // byte string: 0x42
        ];

        let arena: TerminalContext<3> = TerminalContext::new();
        let decoded = decode_output_descriptor("crypto-output", CBOR, &arena).unwrap();

        let Terminal::ScriptHash(first) = decoded else {
            panic!("expected outer script-hash");
        };
        let Terminal::ScriptHash(second) = &*first else {
            panic!("expected nested script-hash");
        };
        let Terminal::WitnessScriptHash(third) = &**second else {
            panic!("expected witness-script-hash");
        };
        assert!(matches!(&**third, Terminal::RawScript(&[0x42])));
    }

    #[test]
    fn test_decode_output_descriptor_rejects_output_descriptor_alias() {
        // BCR-2023-010 `output-descriptor` uses a different CBOR shape (tag
        // 40308 map), so this helper — which only understands the legacy
        // BCR-2020-010 tag-400..410 tree — must reject it at the type-string
        // layer rather than handing the bytes to the wrong decoder.
        let cbor = sample_wsh_sortedmulti_cbor();
        let arena: TerminalContext<8> = TerminalContext::new();
        match decode_output_descriptor("output-descriptor", &cbor, &arena) {
            Err(Error::UnsupportedResource) => {}
            other => panic!("expected UnsupportedResource, got {other:?}"),
        };
    }

    #[test]
    fn test_decode_output_descriptor_rejects_other_types() {
        let cbor = sample_wsh_sortedmulti_cbor();
        let arena: TerminalContext<8> = TerminalContext::new();
        match decode_output_descriptor("bytes", &cbor, &arena) {
            Err(Error::UnsupportedResource) => {}
            other => panic!("expected UnsupportedResource, got {other:?}"),
        };
    }

    #[test]
    fn test_byte_string_bytes() {
        const BYTES_PAYLOAD: &[u8] = &[
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        const CBOR_PAYLOAD: &[u8] = &[
            0x50, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
            0xDD, 0xEE, 0xFF,
        ];

        let value = Value::from_ur("bytes", CBOR_PAYLOAD).unwrap();
        assert_eq!(value, Value::Bytes(BYTES_PAYLOAD));

        let cbor = minicbor::to_vec(&value).unwrap();
        assert_eq!(cbor, CBOR_PAYLOAD);
    }
}
