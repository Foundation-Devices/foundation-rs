// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use minicbor::{
    data::{Tag, Type},
    decode::Error,
    encode::Write,
    Decode, Decoder, Encode, Encoder,
};

use foundation_arena::{boxed::Box, Arena};

use crate::registry::{CryptoAddress, CryptoECKey, CryptoHDKey};

/// Context type passed to [`Terminal`] [`minicbor::Decode`] implementation.
///
/// It is a heapless arena that is used to allocate [`Terminal`]s.
///
/// This is needed because [`Terminal`] is a recursive data structure.
pub type TerminalContext<'a, 'b, const N: usize> = Arena<Terminal<'a, 'b>, N>;

/// Output descriptor element.
#[derive(Debug, PartialEq)]
pub enum Terminal<'a, 'b> {
    /// Script hash.
    ScriptHash(Box<'a, Terminal<'a, 'b>>),
    /// Witness script hash.
    WitnessScriptHash(Box<'a, Terminal<'a, 'b>>),
    /// Public key.
    PublicKey(Key<'a>),
    /// Public key hash.
    PublicKeyHash(Key<'a>),
    /// Witness public key hash.
    WitnessPublicKeyHash(Key<'b>),
    /// Unknown purpose.
    ///
    /// It is not documented in the specification.
    ///
    /// **Warning**: This is not defined in miniscript.
    Combo(Key<'a>),
    /// Multiple signature checking.
    Multisig(Multikey<'a>),
    /// Sorted (deterministic) multiple signature checking.
    SortedMultisig(Multikey<'a>),
    /// A bare Bitcoin address.
    Address(CryptoAddress<'a>),
    /// A raw script.
    RawScript(&'a [u8]),
    /// Taproot script.
    Taproot(Box<'a, Terminal<'a, 'b>>),
    /// Additional cosigner.
    ///
    /// **Warning**: This is not defined in miniscript.
    Cosigner(Key<'a>),
}

impl<'a, 'b> Terminal<'a, 'b> {
    const TAG_SCRIPT_HASH: Tag = Tag::new(400);
    const TAG_WITNESS_SCRIPT_HASH: Tag = Tag::new(401);
    const TAG_PUBLIC_KEY: Tag = Tag::new(402);
    const TAG_PUBLIC_KEY_HASH: Tag = Tag::new(403);
    const TAG_WITNESS_PUBLIC_KEY_HASH: Tag = Tag::new(404);
    const TAG_COMBO: Tag = Tag::new(405);
    const TAG_MULTISIG: Tag = Tag::new(406);
    const TAG_SORTED_MULTISIG: Tag = Tag::new(407);
    const TAG_RAW_SCRIPT: Tag = Tag::new(408);
    const TAG_TAPROOT: Tag = Tag::new(409);
    const TAG_COSIGNER: Tag = Tag::new(410);
}

fn oom() -> Error {
    Error::message("descriptor does not fit in memory")
}

impl<'a, 'b, const N: usize> Decode<'b, &'a TerminalContext<'a, 'b, N>> for Terminal<'a, 'b> {
    fn decode(
        d: &mut Decoder<'b>,
        ctx: &mut &'a TerminalContext<'a, 'b, N>,
    ) -> Result<Self, Error> {
        match d.tag()? {
            Self::TAG_SCRIPT_HASH => Box::new_in(Terminal::decode(d, ctx)?, ctx)
                .map_err(|_| oom())
                .map(|e| Terminal::ScriptHash(e)),
            Self::TAG_WITNESS_SCRIPT_HASH => Box::new_in(Terminal::decode(d, ctx)?, ctx)
                .map_err(|_| oom())
                .map(|e| Terminal::WitnessScriptHash(e)),
            Self::TAG_PUBLIC_KEY => Key::decode(d, ctx).map(Terminal::PublicKey),
            Self::TAG_PUBLIC_KEY_HASH => Key::decode(d, ctx).map(Terminal::PublicKeyHash),
            Self::TAG_WITNESS_PUBLIC_KEY_HASH => {
                Key::decode(d, ctx).map(Terminal::WitnessPublicKeyHash)
            }
            Self::TAG_COMBO => Key::decode(d, ctx).map(Terminal::Combo),
            Self::TAG_MULTISIG => Multikey::decode(d, ctx).map(Terminal::Multisig),
            Self::TAG_SORTED_MULTISIG => Multikey::decode(d, ctx).map(Terminal::SortedMultisig),
            CryptoAddress::TAG => CryptoAddress::decode(d, ctx).map(Terminal::Address),
            Self::TAG_RAW_SCRIPT => d.bytes().map(Terminal::RawScript),
            Self::TAG_TAPROOT => Box::new_in(Terminal::decode(d, ctx)?, ctx)
                .map_err(|_| oom())
                .map(|e| Terminal::Taproot(e)),
            Self::TAG_COSIGNER => Key::decode(d, ctx).map(Terminal::Cosigner),
            _ => Err(Error::message("invalid tag")),
        }
    }
}

impl<'a, 'b, C> Encode<C> for Terminal<'a, 'b> {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            Terminal::ScriptHash(exp) => {
                e.tag(Self::TAG_SCRIPT_HASH)?;
                exp.encode(e, ctx)?;
            }
            Terminal::WitnessScriptHash(exp) => {
                e.tag(Self::TAG_WITNESS_SCRIPT_HASH)?;
                exp.encode(e, ctx)?;
            }
            Terminal::PublicKey(key) => {
                e.tag(Self::TAG_PUBLIC_KEY)?;
                key.encode(e, ctx)?;
            }
            Terminal::PublicKeyHash(key) => {
                e.tag(Self::TAG_PUBLIC_KEY_HASH)?;
                key.encode(e, ctx)?;
            }
            Terminal::WitnessPublicKeyHash(key) => {
                e.tag(Self::TAG_WITNESS_PUBLIC_KEY_HASH)?;
                key.encode(e, ctx)?;
            }
            Terminal::Combo(key) => {
                e.tag(Self::TAG_COMBO)?;
                key.encode(e, ctx)?;
            }
            Terminal::Multisig(multikey) => {
                e.tag(Self::TAG_MULTISIG)?;
                multikey.encode(e, ctx)?;
            }
            Terminal::SortedMultisig(multikey) => {
                e.tag(Self::TAG_SORTED_MULTISIG)?;
                multikey.encode(e, ctx)?;
            }
            Terminal::Address(address) => {
                e.tag(CryptoAddress::TAG)?;
                address.encode(e, ctx)?;
            }
            Terminal::RawScript(script) => {
                e.tag(Self::TAG_RAW_SCRIPT)?.bytes(script)?;
            }
            Terminal::Taproot(exp) => {
                e.tag(Self::TAG_TAPROOT)?;
                exp.encode(e, ctx)?;
            }
            Terminal::Cosigner(key) => {
                e.tag(Self::TAG_COSIGNER)?;
                key.encode(e, ctx)?;
            }
        }

        Ok(())
    }
}

/// A key.
#[derive(Debug, Clone, PartialEq)]
pub enum Key<'a> {
    /// Elliptic-curve key.
    CryptoECKey(CryptoECKey<'a>),
    /// Elliptic-curve key with the derivation information.
    CryptoHDKey(CryptoHDKey<'a>),
}

impl<'b, C> Decode<'b, C> for Key<'b> {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, Error> {
        d.tag().and_then(|t| match t {
            CryptoECKey::TAG => CryptoECKey::decode(d, ctx).map(Self::CryptoECKey),
            CryptoHDKey::TAG => CryptoHDKey::decode(d, ctx).map(Self::CryptoHDKey),
            _ => Err(Error::message("invalid tag")),
        })
    }
}

impl<'a, C> Encode<C> for Key<'a> {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            Key::CryptoECKey(k) => {
                e.tag(CryptoECKey::TAG)?;
                k.encode(e, ctx)
            }
            Key::CryptoHDKey(k) => {
                e.tag(CryptoHDKey::TAG)?;
                k.encode(e, ctx)
            }
        }
    }
}

/// A container of [`Key`] stored in the same order as they are decoded.
#[derive(Debug, Clone, PartialEq)]
pub struct Keys<'a> {
    storage: KeysStorage<'a>,
}

impl<'a> Keys<'a> {
    pub fn iter(&self) -> KeysIter<'a> {
        KeysIter {
            storage: self.storage.clone(),
            index: 0,
        }
    }
}

impl<'a> From<&'a [Key<'a>]> for Keys<'a> {
    fn from(keys: &'a [Key<'a>]) -> Self {
        Self {
            storage: KeysStorage::Slice(keys),
        }
    }
}

impl<'b, C> Decode<'b, C> for Keys<'b> {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, Error> {
        let mut array_len = d.array()?;
        let keys_decoder = d.clone();
        let mut len: usize = 0;
        loop {
            match array_len {
                Some(n) if n == 0 => break,
                Some(n) => array_len = Some(n.saturating_sub(1)),
                None => {
                    if d.datatype()? == Type::Break {
                        break;
                    }
                }
            }

            Key::decode(d, ctx)?;
            match len.overflowing_add(1) {
                (new_len, false) => len = new_len,
                (_, true) => return Err(Error::message("too many elements")),
            }
        }

        if len == 0 {
            return Err(Error::message("empty keys array"));
        }

        Ok(Self {
            storage: KeysStorage::Cbor {
                d: keys_decoder,
                len,
            },
        })
    }
}

impl<'a, C> Encode<C> for Keys<'_> {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        debug_assert!(self.storage.len() != 0);

        e.array(u64::try_from(self.storage.len()).unwrap())?;
        for key in self.iter() {
            key.encode(e, ctx)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
enum KeysStorage<'a> {
    Cbor { d: Decoder<'a>, len: usize },
    Slice(&'a [Key<'a>]),
}

impl<'a> KeysStorage<'a> {
    fn len(&self) -> usize {
        match self {
            Self::Cbor { len, .. } => *len,
            Self::Slice(s) => s.len(),
        }
    }
}

impl<'a> PartialEq for KeysStorage<'a> {
    fn eq(&self, other: &Self) -> bool {
        if self.len() != other.len() {
            return false;
        }

        let lhs_iter = KeysIter {
            storage: self.clone(),
            index: 0,
        };

        let rhs_iter = KeysIter {
            storage: other.clone(),
            index: 0,
        };

        for (lhs, rhs) in lhs_iter.zip(rhs_iter) {
            if lhs != rhs {
                return false;
            }
        }

        true
    }
}

#[derive(Debug, Clone)]
pub struct KeysIter<'a> {
    storage: KeysStorage<'a>,
    index: usize,
}

impl<'a> Iterator for KeysIter<'a> {
    type Item = Key<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.storage.len() {
            return None;
        }

        let elt = match self.storage {
            KeysStorage::Cbor { ref mut d, .. } => {
                Key::decode(d, &mut ()).expect("element should be valid")
            }
            KeysStorage::Slice(keys) => keys[self.index].clone(),
        };

        self.index += 1;
        Some(elt)
    }
}

/// A multiple signature scheme data.
#[derive(Debug, Decode, Encode, PartialEq)]
#[cbor(map)]
pub struct Multikey<'a> {
    /// The minimum number of signers required.
    #[cbor(n(1))]
    pub threshold: u8,
    /// The keys.
    #[cbor(b(2))]
    pub keys: Keys<'a>,
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::registry::CryptoECKey;

    #[test]
    fn test_example_1() {
        const EXPECTED: &[u8] = &[
            0xd9, 0x01, 0x93, 0xd9, 0x01, 0x32, 0xa1, 0x03, 0x58, 0x21, 0x02, 0xc6, 0x04, 0x7f,
            0x94, 0x41, 0xed, 0x7d, 0x6d, 0x30, 0x45, 0x40, 0x6e, 0x95, 0xc0, 0x7c, 0xd8, 0x5c,
            0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7, 0xab, 0xac, 0x09, 0xb9, 0x5c, 0x70, 0x9e,
            0xe5,
        ];

        let a: TerminalContext<1> = TerminalContext::new();
        let descriptor = Terminal::PublicKeyHash(Key::CryptoECKey(CryptoECKey {
            curve: CryptoECKey::SECP256K1,
            is_private: false,
            data: &[
                0x02, 0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d, 0x30, 0x45, 0x40, 0x6e, 0x95,
                0xc0, 0x7c, 0xd8, 0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7, 0xab, 0xac, 0x09,
                0xb9, 0x5c, 0x70, 0x9e, 0xe5,
            ],
        }));

        let cbor = minicbor::to_vec(&descriptor).unwrap();
        assert_eq!(cbor, EXPECTED);

        let decoded: Terminal = minicbor::decode_with(&EXPECTED, &mut &a).unwrap();

        assert_eq!(descriptor, decoded);
    }

    #[test]
    fn test_example_2() {
        const EXPECTED: &[u8] = &[
            0xd9, 0x01, 0x90, 0xd9, 0x01, 0x94, 0xd9, 0x01, 0x32, 0xa1, 0x03, 0x58, 0x21, 0x03,
            0xff, 0xf9, 0x7b, 0xd5, 0x75, 0x5e, 0xee, 0xa4, 0x20, 0x45, 0x3a, 0x14, 0x35, 0x52,
            0x35, 0xd3, 0x82, 0xf6, 0x47, 0x2f, 0x85, 0x68, 0xa1, 0x8b, 0x2f, 0x05, 0x7a, 0x14,
            0x60, 0x29, 0x75, 0x56,
        ];

        let a: TerminalContext<8> = TerminalContext::new();

        let wpkh = Box::new_in(
            Terminal::WitnessPublicKeyHash(Key::CryptoECKey(CryptoECKey {
                curve: CryptoECKey::SECP256K1,
                is_private: false,
                data: &[
                    0x03, 0xff, 0xf9, 0x7b, 0xd5, 0x75, 0x5e, 0xee, 0xa4, 0x20, 0x45, 0x3a, 0x14,
                    0x35, 0x52, 0x35, 0xd3, 0x82, 0xf6, 0x47, 0x2f, 0x85, 0x68, 0xa1, 0x8b, 0x2f,
                    0x05, 0x7a, 0x14, 0x60, 0x29, 0x75, 0x56,
                ],
            })),
            &a,
        )
        .unwrap();
        let descriptor = Terminal::ScriptHash(wpkh);

        let cbor = minicbor::to_vec(&descriptor).unwrap();
        assert_eq!(cbor, EXPECTED);

        let decoded: Terminal = minicbor::decode_with(&EXPECTED, &mut &a).unwrap();

        assert_eq!(descriptor, decoded);
    }

    #[test]
    fn test_example_3() {
        const EXPECTED: &[u8] = &[
            0xd9, 0x01, 0x90, 0xd9, 0x01, 0x96, 0xa2, 0x01, 0x02, 0x02, 0x82, 0xd9, 0x01, 0x32,
            0xa1, 0x03, 0x58, 0x21, 0x02, 0x2f, 0x01, 0xe5, 0xe1, 0x5c, 0xca, 0x35, 0x1d, 0xaf,
            0xf3, 0x84, 0x3f, 0xb7, 0x0f, 0x3c, 0x2f, 0x0a, 0x1b, 0xdd, 0x05, 0xe5, 0xaf, 0x88,
            0x8a, 0x67, 0x78, 0x4e, 0xf3, 0xe1, 0x0a, 0x2a, 0x01, 0xd9, 0x01, 0x32, 0xa1, 0x03,
            0x58, 0x21, 0x03, 0xac, 0xd4, 0x84, 0xe2, 0xf0, 0xc7, 0xf6, 0x53, 0x09, 0xad, 0x17,
            0x8a, 0x9f, 0x55, 0x9a, 0xbd, 0xe0, 0x97, 0x96, 0x97, 0x4c, 0x57, 0xe7, 0x14, 0xc3,
            0x5f, 0x11, 0x0d, 0xfc, 0x27, 0xcc, 0xbe,
        ];

        let a: TerminalContext<8> = TerminalContext::new();
        let key1 = Key::CryptoECKey(CryptoECKey {
            curve: CryptoECKey::SECP256K1,
            is_private: false,
            data: &[
                0x02, 0x2f, 0x01, 0xe5, 0xe1, 0x5c, 0xca, 0x35, 0x1d, 0xaf, 0xf3, 0x84, 0x3f, 0xb7,
                0x0f, 0x3c, 0x2f, 0x0a, 0x1b, 0xdd, 0x05, 0xe5, 0xaf, 0x88, 0x8a, 0x67, 0x78, 0x4e,
                0xf3, 0xe1, 0x0a, 0x2a, 0x01,
            ],
        });
        let key2 = Key::CryptoECKey(CryptoECKey {
            curve: CryptoECKey::SECP256K1,
            is_private: false,
            data: &[
                0x03, 0xac, 0xd4, 0x84, 0xe2, 0xf0, 0xc7, 0xf6, 0x53, 0x09, 0xad, 0x17, 0x8a, 0x9f,
                0x55, 0x9a, 0xbd, 0xe0, 0x97, 0x96, 0x97, 0x4c, 0x57, 0xe7, 0x14, 0xc3, 0x5f, 0x11,
                0x0d, 0xfc, 0x27, 0xcc, 0xbe,
            ],
        });
        let keys: &[Key] = &[key1, key2];
        let keys = Keys::from(keys);
        let multisig =
            Box::new_in(Terminal::Multisig(Multikey { threshold: 2, keys }), &a).unwrap();
        let descriptor = Terminal::ScriptHash(multisig);

        let cbor = minicbor::to_vec(&descriptor).unwrap();
        assert_eq!(cbor, EXPECTED);

        let decoded: Terminal = minicbor::decode_with(&EXPECTED, &mut &a).unwrap();
        assert_eq!(descriptor, decoded);
    }
}
