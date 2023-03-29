// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use core::{num::NonZeroU32, ops::Range};

use minicbor::{data::Type, decode::Error, encode::Write, Decode, Decoder, Encode, Encoder};

/// Metadata for the complete or partial derivation path of a key.
#[doc(alias("crypto-keypath"))]
#[derive(Debug)]
pub struct CryptoKeypath<'a> {
    /// Path component.
    pub components: PathComponents<'a>,
    /// Fingerprint from the ancestor key.
    pub source_fingerprint: Option<NonZeroU32>,
    /// How many derivations this key is from the master (which is 0).
    pub depth: Option<u8>,
}

impl<'a> CryptoKeypath<'a> {
    /// Create a new key path for a master extended public key.
    ///
    /// The `source_fingerprint` parameter is the fingerprint of the master key.
    pub fn new_master(source_fingerprint: NonZeroU32) -> Self {
        Self {
            components: PathComponents {
                storage: PathStorage::RawDerivationPath(&[]),
            },
            source_fingerprint: Some(source_fingerprint),
            depth: Some(0),
        }
    }
}

impl<'b, C> Decode<'b, C> for CryptoKeypath<'b> {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, Error> {
        let mut components = None;
        let mut source_fingerprint = None;
        let mut depth = None;

        let mut len = d.map()?;
        loop {
            match len {
                Some(n) if n == 0 => break,
                Some(n) => len = Some(n - 1),
                None => {
                    if d.datatype()? == Type::Break {
                        break;
                    }
                }
            }

            match d.u32()? {
                1 => components = Some(PathComponents::decode(d, ctx)?),
                2 => {
                    source_fingerprint = Some(
                        NonZeroU32::new(d.u32()?)
                            .ok_or_else(|| Error::message("source-fingerprint is zero"))?,
                    )
                }
                3 => depth = Some(d.u8()?),
                _ => return Err(Error::message("unknown map entry")),
            }
        }

        Ok(Self {
            components: components.ok_or_else(|| Error::message("components is missing"))?,
            source_fingerprint,
            depth,
        })
    }
}

impl<'a, C> Encode<C> for CryptoKeypath<'a> {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        let len =
            1 + u64::from(self.source_fingerprint.is_some()) + u64::from(self.depth.is_some());
        e.map(len)?;

        e.u8(1)?;
        self.components.encode(e, ctx)?;

        if let Some(source_fingerprint) = self.source_fingerprint {
            e.u8(2)?.u32(source_fingerprint.get())?;
        }

        if let Some(depth) = self.depth {
            e.u8(3)?.u8(depth)?;
        }

        Ok(())
    }
}

#[cfg(feature = "bitcoin")]
impl<'a> From<&'a bitcoin::bip32::DerivationPath> for CryptoKeypath<'a> {
    fn from(derivation_path: &'a bitcoin::bip32::DerivationPath) -> Self {
        Self {
            components: PathComponents {
                storage: PathStorage::DerivationPath(derivation_path.as_ref()),
            },
            source_fingerprint: None,
            depth: None,
        }
    }
}

/// Collection of [`PathComponents`].
#[derive(Debug, Clone)]
pub struct PathComponents<'a> {
    storage: PathStorage<'a>,
}

#[derive(Debug, Clone)]
enum PathStorage<'a> {
    Cbor {
        d: Decoder<'a>,
        len: usize,
    },
    RawDerivationPath(&'a [u32]),
    #[cfg(feature = "bitcoin")]
    DerivationPath(&'a [bitcoin::bip32::ChildNumber]),
}

impl<'a> PathStorage<'a> {
    fn len(&self) -> usize {
        match self {
            PathStorage::Cbor { len, .. } => *len,
            PathStorage::RawDerivationPath(path) => path.len(),
            #[cfg(feature = "bitcoin")]
            PathStorage::DerivationPath(path) => path.len(),
        }
    }
}

impl<'a> PathComponents<'a> {
    pub fn len(&self) -> usize {
        self.storage.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn iter(&self) -> PathComponentsIter<'a> {
        PathComponentsIter {
            storage: self.storage.clone(),
            index: 0,
        }
    }
}

impl<'b, C> Decode<'b, C> for PathComponents<'b> {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, Error> {
        // Eat the array type bytes.
        let mut array_len = d.array()?.map(|len| len / 2);

        // Clone the original decoder as the "starting point" of the
        // path components.
        let path_decoder = d.clone();

        // Iterate over the path components in order to verify the data and
        // to consume the bytes of the passed decoder.
        let mut len = 0;
        loop {
            match array_len {
                Some(n) if n == 0 => break,
                Some(n) => array_len = Some(n - 1),
                None => {
                    if d.datatype()? == Type::Break {
                        break;
                    }
                }
            }

            // Consume the path component in order to advance the decoder.
            PathComponent::decode(d, ctx)?;
            len += 1;
        }

        Ok(Self {
            storage: PathStorage::Cbor {
                d: path_decoder,
                len,
            },
        })
    }
}

impl<'a, C> Encode<C> for PathComponents<'a> {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.array(self.len() as u64 * 2)?;

        for elt in self.iter() {
            elt.encode(e, ctx)?;
        }

        Ok(())
    }
}

/// Iterator over the path components of a [`PathComponents`].
pub struct PathComponentsIter<'a> {
    storage: PathStorage<'a>,
    index: usize,
}

impl<'a> Iterator for PathComponentsIter<'a> {
    type Item = PathComponent;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.storage.len() {
            return None;
        }

        let component = match self.storage {
            PathStorage::Cbor { ref mut d, .. } => {
                PathComponent::decode(d, &mut ()).expect("path component should be valid")
            }
            PathStorage::RawDerivationPath(path) => {
                let (number, is_hardened) = if path[self.index] & (1 << 31) != 0 {
                    (path[self.index] ^ (1 << 31), true)
                } else {
                    (path[self.index], false)
                };

                PathComponent {
                    number: ChildNumber::Number(number),
                    is_hardened,
                }
            }
            #[cfg(feature = "bitcoin")]
            PathStorage::DerivationPath(path) => PathComponent::from(path[self.index]),
        };

        self.index += 1;
        Some(component)
    }
}

impl<'a> ExactSizeIterator for PathComponentsIter<'a> {
    fn len(&self) -> usize {
        self.storage.len()
    }
}

/// A derivation path component.
#[doc(alias("path-component"))]
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PathComponent {
    /// The child number.
    pub number: ChildNumber,
    /// Hardened key?
    pub is_hardened: bool,
}

impl<'b, C> Decode<'b, C> for PathComponent {
    fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, Error> {
        let number = match d.datatype()? {
            Type::U8 | Type::U16 | Type::U32 => ChildNumber::Number(d.u32()?),
            Type::Array => {
                let mut array = d.array_iter::<u32>()?;
                let low = array
                    .next()
                    .ok_or_else(|| Error::message("low child-index not present"))??;
                let high = array
                    .next()
                    .ok_or_else(|| Error::message("high child-index not present"))??;
                if array.next().is_some() {
                    return Err(Error::message("invalid child-index-range size"));
                }

                ChildNumber::Range(low..high)
            }
            _ => return Err(Error::message("unknown child number")),
        };

        Ok(Self {
            number,
            is_hardened: d.bool()?,
        })
    }
}

impl<C> Encode<C> for PathComponent {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self.number {
            ChildNumber::Number(n) => e.u32(n)?,
            ChildNumber::Range(ref range) => e.array(2)?.u32(range.start)?.u32(range.end)?,
        };

        e.bool(self.is_hardened)?;

        Ok(())
    }
}

#[cfg(feature = "bitcoin")]
impl From<bitcoin::bip32::ChildNumber> for PathComponent {
    fn from(number: bitcoin::bip32::ChildNumber) -> Self {
        match number {
            bitcoin::bip32::ChildNumber::Normal { index } => PathComponent {
                number: ChildNumber::Number(index),
                is_hardened: false,
            },
            bitcoin::bip32::ChildNumber::Hardened { index } => PathComponent {
                number: ChildNumber::Number(index),
                is_hardened: true,
            },
        }
    }
}

/// The child number of a path component.
// TODO: add wildcard support.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ChildNumber {
    /// A single child number.
    Number(u32),
    /// A range of child numbers.
    Range(Range<u32>),
}
