// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

//! # `crypto-address`
//!
//! See [BCR-2020-009](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-009-address.md).

use minicbor::{
    data::Tag, data::Type, decode::Error, encode::Write, Decode, Decoder, Encode, Encoder,
};

use crate::registry::CryptoCoinInfo;

/// A cryptocurrency address.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CryptoAddress<'a> {
    /// Coin information.
    pub info: Option<CryptoCoinInfo>,
    /// Address type if applicable.
    pub kind: Option<AddressKind>,
    /// The address data.
    pub data: &'a [u8],
}

impl<'a> CryptoAddress<'a> {
    /// The CBOR tag used when [`CryptoAddress`] is embedded in other CBOR
    /// types.
    pub const TAG: Tag = Tag::Unassigned(307);
}

#[cfg(feature = "bitcoin")]
fn data_from_payload(payload: &bitcoin::address::Payload) -> Result<&[u8], InterpretAddressError> {
    use bitcoin::address::Payload;

    match payload {
        Payload::PubkeyHash(ref pkh) => Ok(pkh.as_ref()),
        Payload::ScriptHash(ref sh) => Ok(sh.as_ref()),
        Payload::WitnessProgram(ref wp) => Ok(wp.program().as_bytes()),
        _ => return Err(InterpretAddressError::UnsupportedPayload),
    }
}

#[cfg(feature = "bitcoin")]
impl<'a> TryFrom<&'a bitcoin::Address<bitcoin::address::NetworkUnchecked>> for CryptoAddress<'a> {
    type Error = InterpretAddressError;

    fn try_from(
        address: &'a bitcoin::Address<bitcoin::address::NetworkUnchecked>,
    ) -> Result<Self, Self::Error> {
        let kind = AddressKind::try_from(address.payload()).ok();
        let data = data_from_payload(address.payload())?;

        Ok(Self {
            info: None,
            kind,
            data,
        })
    }
}

#[cfg(feature = "bitcoin")]
impl<'a> TryFrom<&'a bitcoin::Address<bitcoin::address::NetworkChecked>> for CryptoAddress<'a> {
    type Error = InterpretAddressError;

    fn try_from(address: &'a bitcoin::Address) -> Result<Self, Self::Error> {
        use crate::registry::CoinType;
        use bitcoin::Network;

        let network = match address.network() {
            Network::Bitcoin => CryptoCoinInfo::NETWORK_MAINNET,
            Network::Testnet => CryptoCoinInfo::NETWORK_BTC_TESTNET,
            _ => return Err(InterpretAddressError::UnsupportedNetwork),
        };
        let info = CryptoCoinInfo::new(CoinType::BTC, network);
        let kind = AddressKind::try_from(address.payload()).ok();
        let data = data_from_payload(address.payload())?;

        Ok(Self {
            info: Some(info),
            kind,
            data,
        })
    }
}

#[cfg(feature = "bitcoin")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InterpretAddressError {
    UnsupportedNetwork,
    UnsupportedPayload,
}

impl<'b, C> Decode<'b, C> for CryptoAddress<'b> {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, Error> {
        let mut info = None;
        let mut address_type = None;
        let mut data = None;

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
                1 => {
                    if CryptoCoinInfo::TAG != d.tag()? {
                        return Err(Error::message("crypto-coin-info tag is invalid"));
                    }

                    info = Some(CryptoCoinInfo::decode(d, ctx)?);
                }
                2 => address_type = Some(AddressKind::decode(d, ctx)?),
                3 => data = Some(d.bytes()?),
                _ => return Err(Error::message("unknown map entry")),
            }
        }

        Ok(Self {
            info,
            kind: address_type,
            data: data.ok_or_else(|| Error::message("data is missing"))?,
        })
    }
}

impl<'a, C> Encode<C> for CryptoAddress<'a> {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        let include_info = match self.info {
            Some(ref i) => !i.is_default(),
            None => false,
        };

        let len = include_info as u64 + self.kind.is_some() as u64 + 1;
        e.map(len)?;

        if include_info {
            let info = self.info.as_ref().unwrap();
            e.u8(1)?.tag(CryptoCoinInfo::TAG)?;
            info.encode(e, ctx)?;
        }

        if let Some(ref address_type) = self.kind {
            e.u8(2)?;
            address_type.encode(e, ctx)?;
        }

        e.u8(3)?.bytes(self.data)?;

        Ok(())
    }
}

/// Bitcoin (and similar cryptocurrencies) address type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressKind {
    /// Pay to Public Key Hash.
    P2PKH,
    /// Pay to Script Hash.
    P2SH,
    /// Pay to Witness Public Key Hash.
    P2WPKH,
}

impl TryFrom<u8> for AddressKind {
    type Error = InvalidAddressType;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0 => AddressKind::P2PKH,
            1 => AddressKind::P2SH,
            2 => AddressKind::P2WPKH,
            _ => {
                return Err(InvalidAddressType {
                    invalid_type: value,
                })
            }
        })
    }
}

/// Error that can happen during conversion from an unsigned integer to an
/// [`AddressKind`].
#[derive(Debug)]
pub struct InvalidAddressType {
    /// The invalid type.
    pub invalid_type: u8,
}

impl From<AddressKind> for u8 {
    fn from(value: AddressKind) -> Self {
        match value {
            AddressKind::P2PKH => 0,
            AddressKind::P2SH => 1,
            AddressKind::P2WPKH => 2,
        }
    }
}

#[cfg(feature = "bitcoin")]
impl TryFrom<&bitcoin::address::Payload> for AddressKind {
    type Error = UnknownAddressType;

    fn try_from(value: &bitcoin::address::Payload) -> Result<Self, Self::Error> {
        use bitcoin::{address::Payload, blockdata::script::witness_version::WitnessVersion};

        let kind = match value {
            Payload::PubkeyHash(_) => AddressKind::P2PKH,
            Payload::ScriptHash(_) => AddressKind::P2SH,
            Payload::WitnessProgram(wp) => match wp.version() {
                WitnessVersion::V0 if wp.program().as_bytes().len() == 20 => AddressKind::P2WPKH,
                _ => return Err(UnknownAddressType),
            },
            _ => return Err(UnknownAddressType),
        };

        Ok(kind)
    }
}

#[cfg(feature = "bitcoin")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownAddressType;

impl<'b, C> Decode<'b, C> for AddressKind {
    fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, Error> {
        AddressKind::try_from(d.u8()?).map_err(|_| Error::message("invalid address type"))
    }
}

impl<C> Encode<C> for AddressKind {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.u8((*self).into())?;
        Ok(())
    }
}
