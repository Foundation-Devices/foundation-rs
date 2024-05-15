// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use minicbor::{
    data::Tag, data::Type, decode::Error, encode::Write, Decode, Decoder, Encode, Encoder,
};

/// Metadata for the type and use of a cryptocurrency.
#[doc(alias("crypto-coininfo"))]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CryptoCoinInfo {
    /// Coin type.
    pub coin_type: CoinType,
    /// Network identifier.
    ///
    /// `mainnet` is the general for all currencies.
    ///
    /// All others are coin-specific value.
    pub network: u64,
}

impl CryptoCoinInfo {
    /// Tag for embedding [`CryptoCoinInfo`] in other types.
    pub const TAG: Tag = Tag::new(305);

    /// Universal value for unique network.
    pub const NETWORK_MAINNET: u64 = 0;

    /// Bitcoin testnet network.
    pub const NETWORK_BTC_TESTNET: u64 = 1;

    /// Bitcoin mainnet.
    pub const BTC_MAINNET: Self = Self {
        coin_type: CoinType::BTC,
        network: Self::NETWORK_MAINNET,
    };

    /// Construct a new [`CryptoCoinInfo`].
    pub const fn new(coin_type: CoinType, network: u64) -> Self {
        Self { coin_type, network }
    }

    pub fn is_default(&self) -> bool {
        self.coin_type == CoinType::BTC && self.network == Self::NETWORK_MAINNET
    }
}

impl<'b, C> Decode<'b, C> for CryptoCoinInfo {
    fn decode(d: &mut Decoder<'b>, ctx: &mut C) -> Result<Self, Error> {
        let mut coin_type = None;
        let mut network = None;

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
                1 => coin_type = Some(CoinType::decode(d, ctx)?),
                2 => network = Some(d.u64()?),
                _ => return Err(Error::message("unknown map entry")),
            }
        }

        Ok(Self {
            coin_type: coin_type.unwrap_or(CoinType::BTC),
            network: network.unwrap_or(0),
        })
    }
}

impl<C> Encode<C> for CryptoCoinInfo {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        let is_not_default_coin_type = self.coin_type != CoinType::BTC;
        let is_not_default_network = self.network != 0;
        let len = is_not_default_coin_type as u64 + is_not_default_network as u64;

        e.map(len)?;

        if is_not_default_coin_type {
            e.u8(1)?;
            self.coin_type.encode(e, ctx)?;
        }

        if is_not_default_network {
            e.u8(2)?.u64(self.network)?;
        }

        Ok(())
    }
}

/// A coin type.
///
/// Values are defined in [SLIP-44].
///
/// [SLIP-44]: https://github.com/satoshilabs/slips/blob/master/slip-0044.md
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct CoinType(pub(crate) u32);

impl CoinType {
    pub const BTC: Self = CoinType(0x00);

    pub fn new(value: u32) -> Self {
        Self(value)
    }

    /// Get the value of the coin type.
    pub fn get(self) -> u32 {
        self.0
    }
}

impl<'b, C> Decode<'b, C> for CoinType {
    fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, Error> {
        let n = d.u32()?;
        if n >= 1 << 31 {
            return Err(Error::message("coin type out of range"));
        }

        Ok(CoinType(n))
    }
}

impl<C> Encode<C> for CoinType {
    fn encode<W: Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.u32(self.get())?;
        Ok(())
    }
}

impl From<u32> for CoinType {
    fn from(n: u32) -> Self {
        CoinType(n)
    }
}

impl From<CoinType> for u32 {
    fn from(coin_type: CoinType) -> Self {
        coin_type.get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Basic test. No independent test vectors available.
    #[test]
    fn test_crypto_coininfo_roundtrip() {
        let crypto_coininfo = CryptoCoinInfo::BTC_MAINNET;
        let cbor = minicbor::to_vec(&crypto_coininfo).unwrap();
        let decoded = minicbor::decode(&cbor).unwrap();
        assert_eq!(crypto_coininfo, decoded);
    }

    // Basic test. No independent test vectors available.
    #[test]
    fn test_coin_type_roundtrip() {
        let coin_type = CoinType::BTC;
        let cbor = minicbor::to_vec(coin_type).unwrap();
        assert_eq!(cbor, &[0x00]);
        let decoded = minicbor::decode(&cbor).unwrap();
        assert_eq!(coin_type, decoded);
    }
}
