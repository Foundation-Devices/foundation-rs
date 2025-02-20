// SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use bech32::{hrp, primitives::segwit::MAX_STRING_LENGTH, segwit, Hrp};
use core::fmt;
use heapless::{String, Vec};
use tinyvec::SliceVec;

/// Bitcoin network type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    /// Bech32 Human-Readable-Part of the network.
    pub fn bech32_hrp(&self) -> Hrp {
        match self {
            Network::Mainnet => hrp::BC,
            Network::Testnet => hrp::TB,
        }
    }
}

/// Supported address types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    P2WPKH,
    P2WSH,
    P2TR,
    P2PKH,
    P2SH,
    P2PK,
}

impl AddressType {
    /// Is address type post segregated witness standards?
    pub fn is_segwit(&self) -> bool {
        match self {
            AddressType::P2WPKH | AddressType::P2WSH | AddressType::P2TR => true,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenderAddressError {
    /// Formatting error.
    Format(fmt::Error),
    /// Invalid address data.
    InvalidAddressData,
    AddressTooBig,
    Unimplemented,
}

impl fmt::Display for RenderAddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Format(e) => write!(f, "formatting error: {e}"),
            Self::InvalidAddressData => write!(f, "internal error: address data is invalid"),
            Self::AddressTooBig => write!(f, "address is too big to be rendered"),
            Self::Unimplemented => write!(f, "not yet implemented"),
        }
    }
}

fn render_base58_address(
    version: u8,
    data: &[u8],
    s: &mut String<MAX_STRING_LENGTH>,
) -> Result<(), RenderAddressError> {
    let mut buf: Vec<u8, MAX_STRING_LENGTH> = Vec::new();
    buf.resize_default(MAX_STRING_LENGTH)
        .expect("the new length should be the capacity (unreachable)");

    let len = bs58::encode::EncodeBuilder::new(data, bs58::Alphabet::BITCOIN)
        .with_check_version(version)
        .onto(SliceVec::from(buf.as_mut_slice()))
        .map_err(|_| RenderAddressError::AddressTooBig)?;
    buf.truncate(len);

    // Encoder should only produce valid UTF-8, anything else is a logic
    // error, better to not continue with execution since this is
    // impossible.
    *s = String::from_utf8(buf)
        .expect("conversion to base58 always contains valid characters (unreachable)");

    Ok(())
}

/// Render a Bitcoin address as text.
///
/// The result is stored in `s`.
pub fn render(
    network: Network,
    kind: AddressType,
    data: &[u8],
    s: &mut String<MAX_STRING_LENGTH>,
) -> Result<(), RenderAddressError> {
    s.clear();

    match kind {
        AddressType::P2WPKH => {
            if data.len() != 20 {
                return Err(RenderAddressError::InvalidAddressData);
            }

            segwit::encode_to_fmt_unchecked(s, network.bech32_hrp(), segwit::VERSION_0, data)
                .map_err(RenderAddressError::Format)?;
        }
        AddressType::P2WSH => {
            if data.len() != 32 {
                return Err(RenderAddressError::InvalidAddressData);
            }

            segwit::encode_to_fmt_unchecked(s, network.bech32_hrp(), segwit::VERSION_0, data)
                .map_err(RenderAddressError::Format)?;
        }
        AddressType::P2TR => {
            if data.len() != 32 {
                return Err(RenderAddressError::InvalidAddressData);
            }

            segwit::encode_to_fmt_unchecked(s, network.bech32_hrp(), segwit::VERSION_1, data)
                .map_err(RenderAddressError::Format)?;
        }
        AddressType::P2PKH => {
            if data.len() != 20 {
                return Err(RenderAddressError::InvalidAddressData);
            }

            render_base58_address(0x00, data, s)?;
        }
        AddressType::P2SH => {
            if data.len() != 20 {
                return Err(RenderAddressError::InvalidAddressData);
            }

            render_base58_address(0x05, data, s)?;
        }
        // Maybe render the public key as hex.
        AddressType::P2PK => return Err(RenderAddressError::Unimplemented),
    };

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_bech32_hrp() {
        let mainnet_hrp = Network::Mainnet.bech32_hrp();
        let testnet_hrp = Network::Testnet.bech32_hrp();

        assert_eq!(mainnet_hrp.as_str(), "bc");
        assert!(mainnet_hrp.is_valid_segwit());
        assert!(mainnet_hrp.is_valid_on_mainnet());

        assert_eq!(testnet_hrp.as_str(), "tb");
        assert!(testnet_hrp.is_valid_segwit());
        assert!(testnet_hrp.is_valid_on_testnet());
        assert!(testnet_hrp.is_valid_on_signet());
    }

    #[test]
    fn render_invalid_p2wpkh() {
        let mut s = String::new();
        assert_eq!(
            render(Network::Mainnet, AddressType::P2WPKH, &[], &mut s),
            Err(RenderAddressError::InvalidAddressData)
        );
        assert_eq!(
            render(Network::Testnet, AddressType::P2WPKH, &[], &mut s),
            Err(RenderAddressError::InvalidAddressData)
        );
    }

    #[test]
    fn render_invalid_p2wsh() {
        let mut s = String::new();
        assert_eq!(
            render(Network::Mainnet, AddressType::P2WSH, &[], &mut s),
            Err(RenderAddressError::InvalidAddressData)
        );
        assert_eq!(
            render(Network::Testnet, AddressType::P2WSH, &[], &mut s),
            Err(RenderAddressError::InvalidAddressData)
        );
    }
}
