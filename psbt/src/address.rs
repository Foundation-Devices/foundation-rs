// SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use bech32::{hrp, primitives::segwit::MAX_STRING_LENGTH, segwit, Hrp};
use core::{fmt, str};
use faster_hex::hex_encode;
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
    Return,
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

/// Render a string truncating it if it does not fit in the result.
///
/// Places an ellipsis at the end if it does not fit.
fn render_truncated<const N: usize>(s: &str, result: &mut String<N>) {
    // Easy case, string fits.
    if s.len() <= result.capacity().saturating_sub(result.len()) {
        result
            .push_str(s)
            .expect("s length should be less than the capacity");
        return;
    }

    for c in s.chars() {
        let mut buf = [0; 4];
        let encoded = c.encode_utf8(&mut buf);
        if encoded.len() > result.capacity().saturating_sub(result.len()) {
            break;
        }

        result.push_str(encoded).expect("capacity should be enough");
    }

    // Reserve capacity for the ellipsis.
    let remaining = result.capacity().saturating_sub(result.len());
    if remaining < 3 {
        for _ in remaining..3 {
            result.pop();
        }
    }

    result
        .push_str("...")
        .expect("ellipsis length should have been reserved");
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
        // OP_RETURN, display message if encoded as UTF-8 or just the
        // hexadecimal bytes.
        AddressType::Return => {
            const REMAINING_LENGTH: usize = MAX_STRING_LENGTH - "OP_RETURN:".len();

            s.push_str("OP_RETURN:").expect("should have enough space");

            match str::from_utf8(data) {
                Ok(message) => render_truncated(message, s),
                Err(_) => {
                    let mut buf = [0; REMAINING_LENGTH];
                    let hex = hex_encode(&data[..REMAINING_LENGTH / 2], &mut buf)
                        .expect("length of data should fit in buf");
                    render_truncated(hex, s);
                }
            }
        }
    };

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use heapless::String;

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
    fn render_truncated_cases() {
        let mut result: String<4> = String::new();

        // should fit and contents should append
        result.push('a').unwrap();
        render_truncated("bcd", &mut result);
        assert_eq!(result, "abcd");
        result.clear();

        // should fit
        render_truncated("abcd", &mut result);
        assert_eq!(result, "abcd");
        result.clear();

        // should truncate
        render_truncated("abcde", &mut result);
        assert_eq!(result, "a...");
        result.clear();
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

    #[test]
    fn render_op_return() {
        const DATA0: &[u8] = &[
            0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x2C, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21,
        ];

        let mut s = String::new();
        render(Network::Mainnet, AddressType::Return, &DATA0, &mut s).unwrap();
        assert_eq!(s, "OP_RETURN:Hello, World!");

        const DATA1: &[u8] = &[
            0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x2C, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21, 0x48,
            0x65, 0x6C, 0x6C, 0x6F, 0x2C, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21, 0x48, 0x65,
            0x6C, 0x6C, 0x6F, 0x2C, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21, 0x48, 0x65, 0x6C,
            0x6C, 0x6F, 0x2C, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21, 0x48, 0x65, 0x6C, 0x6C,
            0x6F, 0x2C, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21, 0x48, 0x65, 0x6C, 0x6C, 0x6F,
            0x2C, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x2C,
            0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64, 0x21,
        ];

        let mut s = String::new();
        render(Network::Mainnet, AddressType::Return, &DATA1, &mut s).unwrap();
        assert_eq!(s, "OP_RETURN:Hello, World!Hello, World!Hello, World!Hello, World!Hello, World!Hello, World...");
    }
}
