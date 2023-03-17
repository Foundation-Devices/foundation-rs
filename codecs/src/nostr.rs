// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

//! # Nostr.
//!
//! This module implements [NIP-19] Bech32-encoded entities standard.
//!
//! [NIP-19]: https://github.com/nostr-protocol/nips/blob/master/19.md
//!
//! Since the size of the encoded `npub` and `nsec` no allocations are made
//! and the encoded value is written to a [`heapless::String`].
//!
//! Also the functions [`encode_npub_to_fmt`] and [`encode_nsec_to_fmt`] can
//! write directly to a [`fmt::Write`] without allocating.

use core::fmt;

use bech32::{Bech32Writer, ToBase32, Variant};

use crate::bech32::bech32_len;

const NPUB: &str = "npub";
const NSEC: &str = "nsec";

/// Length of an encoded `npub`.
pub const NPUB_LEN: usize = bech32_len(NPUB, 32);

/// Length of an encoded `nsec`.
pub const NSEC_LEN: usize = bech32_len(NSEC, 32);

/// Encode a Nostr public key to a fixed size string buffer.
///
/// # Example
///
/// Basic usage:
///
/// ```
/// # use foundation_codecs::nostr::encode_npub;
/// # let data = [0; 32];
/// let npub = encode_npub(&data);
/// println!("{}", npub);
/// ```
pub fn encode_npub(public_key: &[u8; 32]) -> heapless::String<NPUB_LEN> {
    let mut result = heapless::String::new();
    encode_npub_to_fmt(public_key, &mut result)
        .expect("NPUB_LEN should be big enough to hold the result");
    result
}

/// Encode a Nostr secret key to a fixed size string buffer.
///
/// Basic usage:
///
/// ```
/// # use foundation_codecs::nostr::encode_nsec;
/// # let data = [0; 32];
/// let nsec = encode_nsec(&data);
/// println!("{}", nsec);
/// ```
pub fn encode_nsec(secret_key: &[u8; 32]) -> heapless::String<NSEC_LEN> {
    let mut result = heapless::String::new();
    encode_nsec_to_fmt(secret_key, &mut result)
        .expect("NSEC_LEN should be big enough to hold the result");
    result
}

fn encode(hrp: &str, data: &[u8], fmt: &mut dyn fmt::Write) -> Result<(), fmt::Error> {
    let mut writer = Bech32Writer::new(hrp, Variant::Bech32, fmt)?;
    data.write_base32(&mut writer)?;
    writer.finalize()?;
    Ok(())
}

/// Encode a Nostr public key to a [`fmt::Write`].
pub fn encode_npub_to_fmt(
    public_key: &[u8; 32],
    fmt: &mut dyn fmt::Write,
) -> Result<(), fmt::Error> {
    encode(NPUB, public_key, fmt)
}

/// Encode a Nostr secret key to a [`fmt::Write`].
pub fn encode_nsec_to_fmt(
    public_key: &[u8; 32],
    fmt: &mut dyn fmt::Write,
) -> Result<(), fmt::Error> {
    encode(NSEC, public_key, fmt)
}

#[cfg(test)]
pub mod tests {
    use foundation_test_vectors::NIP19Vector;

    use super::*;

    #[test]
    pub fn test_encode_npub() {
        let vectors = NIP19Vector::new();

        for vector in vectors.iter().filter(|t| t.kind == NPUB) {
            let encoded = encode_npub(&vector.bytes);
            assert_eq!(&encoded, &*vector.encoded);
        }
    }

    #[test]
    pub fn test_encode_nsec() {
        let vectors = NIP19Vector::new();

        for vector in vectors.iter().filter(|t| t.kind == NSEC) {
            let encoded = encode_nsec(&vector.bytes);
            assert_eq!(&encoded, &*vector.encoded);
        }
    }
}
