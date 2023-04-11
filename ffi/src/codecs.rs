// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

/// Encoded length of a `npub` in bytes.
pub const NPUB_LEN: usize = 63;
/// Encoded length of a `nsec` in bytes.
pub const NSEC_LEN: usize = 63;

/// Encode a public key to a Nostr `npub`.
#[export_name = "foundation_encode_npub"]
pub extern "C" fn encode_npub(public_key: &[u8; 32], output: &mut [u8; NPUB_LEN]) {
    let npub = foundation_codecs::nostr::encode_npub(public_key);
    output[..npub.len()].copy_from_slice(npub.as_bytes());
}

/// Encode a secret key to a Nostr `nsec`.
#[export_name = "foundation_encode_nsec"]
pub extern "C" fn encode_nsec(secret_key: &[u8; 32], output: &mut [u8; NSEC_LEN]) {
    let nsec = foundation_codecs::nostr::encode_nsec(secret_key);
    output[..nsec.len()].copy_from_slice(nsec.as_bytes());
}

#[cfg(test)]
pub mod tests {
    use super::*;

    // This test is necessary because the constants in foundation-codecs
    // are calculated using const functions, but cbindgen doesn't support
    // these kinds of constants, so we declare it manually and check that
    // these are correct.
    #[test]
    fn test_constants() {
        assert_eq!(NPUB_LEN, foundation_codecs::nostr::NPUB_LEN);
        assert_eq!(NSEC_LEN, foundation_codecs::nostr::NSEC_LEN);
    }
}
