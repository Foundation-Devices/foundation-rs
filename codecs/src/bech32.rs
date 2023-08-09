// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

const SEP_LEN: usize = 1;
const CHECKSUM_LEN: usize = 6;

/// Calculate the encoded length of a byte slice as Bech32.
pub const fn bech32_len(hrp: &str, len: usize) -> usize {
    hrp.len() + SEP_LEN + base32_len(len) + CHECKSUM_LEN
}

/// Calculate the encoded length of a byte slice as base32.
///
/// It doesn't take into account the Human-Readable-Part, the separator and the
/// checksum.
///
/// So, it calculates the length of converting a [`u8`] slice to a
/// [`bech32::u5`] slice.
pub const fn base32_len(len: usize) -> usize {
    let bits = len * 8;
    if bits % 5 == 0 {
        bits / 5
    } else {
        (bits / 5) + 1
    }
}
