// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use ur::fountain::part::Part;

/// Calculates the maximum fragment length in bytes that can fit in
/// `max_characters`, for example, it could be the maximum number of
/// alphanumeric characters in a given QR code.
///
/// - `max_sequence_number` is the maximum number that `seq-len` will reach.
///
/// ```text
/// ur:<type>/<seq>-<seq-len>/<part><fragment><crc>
///                                 ▲        ▲
///                                 └───┬────┘
///                  Length in bytes◄───┘
/// ```
///
/// # Examples
///
/// Basic usage:
///
/// ```
/// # use foundation_ur::max_fragment_len;
/// let max_sequence_number = 1000;
/// let max_characters = 500;
/// let fragment_len = max_fragment_len("crypto-coininfo", max_sequence_number, max_characters);
///
/// assert_eq!(fragment_len, 192);
/// ```
pub const fn max_fragment_len(
    max_ur_type: &str,
    max_sequence_number: usize,
    max_characters: usize,
) -> usize {
    let mut non_payload_characters = 0;

    non_payload_characters += max_ur_type.len();
    non_payload_characters += "/".len();
    non_payload_characters += digit_count(u32::MAX as usize);
    non_payload_characters += "-".len();
    non_payload_characters += digit_count(max_sequence_number);
    non_payload_characters += "/".len();
    non_payload_characters += Part::max_encoded_len() * 2;
    non_payload_characters += 4 * 2;

    (max_characters - non_payload_characters) / 2
}

// Calculate the number of digits in a number.
const fn digit_count(mut v: usize) -> usize {
    if v == 0 {
        return 1;
    }

    // Using this method as ilog10 is not stable in 1.65.
    let mut count = 0;
    while v != 0 {
        v /= 10;
        count += 1;
    }

    count
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_digit_count() {
        assert_eq!(digit_count(9), 1);
        assert_eq!(digit_count(99), 2);
        assert_eq!(digit_count(999), 3);
        assert_eq!(digit_count(9999), 4);
        assert_eq!(digit_count(99999), 5);
    }
}
