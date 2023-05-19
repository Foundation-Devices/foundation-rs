// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-FileCopyrightText: © 2020 Dominik Spicher <dominikspicher@gmail.com>
// SPDX-License-Identifier: MIT

/// Calculates the quotient of `a` and `b`, rounding the results towards
/// positive infinity.
///
/// Note: there's an implementation on the `usize` type of this function,
/// but it's not stable yet.
#[must_use]
pub const fn div_ceil(a: usize, b: usize) -> usize {
    let d = a / b;
    let r = a % b;
    if r > 0 {
        d + 1
    } else {
        d
    }
}

/// Calculate a nominal fragment length from the message length and the maximum
/// fragment size.
///
/// # Examples
///
/// ```
/// # use foundation_ur::fountain::fragment_length;
///
/// const MESSAGE_LENGTH: usize = 100;
/// const MAX_FRAGMENT_LENGTH: usize = 27;
///
/// assert_eq!(fragment_length(MESSAGE_LENGTH, MAX_FRAGMENT_LENGTH), 25);
/// ```
///
/// # Panics
///
/// This function panics if `max_fragment_length` is zero.
#[must_use]
pub const fn fragment_length(message_length: usize, max_fragment_length: usize) -> usize {
    let fragment_count = div_ceil(message_length, max_fragment_length);
    div_ceil(message_length, fragment_count)
}

pub fn xor_into(v1: &mut [u8], v2: &[u8]) {
    assert_eq!(v1.len(), v2.len());

    for (x1, &x2) in v1.iter_mut().zip(v2.iter()) {
        *x1 ^= x2;
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[should_panic]
    #[test]
    fn test_div_ceil_divide_by_zero() {
        let _ = div_ceil(1, 0);
    }

    #[test]
    fn test_fragment_length() {
        assert_eq!(fragment_length(12345, 1955), 1764);
        assert_eq!(fragment_length(12345, 30000), 12345);

        assert_eq!(fragment_length(10, 4), 4);
        assert_eq!(fragment_length(10, 5), 5);
        assert_eq!(fragment_length(10, 6), 5);
        assert_eq!(fragment_length(10, 10), 10);
    }

    #[test]
    #[should_panic]
    fn test_fragment_length_greater_than_zero() {
        let _ = fragment_length(10, 0);
    }

    #[test]
    #[should_panic]
    fn test_xor_into_different_len() {
        let mut a = [0; 10];
        let b = [0; 9];
        xor_into(&mut a, &b);
    }

    #[test]
    fn test_xor_into() {
        const A: [u8; 10] = [0x91, 0x6e, 0xc6, 0x5c, 0xf7, 0x7c, 0xad, 0xf5, 0x5c, 0xd7];
        const B: [u8; 10] = [0xf9, 0xcd, 0xa1, 0xa1, 0x03, 0x00, 0x26, 0xdd, 0xd4, 0x2e];
        const C: [u8; 10] = [0x68, 0xa3, 0x67, 0xfd, 0xf4, 0x7c, 0x8b, 0x28, 0x88, 0xf9];

        let mut a = A.clone();
        xor_into(&mut a, &B);
        assert_eq!(a, C);

        xor_into(&mut a, &A);
        assert_eq!(a, B);
    }
}
