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
/// use ur::fountain::fragment_length;
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
    debug_assert_eq!(v1.len(), v2.len());

    for (x1, &x2) in v1.iter_mut().zip(v2.iter()) {
        *x1 ^= x2;
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

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
    fn test_xor_into() {
        let mut rng = crate::xoshiro::Xoshiro256::from("Wolf");

        let data1 = rng.next_bytes(10);
        assert_eq!(hex::encode(&data1), "916ec65cf77cadf55cd7");

        let data2 = rng.next_bytes(10);
        assert_eq!(hex::encode(&data2), "f9cda1a1030026ddd42e");

        let mut data3 = data1.clone();
        xor_into(&mut data3, &data2);
        assert_eq!(hex::encode(&data3), "68a367fdf47c8b2888f9");

        xor_into(&mut data3, &data1);
        assert_eq!(hex::encode(data3), hex::encode(data2));
    }
}
