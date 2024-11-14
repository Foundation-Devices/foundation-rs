// SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

use foundation_psbt::{
    encoder::compact_size::encode_compact_size, parser::compact_size::compact_size,
};
use heapless::Vec;

// Check encoder and parser are inverses.
#[test]
fn roundtrip() {
    const VALUES: [(u64, usize); 4] = [
        (0xAA, 1),
        (0xBBAA, 3),
        (0xDDCC_BBAA, 5),
        (0xBEEF_FFEE_DDCC_BBAA, 9),
    ];

    let mut buf: Vec<u8, 9> = Vec::new();

    for (value, len) in VALUES {
        buf.clear();
        buf.resize(len, 0).unwrap();
        assert_eq!(encode_compact_size(&mut buf[..], value), Ok(len));
        let (_, v) = compact_size::<_, nom::error::Error<_>>(&buf[..]).unwrap();
        assert_eq!(v, value);
    }
}
