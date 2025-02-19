// SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

use foundation_psbt::{address::AddressType, transaction::Output};

#[test]
fn test_output_p2wsh() {
    const SCRIPT_PUBKEY: &[u8] = &[
        0x00, 0x20, 0x6e, 0x34, 0x0b, 0x9c, 0xff, 0xb3, 0x7a, 0x98, 0x9c, 0xa5, 0x44, 0xe6, 0xbb,
        0x78, 0x0a, 0x2c, 0x78, 0x90, 0x1d, 0x3f, 0xb3, 0x37, 0x38, 0x76, 0x85, 0x11, 0xa3, 0x06,
        0x17, 0xaf, 0xa0, 0x1d,
    ];
    const SCRIPT_HASH: &[u8] = &[
        0x6e, 0x34, 0x0b, 0x9c, 0xff, 0xb3, 0x7a, 0x98, 0x9c, 0xa5, 0x44, 0xe6, 0xbb, 0x78, 0x0a,
        0x2c, 0x78, 0x90, 0x1d, 0x3f, 0xb3, 0x37, 0x38, 0x76, 0x85, 0x11, 0xa3, 0x06, 0x17, 0xaf,
        0xa0, 0x1d,
    ];

    let output = Output {
        value: 0,
        script_pubkey: SCRIPT_PUBKEY,
    };

    match output.address() {
        Some((AddressType::P2WSH, hash)) => assert_eq!(hash, SCRIPT_HASH),
        _ => panic!(),
    }
}
