// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use foundation_test_vectors::{AddressVector, URVector, UR};
use foundation_urtypes::registry::{Address, CoinInfo, CoinType};

#[test]
fn test_roundtrip() {
    let vectors = URVector::new();

    for vector in vectors.iter().filter(|v| matches!(v.ur, UR::Address(_))) {
        let crypto_address = match vector.ur.unwrap_address() {
            AddressVector::Bitcoin(a) => {
                let mut address = Address::try_from(a).unwrap();
                address.info = Some(CoinInfo::BTC_MAINNET);
                address.kind = None; // The test vector does not include this field.
                address
            }
            AddressVector::Ethereum(a) => Address {
                info: Some(CoinInfo::new(CoinType::new(0x3c), 1)),
                kind: None,
                data: (a as &[_]).into(),
            },
        };

        let cbor = minicbor::to_vec(&crypto_address).unwrap();
        assert_eq!(vector.as_cbor, cbor);
    }
}
