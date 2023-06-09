// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use foundation_test_vectors::{CryptoAddressVector, URVector, UR};
use foundation_urtypes::registry::{CoinType, CryptoAddress, CryptoCoinInfo};

#[test]
fn test_roundtrip() {
    let vectors = URVector::new();

    for vector in vectors
        .iter()
        .filter(|v| matches!(v.ur, UR::CryptoAddress(_)))
    {
        let crypto_address = match vector.ur.unwrap_crypto_address() {
            CryptoAddressVector::Bitcoin(a) => {
                let mut address = CryptoAddress::try_from(a).unwrap();
                address.info = Some(CryptoCoinInfo::BTC_MAINNET);
                address.kind = None; // The test vector does not include this field.
                address
            }
            CryptoAddressVector::Ethereum(a) => CryptoAddress {
                info: Some(CryptoCoinInfo::new(CoinType::new(0x3c), 1)),
                kind: None,
                data: (a as &[_]).into(),
            },
        };

        let cbor = minicbor::to_vec(&crypto_address).unwrap();
        assert_eq!(vector.as_cbor, cbor);
    }
}
