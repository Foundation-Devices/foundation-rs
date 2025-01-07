// SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    P2WPKH,
    P2WSH,
    P2TR,
    P2PKH,
    P2SH,
    P2PK,
}

impl AddressType {
    /// Is address type post segregated witness standards?
    pub fn is_segwit(&self) -> bool {
        match self {
            AddressType::P2WPKH | AddressType::P2WSH | AddressType::P2TR => true,
            _ => false,
        }
    }
}
