// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
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
