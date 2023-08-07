// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use bitcoin_hashes::{hash_newtype, sha256d};

hash_newtype! {
    pub struct Txid(sha256d::Hash);
}
