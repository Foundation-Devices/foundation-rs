// SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use bitcoin_primitives::TapLeafHash;
use secp256k1::XOnlyPublicKey;

#[derive(Debug, Clone)]
pub struct TaprootScriptSignature {
    pub x_only_public_key: XOnlyPublicKey,
    pub leaf_hash: TapLeafHash,
}
