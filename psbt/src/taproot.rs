// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use bitcoin_hashes::sha256t_hash_newtype;
use secp256k1::XOnlyPublicKey;

// Define our own Taproot TapLeaf hash type since the one in rust-bitcoin is
// unusable for us since that library doesn't work without `alloc`.
//
// TODO:
//  - If this is available independently of rust-bitcoin, we should use that.
sha256t_hash_newtype! {
    pub struct Leaf = hash_str("TapLeaf");

    #[hash_newtype(forward)]
    pub struct LeafHash(_);
}

sha256t_hash_newtype! {
    pub struct TapBranch = hash_str("TapBranch");

    #[hash_newtype(forward)]
    pub struct TapNodeHash(_);
}

#[derive(Debug, Clone)]
pub struct TaprootScriptSignature {
    pub x_only_public_key: XOnlyPublicKey,
    pub leaf_hash: LeafHash,
}
