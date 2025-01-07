// SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Partially Signed Bitcoin Transaction (PSBT) library.

#![cfg_attr(not(feature = "std"), no_std)]
// TODO(jeandudey): Remove this before PR.
#![allow(dead_code)]

pub mod address;
pub mod encoder;
pub mod parser;
pub mod signing;
pub mod taproot;
pub mod transaction;
pub mod validation;
