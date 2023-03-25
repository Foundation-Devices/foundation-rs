// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;
extern crate core;

mod len;
pub mod passport;
pub mod registry;
pub mod supply_chain_validation;

pub use self::len::max_fragment_len;
