// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

#![no_main]

use foundation_urtypes::registry::Address;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    minicbor::decode::<'_, Address>(data).ok();
});
