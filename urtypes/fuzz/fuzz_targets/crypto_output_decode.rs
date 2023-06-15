// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

#![no_main]

use foundation_arena::Arena;
use foundation_urtypes::registry::Terminal;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let a: Arena<_, 32> = Arena::new();
    minicbor::decode_with::<_, Terminal>(data, &mut &a).ok();
});
