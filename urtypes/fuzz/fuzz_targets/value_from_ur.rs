// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

#![no_main]

use arbitrary::Arbitrary;
use foundation_urtypes::value::Value;
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
pub struct Data<'a> {
    pub ur_type: &'a str,
    pub payload: &'a [u8],
}

fuzz_target!(|data: Data| {
    Value::from_ur(data.ur_type, data.payload).ok();
});
