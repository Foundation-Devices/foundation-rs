// SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

pub const VALID_HEADER: &[u8] = include_bytes!("../data/v2.3.0-firmware-header-passport.bin");
pub const INVALID_MAGIC: &[u8] = include_bytes!("../data/v2.3.0-firmware-magic-passport.bin");
pub const INVALID_MAX_LENGTH: &[u8] =
    include_bytes!("../data/v2.3.0-firmware-max-length-passport.bin");
pub const INVALID_MIN_LENGTH: &[u8] =
    include_bytes!("../data/v2.3.0-firmware-min-length-passport.bin");
pub const INVALID_PUBLIC_KEY1: &[u8] =
    include_bytes!("../data/v2.3.0-firmware-public-key1-passport.bin");
pub const INVALID_PUBLIC_KEY2: &[u8] =
    include_bytes!("../data/v2.3.0-firmware-public-key2-passport.bin");
pub const INVALID_TIMESTAMP: &[u8] =
    include_bytes!("../data/v2.3.0-firmware-timestamp-passport.bin");
