// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Standard CBOR encodable types.

mod timestamp;
pub mod uuid;

pub use self::timestamp::Timestamp;
