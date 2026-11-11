// SPDX-FileCopyrightText: © 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Limits on peer-supplied values that are used to slice or resize a buffer.
//!
//! Everything else the pool sends is bounded by the field types in the
//! `heapless` build, and only by the frame (at most `RX_BUF_SIZE`) with `alloc`.

use crate::{Error, Field, Result};

/// Exact length of the hex-encoded previous block hash, in characters.
///
/// [`Work::prev_hash`] is decoded by slicing the field at fixed offsets, so
/// anything but 32 hex-encoded bytes is rejected.
///
/// [`Work::prev_hash`]: crate::Job
pub const PREV_HASH_HEX_LEN: usize = 64;

/// Maximum extranonce2 size accepted from the pool, in bytes.
///
/// The pool picks this value and it sizes the extranonce2 buffer the client
/// rolls, so it is bounded before it reaches any resize.
pub const EXTRANONCE2_SIZE_MAX: usize = 8;

/// Reject `actual` unless it is exactly `expected`.
pub(crate) fn check_exact(field: Field, actual: usize, expected: usize) -> Result<()> {
    if actual != expected {
        return Err(Error::InvalidFieldLength {
            field,
            expected,
            actual,
        });
    }
    Ok(())
}

/// Reject `actual` if it is over `max`.
pub(crate) fn check_max(field: Field, actual: usize, max: usize) -> Result<()> {
    if actual > max {
        return Err(Error::FieldTooLarge { field, max, actual });
    }
    Ok(())
}
