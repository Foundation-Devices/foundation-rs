// SPDX-FileCopyrightText: © 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Maxima enforced on peer-supplied frames.
//!
//! Every value here is the capacity the `heapless` build already gets from the
//! type of the corresponding field. Enforcing them explicitly serves two
//! purposes:
//!
//! - With `alloc`, the deserialized strings and vectors are unbounded, so
//!   nothing else would stop a pool from handing us a value larger than the
//!   fixed-size buffers it is later copied into.
//! - It turns "the field is the wrong size" from an out-of-bounds slice or an
//!   inconsistent internal state into a plain [`Error`].
//!
//! Both builds therefore reject the same frames, with the same errors.

use crate::{Error, Field, Result};

/// Maximum length of the `job_id` field, in characters.
pub const JOB_ID_LEN_MAX: usize = 32;

/// Exact length of the hex-encoded previous block hash, in characters.
///
/// This one is not a maximum: [`Work::prev_hash`] is decoded by slicing the
/// field at fixed offsets, so anything but 32 hex-encoded bytes is rejected.
///
/// [`Work::prev_hash`]: crate::Job
pub const PREV_HASH_HEX_LEN: usize = 64;

/// Maximum length of the hex-encoded first part of the coinbase transaction.
pub const COINB1_HEX_LEN_MAX: usize = 256;

/// Maximum length of the hex-encoded second part of the coinbase transaction.
pub const COINB2_HEX_LEN_MAX: usize = 260;

/// Maximum number of merkle branch nodes accepted in a `mining.notify`.
pub const MERKLE_BRANCH_LEN_MAX: usize = 16;

/// Maximum length of the hex-encoded extranonce1, in characters.
pub const EXTRANONCE1_HEX_LEN_MAX: usize = 16;

/// Maximum extranonce2 size accepted from the pool, in bytes.
///
/// The pool picks this value, and it drives the size of the extranonce2 buffer
/// the client rolls, so it has to be bounded before it reaches any allocation
/// or resize.
pub const EXTRANONCE2_SIZE_MAX: usize = 8;

/// Maximum number of subscriptions accepted in a `mining.subscribe` response.
pub const SUBSCRIPTIONS_LEN_MAX: usize = 2;

/// Maximum number of parameters accepted in a notification that carries a
/// single value.
pub const SINGLE_PARAM_LEN_MAX: usize = 1;

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
