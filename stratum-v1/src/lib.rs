// SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Stratum v1 client.
//!
//! This library provides client side functions to create requests and parse responses for Stratum v1 protocol.

#![no_std]
#![macro_use]
pub(crate) mod fmt;

#[cfg(feature = "alloc")]
#[macro_use]
extern crate alloc;

mod client;
mod error;

pub use client::{Client, Extensions, Info, Job, Message, Share, VersionRolling};
pub use error::{Error, Result};
