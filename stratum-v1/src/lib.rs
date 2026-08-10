// SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Stratum v1 client.
//!
//! This library provides client side functions to create requests and parse responses for Stratum v1 protocol.
//!
//! # Handling of malformed peer input
//!
//! The pool is not trusted. Every length and domain coming off the wire is
//! validated before it is used to slice, shift or resize anything, so arbitrary
//! peer bytes produce an [`Error`] rather than a panic. The maxima are listed
//! in [`limits`] and are identical for both builds:
//!
//! - In the default `heapless` build they are the capacities of the fixed-size
//!   buffers the fields are decoded into.
//! - With `alloc`, the deserialized strings and vectors are unbounded, so the
//!   same maxima are enforced explicitly. Parsing always runs over a single
//!   frame taken from the fixed-size receive buffer, which bounds allocation to
//!   `RX_BUF_SIZE` regardless.
//!
//! A frame that fails validation is consumed before its error is returned, so
//! it cannot poison the frames behind it, and client state is left untouched.
//! See [`Client::poll_message`].

#![no_std]
#![macro_use]
pub(crate) mod fmt;

#[cfg(feature = "alloc")]
#[macro_use]
extern crate alloc;

mod client;
mod error;
pub mod limits;

pub use client::{Client, Extensions, Info, Job, Message, Share, VersionRolling};
pub use error::{Error, Field, Result};
