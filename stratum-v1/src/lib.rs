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
//! peer bytes produce an [`Error`] rather than a panic; see [`limits`]. Other
//! fields are bounded by their types in the default `heapless` build. With
//! `alloc` they are bounded only by the frame, which parsing always takes from
//! the fixed-size receive buffer, so allocation stays within `RX_BUF_SIZE`.
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
