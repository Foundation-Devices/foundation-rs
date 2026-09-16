// SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Stratum v1 client.
//!
//! This library provides client side functions to create requests and parse responses for Stratum v1 protocol.
//!
//! # Logging and credentials
//!
//! `mining.authorize` carries the pool user and password, and `mining.submit`
//! repeats the user on every share. Neither frame is ever written to the log,
//! under either backend and at any level; they are logged as their method,
//! request id and byte count, with the serialized body replaced by a
//! placeholder. The same applies to the pool's replies to those two requests,
//! because pools echo the submitted user back in error details.
//!
//! What *is* logged, and is therefore documented as carrying no authorization
//! parameter:
//!
//! - `mining.configure`, `mining.subscribe` and `mining.suggest_difficulty`, in
//!   full. Their parameters are the extension list, the optional device
//!   identifier and a difficulty number — connection metadata the caller has
//!   chosen to publish to the pool.
//! - Notifications and any response not matched to a pending authorization or
//!   share, in full.
//! - For every frame: byte counts, buffer offsets, request ids, the request
//!   method, and the connection state transitions.
//!
//! Raw receive-buffer contents are not logged at all: a buffer spans an
//! arbitrary number of frames, so at that point there is no way to tell whether
//! one of them echoes a credential.
//!
//! [`Error::Pool`] is the one credential-adjacent value the library hands back
//! rather than logging; see its documentation before logging it yourself.

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
