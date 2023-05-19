// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-FileCopyrightText: © 2020 Dominik Spicher <dominikspicher@gmail.com>
// SPDX-License-Identifier: MIT

//! `ur` is a crate to interact with ["Uniform Resources (UR)"] encodings
//! of binary data.
//!
//! The encoding scheme is optimized for transport in URIs and QR codes.
//!
//! The [encoder](ur::BaseEncoder) allows a byte payload to be transmitted in
//! multiple stages, respecting maximum size requirements. Under the hood, a
//! [`fountain`] encoder is used to create an unbounded stream of URIs, subsets
//! of which can be recombined at the receiving side into the payload.
//!
//! For example:
//!
//! ```
//! const MAX_FRAGMENT_LENGTH: usize = 5;
//!
//! let data = "Ten chars!".repeat(10);
//!
//! let mut encoder = ur::Encoder::new();
//! encoder.start("bytes", data.as_bytes(), MAX_FRAGMENT_LENGTH);
//! assert_eq!(
//!     encoder.next_part().to_string(),
//!     "ur:bytes/1-20/lpadbbcsiecyvdidatkpfeghihjtcxiabdfevlms"
//! );
//!
//! let mut decoder = ur::Decoder::default();
//! while !decoder.is_complete() {
//!     let sequence = encoder.current_sequence();
//!     let part = encoder.next_part();
//!     // Simulate some communication loss
//!     if sequence & 1 > 0 {
//!         decoder.receive(part).unwrap();
//!     }
//! }
//! assert_eq!(decoder.message().unwrap().as_deref(), Some(data.as_bytes()));
//! ```
//!
//! ["Uniform Resources (UR)"]: https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-005-ur.md
//! [`fountain`]: https://en.wikipedia.org/wiki/Fountain_code
//!
//! The following useful building blocks are also part of the public API:
//!
//!  - The [`bytewords`] module contains functionality to encode byte payloads
//!    into a suitable alphabet, achieving hexadecimal byte-per-character
//!    efficiency.
//!
//!  - The [`fountain`] module provides an implementation of a fountain
//!    encoder, which splits up a byte payload into multiple segments and
//!    emits an unbounded stream of parts which can be recombined at the
//!    receiving decoder side.
#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;
extern crate core;

pub mod bytewords;
pub mod collections;
pub mod fountain;

mod ur;
mod xoshiro;

pub use self::ur::*;

const CRC32: crc::Crc<u32> = crc::Crc::<u32>::new(&crc::CRC_32_ISO_HDLC);

#[test]
fn test_crc() {
    assert_eq!(CRC32.checksum(b"Hello, world!"), 0xebe6_c6e6);
    assert_eq!(CRC32.checksum(b"Wolf"), 0x598c_84dc);
}
