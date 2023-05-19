// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-FileCopyrightText: © 2020 Dominik Spicher <dominikspicher@gmail.com>
// SPDX-License-Identifier: MIT

//! # Fountain encoder/decoder.
//!
//! The `fountain` module provides an implementation of a fountain encoder, which splits
//! up a byte payload into multiple segments and emits an unbounded stream of parts which
//! can be recombined at the receiving decoder site. The emitted parts are either original
//! payload segments, or constructed by xor-ing a certain set of payload segments.

pub mod chooser;
pub mod decoder;
pub mod encoder;
pub mod part;
pub mod sampler;

mod util;

#[cfg(feature = "alloc")]
pub use self::decoder::Decoder;
pub use self::decoder::{BaseDecoder, HeaplessDecoder};

#[cfg(feature = "alloc")]
pub use self::encoder::Encoder;
pub use self::encoder::{BaseEncoder, HeaplessEncoder};

pub use self::util::fragment_length;
