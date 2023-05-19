// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-FileCopyrightText: © 2020 Dominik Spicher <dominikspicher@gmail.com>
// SPDX-License-Identifier: MIT

//! Split up big payloads into constantly sized chunks which can be recombined by a decoder.
//!
//! The `fountain` module provides an implementation of a fountain encoder, which splits
//! up a byte payload into multiple segments and emits an unbounded stream of parts which
//! can be recombined at the receiving decoder site. The emitted parts are either original
//! payload segments, or constructed by xor-ing a certain set of payload segments.
//!
//! A seeded `Xoshiro` RNG ensures that the receiver can reconstruct which segments
//! were combined into the part.
//!
//! ```
//! # use foundation_ur::fountain::{Encoder, Decoder};
//! let xor = |a: &[u8], b: &[u8]| {
//!     a.iter()
//!         .zip(b.iter())
//!         .map(|(&x1, &x2)| x1 ^ x2)
//!         .collect::<Vec<_>>()
//! };
//!
//! let data = String::from("Ten chars!");
//! let max_length = 4;
//! // note the padding
//! let (p1, p2, p3) = (
//!     "Ten ".as_bytes(),
//!     "char".as_bytes(),
//!     "s!\u{0}\u{0}".as_bytes(),
//! );
//!
//! let mut encoder = Encoder::new();
//! encoder.start(data.as_bytes(), max_length);
//! let mut decoder = Decoder::default();
//!
//! // the fountain encoder first emits all original segments in order
//! let part1 = encoder.next_part();
//! assert_eq!(part1.data, p1);
//! // receive the first part into the decoder
//! decoder.receive(&part1).unwrap();
//!
//! let part2 = encoder.next_part();
//! assert_eq!(part2.data, p2);
//! // receive the second part into the decoder
//! decoder.receive(&part2).unwrap();
//!
//! // miss the third part
//! assert_eq!(encoder.next_part().data, p3);
//!
//! // the RNG then first selects the original third segment
//! assert_eq!(encoder.next_part().data, p3);
//!
//! // the RNG then selects all three segments to be xored
//! let xored = encoder.next_part();
//! assert_eq!(xored.data, xor(&xor(p1, p2), p3));
//! // receive the xored part into the decoder
//! // since it already has p1 and p2, p3 can be computed
//! // from p1 xor p2 xor p3
//! decoder.receive(&xored).unwrap();
//! assert!(decoder.is_complete());
//! assert_eq!(decoder.message().unwrap().as_deref(), Some(data.as_bytes()));
//! ```
//!
//! The index selection is biased towards combining fewer segments.
//!
//! ```
//! # use std::collections::BTreeSet;
//! # use foundation_ur::fountain::{Encoder, chooser};
//! let data = String::from("Fifty chars").repeat(5);
//! let max_length = 5;
//! let mut encoder = Encoder::new();
//! encoder.start(data.as_bytes(), max_length);
//! // 40% of the emitted parts represent original message segments
//! assert_eq!(
//!     (0..100)
//!         .map(|_i| {
//!             let part = encoder.next_part().into_indexed_part::<chooser::Alloc, Vec<u8>, BTreeSet<usize>>();
//!             if part.is_simple() {
//!                 1
//!             } else {
//!                 0
//!             }
//!         })
//!         .sum::<usize>(),
//!     39
//! );
//! let mut encoder = Encoder::new();
//! encoder.start(data.as_bytes(), max_length);
//! // On average, 3.33 segments (out of ten total) are combined into a part
//! assert_eq!(
//!     (0..100)
//!         .map(|_i| encoder.next_part().indexes::<chooser::Alloc, BTreeSet<usize>>().len())
//!         .sum::<usize>(),
//!     333
//! );
//! ```

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
