// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-FileCopyrightText: © 2020 Dominik Spicher <dominikspicher@gmail.com>
// SPDX-License-Identifier: MIT

//! Random Sampler.

use crate::collections::Vec;

/// A random sampler.
#[cfg(feature = "alloc")]
pub type Weighted = BaseWeighted<Alloc>;

#[cfg(feature = "alloc")]
impl Weighted {
    /// Construct a new [`Weighted`].
    pub const fn new() -> Self {
        Self {
            aliases: alloc::vec::Vec::new(),
            probs: alloc::vec::Vec::new(),
            weights: alloc::vec::Vec::new(),
            s: alloc::vec::Vec::new(),
            l: alloc::vec::Vec::new(),
        }
    }
}

/// A static random sampler.
///
/// `N` represents the maximum number of probabilities (weights)
/// that can be passed to the sampler. This corresponds to the sequence
/// count number in UR parts.
pub type HeaplessWeighted<const N: usize> = BaseWeighted<Heapless<N>>;

impl<const N: usize> HeaplessWeighted<N> {
    /// Construct a new [`HeaplessWeighted`].
    pub const fn new() -> Self {
        Self {
            aliases: heapless::Vec::new(),
            probs: heapless::Vec::new(),
            weights: heapless::Vec::new(),
            s: heapless::Vec::new(),
            l: heapless::Vec::new(),
        }
    }
}

/// Weighted random sampler.
#[derive(Default)]
pub struct BaseWeighted<T: Types> {
    aliases: T::Aliases,
    probs: T::Probs,
    weights: T::Weights,

    s: T::S,
    l: T::L,
}

impl<T: Types> BaseWeighted<T> {
    /// Initialize random sampler.
    pub fn set<I: ExactSizeIterator<Item = f64>>(&mut self, weights: I) {
        // The maximum number set of probabilities is u32::MAX, as seqNum in a part
        // wraps at u32::MAX, however, seqLen can be higher than a u32::MAX per the
        // CDDL specification, that should be fixed in the specification.
        let count =
            u32::try_from(weights.len()).expect("probabilities set is larger than expected");

        self.weights.clear();
        self.weights.reserve(weights.len());
        self.weights.extend(weights);

        let mut summed = 0.0;
        for &p in self.weights.iter() {
            assert!(p >= 0.0, "negative probability encountered");
            summed += p;
        }
        assert!(summed > 0.0, "probabilities don't sum to a positive value");

        let ratio = f64::from(count) / summed;
        for p in self.weights.iter_mut() {
            *p *= ratio;
        }

        self.reset(self.weights.len());

        for i in (0..self.weights.len()).rev() {
            if self.weights[i] < 1.0 {
                self.s.try_push(i).unwrap();
            } else {
                self.l.try_push(i).unwrap();
            }
        }

        while !self.s.is_empty() && !self.l.is_empty() {
            let a = self.s.pop().unwrap();
            let g = self.l.pop().unwrap();
            self.probs[a] = self.weights[a];
            self.aliases[a] = g.try_into().unwrap();
            self.weights[g] += self.weights[a] - 1.0;
            if self.weights[g] < 1.0 {
                self.s.try_push(g).unwrap();
            } else {
                self.l.try_push(g).unwrap();
            }
        }

        while !self.l.is_empty() {
            let g = self.l.pop().unwrap();
            self.probs[g] = 1.0;
        }

        while !self.s.is_empty() {
            let a = self.s.pop().unwrap();
            self.probs[a] = 1.0;
        }
    }

    /// Next sample.
    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_precision_loss)]
    #[allow(clippy::cast_sign_loss)]
    pub fn next(&mut self, xoshiro: &mut crate::xoshiro::Xoshiro256) -> u32 {
        let r1 = xoshiro.next_double();
        let r2 = xoshiro.next_double();
        let n = self.probs.len();
        let i = (n as f64 * r1) as usize;
        if r2 < self.probs[i] {
            i as u32
        } else {
            self.aliases[i]
        }
    }

    fn reset(&mut self, len: usize) {
        self.aliases.clear();
        self.probs.clear();
        self.s.clear();
        self.l.clear();

        self.aliases
            .try_resize(len, 0)
            .expect("not enough memory for sampler");
        self.probs
            .try_resize(len, 0.0)
            .expect("not enough memory for sampler");
    }
}

/// Types for [`BaseWeighted`].
pub trait Types: Default {
    /// Aliases.
    type Aliases: Vec<u32>;
    /// Probabilities.
    type Probs: Vec<f64>;
    /// Weights.
    type Weights: Vec<f64>;
    /// S.
    type S: Vec<usize>;
    /// L.
    type L: Vec<usize>;
}

/// [`alloc`] types for [`BaseWeighted`].
#[derive(Default)]
#[cfg(feature = "alloc")]
pub struct Alloc;

#[cfg(feature = "alloc")]
impl Types for Alloc {
    type Aliases = alloc::vec::Vec<u32>;
    type Probs = alloc::vec::Vec<f64>;
    type Weights = alloc::vec::Vec<f64>;
    type S = alloc::vec::Vec<usize>;
    type L = alloc::vec::Vec<usize>;
}

/// [`heapless`] types for [`BaseWeighted`].
#[derive(Default)]
pub struct Heapless<const COUNT: usize>;

impl<const COUNT: usize> Types for Heapless<COUNT> {
    type Aliases = heapless::Vec<u32, COUNT>;
    type Probs = heapless::Vec<f64, COUNT>;
    type Weights = heapless::Vec<f64, COUNT>;
    type S = heapless::Vec<usize, COUNT>;
    type L = heapless::Vec<usize, COUNT>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::iter;

    const WEIGHTS_LEN: usize = 4;
    const WEIGHTS: [f64; WEIGHTS_LEN] = [1.0, 2.0, 4.0, 8.0];
    const EXPECTED_SAMPLES: &[u32] = &[
        3, 3, 3, 3, 3, 3, 3, 0, 2, 3, 3, 3, 3, 1, 2, 2, 1, 3, 3, 2, 3, 3, 1, 1, 2, 1, 1, 3, 1, 3,
        1, 2, 0, 2, 1, 0, 3, 3, 3, 1, 3, 3, 3, 3, 1, 3, 2, 3, 2, 2, 3, 3, 3, 3, 2, 3, 3, 0, 3, 3,
        3, 3, 1, 2, 3, 3, 2, 2, 2, 1, 2, 2, 1, 2, 3, 1, 3, 0, 3, 2, 3, 3, 3, 3, 3, 3, 3, 3, 2, 3,
        1, 3, 3, 2, 0, 2, 2, 3, 1, 1, 2, 3, 2, 3, 3, 3, 3, 2, 3, 3, 3, 3, 3, 2, 3, 1, 2, 1, 1, 3,
        1, 3, 2, 2, 3, 3, 3, 1, 3, 3, 3, 3, 3, 3, 3, 3, 2, 3, 2, 3, 3, 1, 2, 3, 3, 1, 3, 2, 3, 3,
        3, 2, 3, 1, 3, 0, 3, 2, 1, 1, 3, 1, 3, 2, 3, 3, 3, 3, 2, 0, 3, 3, 1, 3, 0, 2, 1, 3, 3, 1,
        1, 3, 1, 2, 3, 3, 3, 0, 2, 3, 2, 0, 1, 3, 3, 3, 2, 2, 2, 3, 3, 3, 3, 3, 2, 3, 3, 3, 3, 2,
        3, 3, 2, 0, 2, 3, 3, 3, 3, 2, 1, 1, 1, 2, 1, 3, 3, 3, 2, 2, 3, 3, 1, 2, 3, 0, 3, 2, 3, 3,
        3, 3, 0, 2, 2, 3, 2, 2, 3, 3, 3, 3, 1, 3, 2, 3, 3, 3, 3, 3, 2, 2, 3, 1, 3, 0, 2, 1, 3, 3,
        3, 3, 3, 3, 3, 3, 1, 3, 3, 3, 3, 2, 2, 2, 3, 1, 1, 3, 2, 2, 0, 3, 2, 1, 2, 1, 0, 3, 3, 3,
        2, 2, 3, 2, 1, 2, 0, 0, 3, 3, 2, 3, 3, 2, 3, 3, 3, 3, 3, 2, 2, 2, 3, 3, 3, 3, 3, 1, 1, 3,
        2, 2, 3, 1, 1, 0, 1, 3, 2, 3, 3, 2, 3, 3, 2, 3, 3, 2, 2, 2, 2, 3, 2, 2, 2, 2, 2, 1, 2, 3,
        3, 2, 2, 2, 2, 3, 3, 2, 0, 2, 1, 3, 3, 3, 3, 0, 3, 3, 3, 3, 2, 2, 3, 1, 3, 3, 3, 2, 3, 3,
        3, 2, 3, 3, 3, 3, 2, 3, 2, 1, 3, 3, 3, 3, 2, 2, 0, 1, 2, 3, 2, 0, 3, 3, 3, 3, 3, 3, 1, 3,
        3, 2, 3, 2, 2, 3, 3, 3, 3, 3, 2, 2, 3, 3, 2, 2, 2, 1, 3, 3, 3, 3, 1, 2, 3, 2, 3, 3, 2, 3,
        2, 3, 3, 3, 2, 3, 1, 2, 3, 2, 1, 1, 3, 3, 2, 3, 3, 2, 3, 3, 0, 0, 1, 3, 3, 2, 3, 3, 3, 3,
        1, 3, 3, 0, 3, 2, 3, 3, 1, 3, 3, 3, 3, 3, 3, 3, 0, 3, 3, 2,
    ];

    #[test]
    fn test_sampler() {
        fn test<T: Types>(sampler: &mut BaseWeighted<T>) {
            let mut xoshiro = crate::xoshiro::Xoshiro256::from("Wolf");
            sampler.set(WEIGHTS.iter().copied());

            for &e in EXPECTED_SAMPLES {
                assert_eq!(sampler.next(&mut xoshiro), e);
            }
        }

        let mut heapless_weighted: HeaplessWeighted<WEIGHTS_LEN> = HeaplessWeighted::new();
        let mut weighted = Weighted::new();

        test(&mut heapless_weighted);
        test(&mut weighted);
    }

    #[test]
    #[should_panic = "can't reserve more capacity, remaining 3 and need 1"]
    fn test_sampler_static_capacity() {
        let mut sampler: HeaplessWeighted<{ WEIGHTS_LEN - 1 }> = Default::default();
        sampler.set(WEIGHTS.iter().copied());
    }

    #[test]
    #[should_panic(expected = "negative probability encountered")]
    fn test_negative_weight() {
        Weighted::default().set([2.0, -1.0].into_iter());
    }

    #[test]
    #[should_panic(expected = "probabilities don't sum to a positive value")]
    fn test_zero_weights() {
        Weighted::default().set(iter::once(0.0));
    }
}
