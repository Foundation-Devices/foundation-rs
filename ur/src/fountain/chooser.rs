// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-FileCopyrightText: © 2020 Dominik Spicher <dominikspicher@gmail.com>
// SPDX-License-Identifier: MIT

//! Fragment Chooser.

use crate::{
    collections::{Set, Vec},
    fountain::{sampler, sampler::BaseWeighted},
    xoshiro::Xoshiro256,
};

/// A fragment chooser.
#[cfg(feature = "alloc")]
pub type FragmentChooser = BaseFragmentChooser<Alloc>;

#[cfg(feature = "alloc")]
impl FragmentChooser {
    /// Construct a new [`FragmentChooser`].
    pub const fn new() -> Self {
        Self {
            sampler: sampler::Weighted::new(),
            indexes: alloc::vec::Vec::new(),
            shuffled: alloc::vec::Vec::new(),
        }
    }
}

/// A static fragment chooser.
pub type HeaplessFragmentChooser<const COUNT: usize> = BaseFragmentChooser<Heapless<COUNT>>;

impl<const COUNT: usize> HeaplessFragmentChooser<COUNT> {
    /// Construct a new [`HeaplessFragmentChooser`].
    pub const fn new() -> Self {
        Self {
            sampler: sampler::HeaplessWeighted::new(),
            indexes: heapless::Vec::new(),
            shuffled: heapless::Vec::new(),
        }
    }
}

/// Base fragment chooser.
#[derive(Default)]
pub struct BaseFragmentChooser<T: Types> {
    sampler: BaseWeighted<T::Sampler>,
    indexes: T::Indexes,
    shuffled: T::Shuffled,
}

impl<T: Types> BaseFragmentChooser<T> {
    /// Choose fragments from part data.
    ///
    /// # Panics
    ///
    /// This function panics if `sequence` or `sequence_count` are zero.
    pub fn choose_fragments<I>(&mut self, sequence: u32, sequence_count: u32, checksum: u32) -> I
    where
        I: Set<usize>,
    {
        assert!(sequence > 0 && sequence_count > 0);

        let mut set = I::default();
        if sequence <= sequence_count {
            set.insert((sequence - 1).try_into().unwrap())
                .expect("Not enough capacity to store single index");
            return set;
        }

        let seed = seed(sequence, checksum);
        let mut prng = Xoshiro256::from(seed.as_slice());

        let degree = choose_degree::<T>(&mut self.sampler, &mut prng, sequence_count);

        self.shuffled.clear();
        self.indexes.clear();
        self.indexes.reserve(sequence_count.try_into().unwrap());
        self.indexes.extend(0..sequence_count.try_into().unwrap());
        shuffle_indexes::<T>(&mut prng, &mut self.indexes, &mut self.shuffled, degree);

        set.extend(self.shuffled.iter().copied());
        set
    }
}

fn choose_degree<T: Types>(
    sampler: &mut BaseWeighted<T::Sampler>,
    prng: &mut Xoshiro256,
    sequence_count: u32,
) -> usize {
    sampler.set((0..sequence_count).map(|x| 1.0 / f64::from(x + 1)));
    usize::try_from(sampler.next(prng) + 1).unwrap()
}
///
/// # Errors
///
/// If serialization fails an error will be returned.

fn shuffle_indexes<T: Types>(
    prng: &mut Xoshiro256,
    indexes: &mut T::Indexes,
    shuffled: &mut T::Shuffled,
    degree: usize,
) {
    debug_assert!(degree <= indexes.len());

    shuffled.reserve(degree);
    while shuffled.len() < degree {
        let index = usize::try_from(prng.next_int(0, (indexes.len() - 1) as u64)).unwrap();
        let item = indexes.remove(index);
        shuffled.try_push(item).unwrap();
    }
}

fn seed(sequence: u32, checksum: u32) -> [u8; 8] {
    let mut seed = [0u8; 8];
    seed[0..4].copy_from_slice(&sequence.to_be_bytes());
    seed[4..8].copy_from_slice(&checksum.to_be_bytes());
    seed
}

/// Types for [`BaseFragmentChooser`].
pub trait Types: Default {
    /// Sampler types.
    type Sampler: sampler::Types;
    /// Indexes.
    type Indexes: Vec<usize>;
    /// Shuffled.
    type Shuffled: Vec<usize>;
}

/// [`alloc`] types for [`BaseFragmentChooser`].
#[cfg(feature = "alloc")]
#[derive(Default)]
pub struct Alloc;

#[cfg(feature = "alloc")]
impl Types for Alloc {
    type Sampler = sampler::Alloc;
    type Indexes = alloc::vec::Vec<usize>;
    type Shuffled = alloc::vec::Vec<usize>;
}

/// [`heapless`] types for [`BaseFragmentChooser`].
#[derive(Default)]
pub struct Heapless<const COUNT: usize>;

impl<const COUNT: usize> Types for Heapless<COUNT> {
    type Sampler = sampler::Heapless<COUNT>;
    type Indexes = heapless::Vec<usize, COUNT>;
    type Shuffled = heapless::Vec<usize, COUNT>;
}

#[cfg(test)]
#[cfg(feature = "alloc")]
pub mod tests {
    use super::*;
    use crate::fountain::sampler::Weighted;
    use crate::fountain::util::{div_ceil, fragment_length};
    use crate::xoshiro::test_utils::make_message;
    use crate::CRC32;
    use alloc::collections::BTreeSet;

    const EXPECTED_FRAGMENT_INDEXES: [&[usize]; 30] = [
        &[0],
        &[1],
        &[2],
        &[3],
        &[4],
        &[5],
        &[6],
        &[7],
        &[8],
        &[9],
        &[10],
        &[9],
        &[2, 5, 6, 8, 9, 10],
        &[8],
        &[1, 5],
        &[1],
        &[0, 2, 4, 5, 8, 10],
        &[5],
        &[2],
        &[2],
        &[0, 1, 3, 4, 5, 7, 9, 10],
        &[0, 1, 2, 3, 5, 6, 8, 9, 10],
        &[0, 2, 4, 5, 7, 8, 9, 10],
        &[3, 5],
        &[4],
        &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        &[0, 1, 3, 4, 5, 6, 7, 9, 10],
        &[6],
        &[5, 6],
        &[7],
    ];

    #[test]
    fn test_fragment_chooser() {
        let mut fragment_chooser = FragmentChooser::default();

        let message = make_message("Wolf", 1024);
        let checksum = CRC32.checksum(&message);
        let fragment_length = fragment_length(message.len(), 100);
        let sequence_count = u32::try_from(div_ceil(message.len(), fragment_length)).unwrap();

        for (sequence, expected_indexes) in EXPECTED_FRAGMENT_INDEXES
            .iter()
            .map(|indexes| indexes.iter().copied().collect::<BTreeSet<usize>>())
            .enumerate()
        {
            let indexes: BTreeSet<usize> = fragment_chooser.choose_fragments(
                u32::try_from(sequence + 1).unwrap(),
                sequence_count,
                checksum,
            );
            let expected_indexes = expected_indexes
                .iter()
                .copied()
                .collect::<BTreeSet<usize>>();
            assert_eq!(indexes, expected_indexes);
        }
    }

    #[test]
    fn test_choose_degree() {
        const MESSAGE_LEN: usize = 1024;
        const EXPECTED_DEGREES: [usize; 200] = [
            11, 3, 6, 5, 2, 1, 2, 11, 1, 3, 9, 10, 10, 4, 2, 1, 1, 2, 1, 1, 5, 2, 4, 10, 3, 2, 1,
            1, 3, 11, 2, 6, 2, 9, 9, 2, 6, 7, 2, 5, 2, 4, 3, 1, 6, 11, 2, 11, 3, 1, 6, 3, 1, 4, 5,
            3, 6, 1, 1, 3, 1, 2, 2, 1, 4, 5, 1, 1, 9, 1, 1, 6, 4, 1, 5, 1, 2, 2, 3, 1, 1, 5, 2, 6,
            1, 7, 11, 1, 8, 1, 5, 1, 1, 2, 2, 6, 4, 10, 1, 2, 5, 5, 5, 1, 1, 4, 1, 1, 1, 3, 5, 5,
            5, 1, 4, 3, 3, 5, 1, 11, 3, 2, 8, 1, 2, 1, 1, 4, 5, 2, 1, 1, 1, 5, 6, 11, 10, 7, 4, 7,
            1, 5, 3, 1, 1, 9, 1, 2, 5, 5, 2, 2, 3, 10, 1, 3, 2, 3, 3, 1, 1, 2, 1, 3, 2, 2, 1, 3, 8,
            4, 1, 11, 6, 3, 1, 1, 1, 1, 1, 3, 1, 2, 1, 10, 1, 1, 8, 2, 7, 1, 2, 1, 9, 2, 10, 2, 1,
            3, 4, 10,
        ];

        let mut sampler = Weighted::default();
        let fragment_length = fragment_length(MESSAGE_LEN, 100);
        let sequence_count = u32::try_from(div_ceil(MESSAGE_LEN, fragment_length)).unwrap();

        for (nonce, &expected_degree) in EXPECTED_DEGREES.iter().enumerate() {
            let mut prng = Xoshiro256::from(format!("Wolf-{}", nonce + 1).as_str());
            let calculated_degree = choose_degree::<Alloc>(&mut sampler, &mut prng, sequence_count);
            assert_eq!(calculated_degree, expected_degree);
        }
    }

    #[test]
    fn test_shuffle() {
        const COUNT: usize = 10;
        const EXPECTED: &[[usize; COUNT]] = &[
            [6, 4, 9, 3, 10, 5, 7, 8, 1, 2],
            [10, 8, 6, 5, 1, 2, 3, 9, 7, 4],
            [6, 4, 5, 8, 9, 3, 2, 1, 7, 10],
            [7, 3, 5, 1, 10, 9, 4, 8, 2, 6],
            [8, 5, 7, 10, 2, 1, 4, 3, 9, 6],
            [4, 3, 5, 6, 10, 2, 7, 8, 9, 1],
            [5, 1, 3, 9, 4, 6, 2, 10, 7, 8],
            [2, 1, 10, 8, 9, 4, 7, 6, 3, 5],
            [6, 7, 10, 4, 8, 9, 2, 3, 1, 5],
            [10, 2, 1, 7, 9, 5, 6, 3, 4, 8],
        ];

        let mut prng = Xoshiro256::from("Wolf");
        for &expected in EXPECTED {
            let mut indexes: alloc::vec::Vec<usize> = (1..=COUNT).collect();
            let mut shuffled = alloc::vec::Vec::new();
            shuffle_indexes::<Alloc>(&mut prng, &mut indexes, &mut shuffled, COUNT);

            assert_eq!(shuffled, expected);
        }
    }
}
