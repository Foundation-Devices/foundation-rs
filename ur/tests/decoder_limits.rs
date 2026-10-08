// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT

#![cfg(feature = "alloc")]

use foundation_ur::{fountain, Decoder, Encoder, UR};

const FIRST_SEQUENCE: u32 = 1;
const SINGLE_FRAGMENT_COUNT: u32 = 1;
const SEQUENCE_CAPACITY: usize = 4;
const MIXED_PART_CAPACITY: usize = 4;
const QUEUE_CAPACITY: usize = 4;
const SINGLE_ENTRY_QUEUE_CAPACITY: usize = 1;
const NO_CAPACITY: usize = 0;
const UR_TYPE_CAPACITY: usize = 16;
const ENCODED_FRAGMENT_CAPACITY: usize = 128;
const MESSAGE_CAPACITY: usize = 32;
const SINGLE_BYTE_FRAGMENT_LEN: usize = 1;
const TWO_PART_FRAGMENT_LEN: usize = 4;
const TWO_PART_COUNT: usize = 2;
const TWO_PART_MESSAGE_LEN: usize = TWO_PART_COUNT * TWO_PART_FRAGMENT_LEN;
const MIXED_SEQUENCE_SEARCH_END: u32 = 100;
const EXCESS_SEQUENCE_COUNT: u32 = (SEQUENCE_CAPACITY * 2) as u32;
const FOUR_PART_MESSAGE_LEN: usize = SEQUENCE_CAPACITY * SINGLE_BYTE_FRAGMENT_LEN;

#[test]
fn rejected_sequence_does_not_retain_type() {
    let mut encoder = Encoder::new();
    encoder.start("bytes", &[1; TWO_PART_MESSAGE_LEN], TWO_PART_FRAGMENT_LEN);
    let serialized = encoder.next_part().to_string();
    let payload = serialized.rsplit('/').next().unwrap();
    let invalid = format!("ur:bytes/{FIRST_SEQUENCE}-{SINGLE_FRAGMENT_COUNT}/{payload}");
    let mut decoder = Decoder::default();
    assert!(decoder.receive(UR::parse(&invalid).unwrap()).is_err());
    assert_eq!(decoder.ur_type(), None);
    assert!(decoder.is_empty());
    let mut honest = Encoder::new();
    honest.start(
        "crypto-psbt",
        &[1; TWO_PART_MESSAGE_LEN],
        TWO_PART_FRAGMENT_LEN,
    );
    decoder.receive(honest.next_part()).unwrap();
}

#[test]
fn matching_metadata_above_heapless_capacity_returns_error() {
    const DECLARED_MESSAGE_LEN: usize = EXCESS_SEQUENCE_COUNT as usize * SINGLE_BYTE_FRAGMENT_LEN;

    let part = fountain::part::Part {
        sequence: EXCESS_SEQUENCE_COUNT + FIRST_SEQUENCE,
        sequence_count: EXCESS_SEQUENCE_COUNT,
        message_length: DECLARED_MESSAGE_LEN,
        checksum: 0,
        data: &[1],
    };
    let mut decoder = foundation_ur::HeaplessDecoder::<
        MESSAGE_CAPACITY,
        MIXED_PART_CAPACITY,
        ENCODED_FRAGMENT_CAPACITY,
        SEQUENCE_CAPACITY,
        QUEUE_CAPACITY,
        UR_TYPE_CAPACITY,
    >::new();
    let serialized = UR::MultiPartDeserialized {
        ur_type: "bytes",
        fragment: part,
    }
    .to_string();
    assert!(matches!(
        decoder.receive(UR::parse(&serialized).unwrap()),
        Err(foundation_ur::decoder::Error::Fountain(
            fountain::decoder::Error::SequenceCountTooLarge { .. }
        ))
    ));
    assert!(decoder.is_empty());
    assert_eq!(decoder.ur_type(), None);
}

#[test]
fn message_limit_changes_apply_after_clear() {
    const REDUCED_MESSAGE_LIMIT: usize = 1;

    let mut decoder = fountain::Decoder::default();
    let mut part = fountain::part::Part {
        sequence: FIRST_SEQUENCE,
        sequence_count: TWO_PART_COUNT as u32,
        message_length: TWO_PART_MESSAGE_LEN,
        checksum: 0,
        data: &[1; TWO_PART_FRAGMENT_LEN],
    };
    decoder.receive(&part).unwrap();
    decoder.set_max_message_len(REDUCED_MESSAGE_LIMIT);
    part.sequence = TWO_PART_COUNT as u32;
    decoder.receive(&part).unwrap();
    assert_eq!(
        decoder.message().unwrap().unwrap().len(),
        TWO_PART_MESSAGE_LEN
    );
    decoder.clear();
    assert!(matches!(
        decoder.receive(&part),
        Err(fountain::decoder::Error::MessageTooLong { .. })
    ));
}

#[test]
fn mismatch_precedes_scratch_buffer_allocation() {
    let mut encoder = Encoder::new();
    encoder.start("bytes", &[1; TWO_PART_MESSAGE_LEN], TWO_PART_FRAGMENT_LEN);
    let serialized = encoder.next_part().to_string();
    let invalid = format!(
        "ur:bytes/{FIRST_SEQUENCE}-{SINGLE_FRAGMENT_COUNT}/{}",
        serialized.rsplit('/').next().unwrap()
    );
    let mut decoder = foundation_ur::HeaplessDecoder::<
        TWO_PART_MESSAGE_LEN,
        MIXED_PART_CAPACITY,
        SINGLE_BYTE_FRAGMENT_LEN,
        SEQUENCE_CAPACITY,
        QUEUE_CAPACITY,
        UR_TYPE_CAPACITY,
    >::new();
    assert!(matches!(
        decoder.receive(UR::parse(&invalid).unwrap()),
        Err(foundation_ur::decoder::Error::InconsistentSequence { .. })
    ));
    assert_eq!(decoder.ur_type(), None);
    assert!(decoder.is_empty());
}

#[test]
fn fragment_count_limits_cover_simple_and_mixed_parts() {
    use fountain::{
        decoder::{Error, Limits},
        part::Part,
    };
    let mut decoder = fountain::Decoder::default();
    decoder.set_limits(Limits {
        max_sequence_count: SEQUENCE_CAPACITY,
        ..Limits::default()
    });
    for count in [SEQUENCE_CAPACITY as u32 + FIRST_SEQUENCE, u32::MAX] {
        for sequence in [FIRST_SEQUENCE, u32::MAX] {
            let part = Part {
                sequence,
                sequence_count: count,
                message_length: SINGLE_BYTE_FRAGMENT_LEN,
                checksum: 0,
                data: &[0],
            };
            assert!(decoder.receive(&part).is_err());
            assert!(decoder.is_empty());
        }
    }
    for sequence in FIRST_SEQUENCE..=SEQUENCE_CAPACITY as u32 {
        decoder
            .receive(&Part {
                sequence,
                sequence_count: SEQUENCE_CAPACITY as u32,
                message_length: FOUR_PART_MESSAGE_LEN,
                checksum: 0,
                data: &[0],
            })
            .unwrap();
    }
    assert!(decoder.is_complete());
    decoder.set_limits(Limits {
        max_sequence_count: NO_CAPACITY,
        ..Limits::default()
    });
    assert!(decoder.is_empty());
    assert!(matches!(
        decoder.receive(&Part {
            sequence: FIRST_SEQUENCE,
            sequence_count: SINGLE_FRAGMENT_COUNT,
            message_length: SINGLE_BYTE_FRAGMENT_LEN,
            checksum: 0,
            data: &[0]
        }),
        Err(Error::SequenceCountTooLarge { .. })
    ));
}

#[test]
fn mixed_and_queue_limits_return_errors_and_allow_reuse() {
    use fountain::{
        decoder::{Error, Limits},
        part::Part,
    };
    let mut decoder = fountain::Decoder::default();
    decoder.set_limits(Limits {
        max_queued_parts: NO_CAPACITY,
        ..Limits::default()
    });
    let mut part = Part {
        sequence: FIRST_SEQUENCE,
        sequence_count: SEQUENCE_CAPACITY as u32,
        message_length: FOUR_PART_MESSAGE_LEN,
        checksum: 0,
        data: &[0],
    };
    assert!(matches!(decoder.receive(&part), Err(Error::QueueFull)));
    assert!(decoder.is_empty());
    decoder.set_limits(Limits {
        max_mixed_parts: NO_CAPACITY,
        ..Limits::default()
    });
    let mut hit_limit = false;
    for sequence in SEQUENCE_CAPACITY as u32 + FIRST_SEQUENCE..MIXED_SEQUENCE_SEARCH_END {
        decoder.clear();
        part.sequence = sequence;
        if matches!(decoder.receive(&part), Err(Error::TooManyMixedParts)) {
            hit_limit = true;
            assert!(decoder.is_empty());
            break;
        }
    }
    assert!(hit_limit);
    decoder.set_limits(Limits::default());
    for sequence in FIRST_SEQUENCE..=SEQUENCE_CAPACITY as u32 {
        part.sequence = sequence;
        decoder.receive(&part).unwrap();
    }
    assert!(decoder.is_complete());
}

#[test]
fn raising_limits_does_not_exceed_fixed_capacity() {
    const FRAGMENT_CAPACITY: usize = 8;
    const DECLARED_MESSAGE_LEN: usize = EXCESS_SEQUENCE_COUNT as usize * SINGLE_BYTE_FRAGMENT_LEN;

    use fountain::{
        decoder::{Error, Limits},
        part::Part,
    };
    let mut decoder = fountain::HeaplessDecoder::<
        MESSAGE_CAPACITY,
        MIXED_PART_CAPACITY,
        FRAGMENT_CAPACITY,
        SEQUENCE_CAPACITY,
        SINGLE_ENTRY_QUEUE_CAPACITY,
    >::new();
    decoder.set_limits(Limits::default());
    let part = Part {
        sequence: EXCESS_SEQUENCE_COUNT + FIRST_SEQUENCE,
        sequence_count: EXCESS_SEQUENCE_COUNT,
        message_length: DECLARED_MESSAGE_LEN,
        checksum: 0,
        data: &[1],
    };
    assert!(matches!(
        decoder.receive(&part),
        Err(Error::SequenceCountTooLarge { .. })
    ));
    assert!(decoder.is_empty());
}

#[test]
fn heapless_queue_overflow_returns_error_after_reduction() {
    const EXPECTED_INDEX_SETS: [[usize; 2]; 2] = [[0, 1], [0, 2]];
    const REDUCTION_SEQUENCE_SEARCH_END: u32 = 200;

    use fountain::{decoder::Error, part::Part};
    use std::collections::BTreeSet;
    let mut sequences = [None; EXPECTED_INDEX_SETS.len()];
    for sequence in SEQUENCE_CAPACITY as u32 + FIRST_SEQUENCE..REDUCTION_SEQUENCE_SEARCH_END {
        let part = Part {
            sequence,
            sequence_count: SEQUENCE_CAPACITY as u32,
            message_length: FOUR_PART_MESSAGE_LEN,
            checksum: 0,
            data: &[0],
        };
        let indexes: BTreeSet<usize> = part.indexes::<fountain::chooser::Alloc, _>();
        for (position, expected) in EXPECTED_INDEX_SETS.into_iter().enumerate() {
            if indexes == BTreeSet::from(expected) {
                sequences[position] = Some(sequence);
            }
        }
    }
    let mut decoder = fountain::HeaplessDecoder::<
        FOUR_PART_MESSAGE_LEN,
        MIXED_PART_CAPACITY,
        SINGLE_BYTE_FRAGMENT_LEN,
        SEQUENCE_CAPACITY,
        SINGLE_ENTRY_QUEUE_CAPACITY,
    >::new();
    for sequence in sequences.map(Option::unwrap) {
        decoder
            .receive(&Part {
                sequence,
                sequence_count: SEQUENCE_CAPACITY as u32,
                message_length: FOUR_PART_MESSAGE_LEN,
                checksum: 0,
                data: &[0],
            })
            .unwrap();
    }
    assert!(matches!(
        decoder.receive(&Part {
            sequence: FIRST_SEQUENCE,
            sequence_count: SEQUENCE_CAPACITY as u32,
            message_length: FOUR_PART_MESSAGE_LEN,
            checksum: 0,
            data: &[0]
        }),
        Err(Error::QueueFull)
    ));
    assert!(decoder.is_empty());
    for sequence in FIRST_SEQUENCE..=SEQUENCE_CAPACITY as u32 {
        decoder
            .receive(&Part {
                sequence,
                sequence_count: SEQUENCE_CAPACITY as u32,
                message_length: FOUR_PART_MESSAGE_LEN,
                checksum: 0,
                data: &[0],
            })
            .unwrap();
    }
    assert!(decoder.is_complete());
}

#[test]
fn heapless_mixed_part_capacity_returns_error() {
    use fountain::{
        decoder::{Error, Limits},
        part::Part,
    };
    let mut decoder = fountain::HeaplessDecoder::<
        FOUR_PART_MESSAGE_LEN,
        NO_CAPACITY,
        SINGLE_BYTE_FRAGMENT_LEN,
        SEQUENCE_CAPACITY,
        SINGLE_ENTRY_QUEUE_CAPACITY,
    >::new();
    decoder.set_limits(Limits::default());
    let mut hit_limit = false;
    for sequence in SEQUENCE_CAPACITY as u32 + FIRST_SEQUENCE..MIXED_SEQUENCE_SEARCH_END {
        decoder.clear();
        let result = decoder.receive(&Part {
            sequence,
            sequence_count: SEQUENCE_CAPACITY as u32,
            message_length: FOUR_PART_MESSAGE_LEN,
            checksum: 0,
            data: &[0],
        });
        if matches!(result, Err(Error::TooManyMixedParts)) {
            hit_limit = true;
            assert!(decoder.is_empty());
            break;
        }
    }
    assert!(hit_limit);
}

#[test]
fn serialized_boundary_inputs_do_not_panic() {
    const ITERATION_COUNT: usize = 4096;
    const RANDOM_SEED: u32 = 1;
    const RANDOM_MULTIPLIER: u32 = 1664525;
    const RANDOM_INCREMENT: u32 = 1013904223;
    const DATA_CAPACITY: usize = 8;
    const SEQUENCE_RANGE: u32 = 32;
    const SEQUENCE_COUNT_RANGE: u32 = EXCESS_SEQUENCE_COUNT + FIRST_SEQUENCE;
    const MESSAGE_LENGTH_RANGE: u32 = (MESSAGE_CAPACITY * 2) as u32;
    const DATA_LENGTH_RANGE: u32 = (DATA_CAPACITY + 1) as u32;
    const SEQUENCE_COUNT_SHIFT: u32 = 5;
    const MESSAGE_LENGTH_SHIFT: u32 = 9;
    const CHECKSUM_SHIFT: u32 = 15;
    const DATA_LENGTH_SHIFT: u32 = 20;
    const RETAINED_MIXED_PART_CAPACITY: usize = 2;

    use fountain::part::Part;
    let mut decoder = foundation_ur::HeaplessDecoder::<
        MESSAGE_CAPACITY,
        RETAINED_MIXED_PART_CAPACITY,
        ENCODED_FRAGMENT_CAPACITY,
        SEQUENCE_CAPACITY,
        SINGLE_ENTRY_QUEUE_CAPACITY,
        UR_TYPE_CAPACITY,
    >::new();
    let mut random = RANDOM_SEED;
    for _ in 0..ITERATION_COUNT {
        random = random
            .wrapping_mul(RANDOM_MULTIPLIER)
            .wrapping_add(RANDOM_INCREMENT);
        let data = [random as u8; DATA_CAPACITY];
        let part = Part {
            sequence: random % SEQUENCE_RANGE,
            sequence_count: (random >> SEQUENCE_COUNT_SHIFT) % SEQUENCE_COUNT_RANGE,
            message_length: ((random >> MESSAGE_LENGTH_SHIFT) % MESSAGE_LENGTH_RANGE) as usize,
            checksum: random >> CHECKSUM_SHIFT,
            data: &data[..((random >> DATA_LENGTH_SHIFT) % DATA_LENGTH_RANGE) as usize],
        };
        let serialized = UR::MultiPartDeserialized {
            ur_type: "bytes",
            fragment: part,
        }
        .to_string();
        if let Ok(ur) = UR::parse(&serialized) {
            let _ = decoder.receive(ur);
        }
        if decoder.is_complete() {
            let _ = decoder.message();
            decoder.clear();
        }
    }
}

#[test]
fn active_ur_message_keeps_its_original_limit() {
    const FRAGMENT_LEN: usize = 100;
    const MESSAGE_LEN: usize = TWO_PART_COUNT * FRAGMENT_LEN;
    const REDUCED_MESSAGE_LIMIT: usize = 1;

    let mut encoder = Encoder::new();
    let message = [1; MESSAGE_LEN];
    encoder.start("bytes", &message, FRAGMENT_LEN);
    let mut decoder = Decoder::default();
    let first = encoder.next_part().to_string();
    decoder.receive(UR::parse(&first).unwrap()).unwrap();
    decoder.set_max_message_len(REDUCED_MESSAGE_LIMIT);
    let second = encoder.next_part().to_string();
    decoder.receive(UR::parse(&second).unwrap()).unwrap();
    assert_eq!(decoder.message().unwrap(), Some(&message[..]));
    decoder.clear();
    assert!(decoder.receive(UR::parse(&first).unwrap()).is_err());
}
