// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT

#![cfg(feature = "alloc")]

use foundation_ur::{fountain, Decoder, Encoder, UR};

#[test]
fn rejected_sequence_does_not_retain_type() {
    let mut encoder = Encoder::new();
    encoder.start("bytes", &[1; 8], 4);
    let serialized = encoder.next_part().to_string();
    let payload = serialized.rsplit('/').next().unwrap();
    let invalid = format!("ur:bytes/1-1/{payload}");
    let mut decoder = Decoder::default();
    assert!(decoder.receive(UR::parse(&invalid).unwrap()).is_err());
    assert_eq!(decoder.ur_type(), None);
    assert!(decoder.is_empty());
    let mut honest = Encoder::new();
    honest.start("crypto-psbt", &[1; 8], 4);
    decoder.receive(honest.next_part()).unwrap();
}

#[test]
fn matching_metadata_above_heapless_capacity_returns_error() {
    let part = fountain::part::Part {
        sequence: 9,
        sequence_count: 8,
        message_length: 8,
        checksum: 0,
        data: &[1],
    };
    let mut decoder = foundation_ur::HeaplessDecoder::<32, 4, 128, 4, 4, 16>::new();
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
    let mut decoder = fountain::Decoder::default();
    let mut part = fountain::part::Part {
        sequence: 1,
        sequence_count: 2,
        message_length: 8,
        checksum: 0,
        data: &[1; 4],
    };
    decoder.receive(&part).unwrap();
    decoder.set_max_message_len(1);
    part.sequence = 2;
    decoder.receive(&part).unwrap();
    assert_eq!(decoder.message().unwrap().unwrap().len(), 8);
    decoder.clear();
    assert!(matches!(
        decoder.receive(&part),
        Err(fountain::decoder::Error::MessageTooLong { .. })
    ));
}

#[test]
fn mismatch_precedes_scratch_buffer_allocation() {
    let mut encoder = Encoder::new();
    encoder.start("bytes", &[1; 8], 4);
    let serialized = encoder.next_part().to_string();
    let invalid = format!("ur:bytes/1-1/{}", serialized.rsplit('/').next().unwrap());
    let mut decoder = foundation_ur::HeaplessDecoder::<8, 4, 1, 4, 4, 16>::new();
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
        max_sequence_count: 4,
        ..Limits::default()
    });
    for count in [5, u32::MAX] {
        for sequence in [1, u32::MAX] {
            let part = Part {
                sequence,
                sequence_count: count,
                message_length: 1,
                checksum: 0,
                data: &[0],
            };
            assert!(decoder.receive(&part).is_err());
            assert!(decoder.is_empty());
        }
    }
    for sequence in 1..=4 {
        decoder
            .receive(&Part {
                sequence,
                sequence_count: 4,
                message_length: 4,
                checksum: 0,
                data: &[0],
            })
            .unwrap();
    }
    assert!(decoder.is_complete());
    decoder.set_limits(Limits {
        max_sequence_count: 0,
        ..Limits::default()
    });
    assert!(decoder.is_empty());
    assert!(matches!(
        decoder.receive(&Part {
            sequence: 1,
            sequence_count: 1,
            message_length: 1,
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
        max_queued_parts: 0,
        ..Limits::default()
    });
    let mut part = Part {
        sequence: 1,
        sequence_count: 4,
        message_length: 4,
        checksum: 0,
        data: &[0],
    };
    assert!(matches!(decoder.receive(&part), Err(Error::QueueFull)));
    assert!(decoder.is_empty());
    decoder.set_limits(Limits {
        max_mixed_parts: 0,
        ..Limits::default()
    });
    let mut hit_limit = false;
    for sequence in 5..100 {
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
    for sequence in 1..=4 {
        part.sequence = sequence;
        decoder.receive(&part).unwrap();
    }
    assert!(decoder.is_complete());
}

#[test]
fn raising_limits_does_not_exceed_fixed_capacity() {
    use fountain::{
        decoder::{Error, Limits},
        part::Part,
    };
    let mut decoder = fountain::HeaplessDecoder::<32, 4, 8, 4, 1>::new();
    decoder.set_limits(Limits::default());
    let part = Part {
        sequence: 9,
        sequence_count: 8,
        message_length: 8,
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
    use fountain::{decoder::Error, part::Part};
    use std::collections::BTreeSet;
    let mut sequences = [None; 2];
    for sequence in 5..200 {
        let part = Part {
            sequence,
            sequence_count: 4,
            message_length: 4,
            checksum: 0,
            data: &[0],
        };
        let indexes: BTreeSet<usize> = part.indexes::<fountain::chooser::Alloc, _>();
        for (position, expected) in [[0, 1], [0, 2]].into_iter().enumerate() {
            if indexes == BTreeSet::from(expected) {
                sequences[position] = Some(sequence);
            }
        }
    }
    let mut decoder = fountain::HeaplessDecoder::<4, 4, 1, 4, 1>::new();
    for sequence in sequences.map(Option::unwrap) {
        decoder
            .receive(&Part {
                sequence,
                sequence_count: 4,
                message_length: 4,
                checksum: 0,
                data: &[0],
            })
            .unwrap();
    }
    assert!(matches!(
        decoder.receive(&Part {
            sequence: 1,
            sequence_count: 4,
            message_length: 4,
            checksum: 0,
            data: &[0]
        }),
        Err(Error::QueueFull)
    ));
    assert!(decoder.is_empty());
    for sequence in 1..=4 {
        decoder
            .receive(&Part {
                sequence,
                sequence_count: 4,
                message_length: 4,
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
    let mut decoder = fountain::HeaplessDecoder::<4, 0, 1, 4, 1>::new();
    decoder.set_limits(Limits::default());
    let mut hit_limit = false;
    for sequence in 5..100 {
        decoder.clear();
        let result = decoder.receive(&Part {
            sequence,
            sequence_count: 4,
            message_length: 4,
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
    use fountain::part::Part;
    let mut decoder = foundation_ur::HeaplessDecoder::<32, 2, 128, 4, 1, 16>::new();
    let mut random = 1u32;
    for _ in 0..4096 {
        random = random.wrapping_mul(1664525).wrapping_add(1013904223);
        let data = [random as u8; 8];
        let part = Part {
            sequence: random % 32,
            sequence_count: (random >> 5) % 9,
            message_length: ((random >> 9) % 64) as usize,
            checksum: random >> 15,
            data: &data[..((random >> 20) % 9) as usize],
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
    let mut encoder = Encoder::new();
    let message = [1; 200];
    encoder.start("bytes", &message, 100);
    let mut decoder = Decoder::default();
    let first = encoder.next_part().to_string();
    decoder.receive(UR::parse(&first).unwrap()).unwrap();
    decoder.set_max_message_len(1);
    let second = encoder.next_part().to_string();
    decoder.receive(UR::parse(&second).unwrap()).unwrap();
    assert_eq!(decoder.message().unwrap(), Some(&message[..]));
    decoder.clear();
    assert!(decoder.receive(UR::parse(&first).unwrap()).is_err());
}
