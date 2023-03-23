// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use criterion::{
    black_box, criterion_group, criterion_main, measurement::WallTime, BenchmarkGroup, BenchmarkId,
    Criterion, Throughput,
};

use foundation_codecs::{nostr::encode_npub, nostr::encode_nsec, seedqr::encode_to_slice};
use foundation_test_vectors::{NIP19Vector, SeedQRVector};

pub fn benchmark(c: &mut Criterion) {
    nip19_benchmark(c.benchmark_group("NIP-19"));
}

pub fn nip19_benchmark(mut group: BenchmarkGroup<WallTime>) {
    let vectors = NIP19Vector::new();

    for vector in vectors.iter() {
        let function_name = match &*vector.kind {
            "npub" => "encode_npub",
            "nsec" => "encode_nsec",
            _ => panic!("invalid kind {}", vector.kind),
        };

        group.bench_with_input(
            BenchmarkId::new(function_name, &vector.name),
            &vector.bytes,
            |b, i| match &*vector.kind {
                "npub" => b.iter(|| encode_npub(i)),
                "nsec" => b.iter(|| encode_nsec(i)),
                _ => panic!("invalid kind {}", vector.kind),
            },
        );
    }
}

criterion_group!(benches, benchmark);
criterion_main!(benches);
