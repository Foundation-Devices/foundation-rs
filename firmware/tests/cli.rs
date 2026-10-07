// SPDX-FileCopyrightText: © 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! The executable's own file length guard.
//!
//! `tests/test-vectors.rs` covers truncated input at the parser, which cannot
//! reach this: the binary slices `HEADER_LEN` bytes off the file before handing
//! anything to `header()`, so a short file used to panic on the slice itself.

#![cfg(feature = "binary")]

use std::io::Write;
use std::process::{Command, Output};

use foundation_firmware::HEADER_LEN;

fn run_on(bytes: &[u8]) -> Output {
    let mut path = std::env::temp_dir();
    path.push(format!("foundation-firmware-cli-{}.bin", bytes.len()));

    let mut file = std::fs::File::create(&path).expect("create temporary firmware");
    file.write_all(bytes).expect("write temporary firmware");
    drop(file);

    let output = Command::new(env!("CARGO_BIN_EXE_foundation-firmware"))
        .arg(&path)
        .output()
        .expect("run foundation-firmware");

    std::fs::remove_file(&path).ok();
    output
}

/// A panic exits with 101 and says so; an `anyhow` error from `main` exits with 1.
fn assert_failed_without_panicking(output: &Output, what: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!stderr.contains("panicked"), "{what} panicked:\n{stderr}");
    assert_eq!(
        output.status.code(),
        Some(1),
        "{what} did not exit with an ordinary error:\n{stderr}"
    );
}

#[test]
fn a_file_shorter_than_the_header_is_an_error_not_a_panic() {
    let header_len = usize::try_from(HEADER_LEN).unwrap();

    for len in [0, 1, 170, header_len - 1] {
        let output = run_on(&vec![0u8; len]);
        assert_failed_without_panicking(&output, &format!("{len} bytes"));

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("too small"),
            "{len} bytes failed for some other reason:\n{stderr}"
        );
    }
}

#[test]
fn a_file_long_enough_to_slice_reaches_the_parser() {
    // Proves the guard above is what rejected the short files, rather than
    // something further up: at exactly HEADER_LEN the length check passes and
    // the failure moves to the header contents.
    let header_len = usize::try_from(HEADER_LEN).unwrap();
    let output = run_on(&vec![0u8; header_len]);

    assert_failed_without_panicking(&output, "a zero filled header");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("too small"),
        "the length guard fired on a full length file:\n{stderr}"
    );
}
