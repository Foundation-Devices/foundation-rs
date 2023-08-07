// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use foundation_psbt::validation::validate;
use foundation_test_vectors::psbt::TestVectors;
use foundation_bip32::Xpriv;
use nom::error::VerboseError;

fn main() {
    let mut args = std::env::args();
    if args.len() != 2 {
        eprintln!("Usage: {} <psbt-index>", args.nth(0).unwrap());
        std::process::exit(1);
    }

    let test_vectors = TestVectors::bip_0174();

    let index: usize = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0".to_string())
        .parse()
        .expect("valid integer");

    let test_vector = &test_vectors.valid[index];

    println!("Test vector `{index}`: \"{}\"", test_vector.description);

    match validate::<_, VerboseError<_>>(test_vector.data.as_slice()) {
        Ok(_) => (),
        Err(e) => {
            println!("Error: {e}");
            println!("Error: {e:?}");
        }
    }
}
