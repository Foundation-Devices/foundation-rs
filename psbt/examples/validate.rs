// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use foundation_bip32::{Xpriv, VERSION_XPRV, Fingerprint, ChainCode};
use foundation_psbt::validation::validate;
use foundation_test_vectors::psbt::TestVectors;
use nom::error::VerboseError;
use rand::rngs::OsRng;
use secp256k1::{global::SECP256K1, Keypair};

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

    // TODO: Remember to make ChainCode field private.
    //
    // Remove this, take the xprv from the command line.
    let keypair = Keypair::new_global(&mut OsRng);
    let xpriv = Xpriv {
        version: VERSION_XPRV,
        depth: 0,
        parent_fingerprint: Fingerprint([0; 4]),
        child_number: 0,
        chain_code: ChainCode([0; 32]),
        private_key: keypair.secret_key(),
    };

    match validate::<_, _, VerboseError<_>>(test_vector.data.as_slice(), SECP256K1, xpriv) {
        Ok(_) => {
            println!("Succeed!");
        },
        Err(e) => {
            println!("Error: {e:?}");
        }
    }
}
