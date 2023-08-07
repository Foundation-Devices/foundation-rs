// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use foundation_psbt::parser::{global::TxModifiable, psbt};

use nom::error::VerboseError;

fn main() {
    /*
    let mut args = std::env::args();
    if args.len() != 2 {
        eprintln!("Usage: {} <psbt-file>", args.nth(0).unwrap());
        std::process::exit(1);
    }

    let file = std::env::args().nth(1).expect("PSBT file path");
    println!("Reading `{file}'...\n");

    let file = std::fs::read(file).expect("Failed to read PSBT file");

    let mut parser = psbt::<_, VerboseError<_>>(|k, v| {
        println!();
        println!("{:?} {:?}", k, v);
    });

    let (_, psbt) = parser(&file).expect("Failed to parse PSBT file");

    println!("");
    println!("Version: {}", psbt.version);
    println!("Transaction version: {}", psbt.version);
    println!(
        "Fallback lock time: {}",
        psbt.fallback_lock_time
            .map(|t| t.to_string())
            .unwrap_or("None".to_string())
    );

    let inputs_modifiable = psbt.tx_modifiable.contains(TxModifiable::INPUTS_MODIFIABLE);
    let outputs_modifiable = psbt
        .tx_modifiable
        .contains(TxModifiable::OUTPUTS_MODIFIABLE);
    let sighash_single = psbt.tx_modifiable.contains(TxModifiable::SIGHASH_SINGLE);

    println!();
    println!(
        "Inputs modifiable? {}.",
        if inputs_modifiable { "Yes" } else { "No" }
    );
    println!(
        "Outputs modifiable? {}.",
        if outputs_modifiable { "Yes" } else { "No" }
    );
    println!(
        "Sighash single? {}.",
        if sighash_single { "Yes" } else { "No" }
    );
    */
}
