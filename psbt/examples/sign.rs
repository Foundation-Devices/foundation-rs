// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use foundation_bip32::Xpriv;
use foundation_psbt::{
    address::Network,
    validation::{validate, Error},
};
use nom::error::VerboseError;
use secp256k1::global::SECP256K1;
use std::str::FromStr;

fn main() {
    env_logger::init();

    let mut args = std::env::args();
    if args.len() != 3 {
        eprintln!("Usage: {} <psbt-file> <xpriv>", args.nth(0).unwrap());
        std::process::exit(1);
    }

    let file = std::env::args().nth(1).unwrap();
    let xpriv = std::env::args().nth(2).unwrap();

    let file = std::fs::read(file).unwrap();
    let xpriv = Xpriv::from_str(&xpriv).unwrap();

    let details = match validate::<_, _, _, VerboseError<_>, 10>(
        Network::Testnet,
        file.as_slice(),
        SECP256K1,
        xpriv,
        |_| (),
    ) {
        Ok(v) => v,
        Err(e) => {
            match e {
                Error::Parse(e) => match e {
                    nom::Err::Incomplete(_) => println!("unexpected end of file"),
                    nom::Err::Error(e) | nom::Err::Failure(e) => {
                        for (i, e) in e.errors.iter().enumerate() {
                            println!("Error {i}: {e:?}");
                        }
                    }
                },
                Error::Validation(e) => println!("{e}"),
                Error::AddressRender(e) => println!("{e}"),
            }

            std::process::exit(1);
        }
    };

    println!("Transaction details:");
    if details.is_self_send() {
        println!("This transaction is a self-send.");
        println!("Total: {} sats", details.total_change);
    } else {
        println!("Total: {} sats", details.total());
        println!("Change: {} sats", details.total_change);
    }
    println!("Fee: {} sats", details.fee());

    println!("Succeed!");
}
