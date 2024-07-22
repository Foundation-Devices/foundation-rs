// SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{anyhow, bail, Context, Result};
use bitcoin_hashes::{sha256, sha256d, Hash, HashEngine};
use clap::{command, value_parser, Arg, ArgAction};
use foundation_firmware::{header, Header, Information, HEADER_LEN};
use nom::Finish;
use secp256k1::{global::SECP256K1, PublicKey};
use std::{fs, path::PathBuf};

fn main() -> Result<()> {
    let matches = command!()
        .arg(
            Arg::new("file-name")
                .value_name("file-name")
                .required(true)
                .value_parser(value_parser!(PathBuf))
                .help("Firmware file name"),
        )
        .arg(
            Arg::new("header-only")
                .long("header-only")
                .action(ArgAction::SetTrue)
                .help("Only validate the header of the firmware, DISABLES signature verification"),
        )
        .arg(
            Arg::new("public-key")
                .short('p')
                .long("public-key")
                .value_parser(value_parser!(PathBuf))
                .help("Public key for user signed firmware"),
        )
        .get_matches();

    let file_name = matches.get_one::<PathBuf>("file-name").unwrap();
    let file_buf = fs::read(file_name).context("failed to read firmware")?;

    let header_len = usize::try_from(HEADER_LEN).unwrap();
    let header = match header(&file_buf[..header_len]).finish() {
        Ok((_, hdr)) => hdr,
        Err(_) => bail!("failed to parse firmware header"),
    };

    print_header(&header);

    header.verify().context("header verification failed")?;

    if !matches.get_flag("header-only") {
        let user_public_key = matches
            .get_one::<PathBuf>("public-key")
            .map(parse_public_key)
            .transpose()?;

        if let Some(public_key) = user_public_key {
            println!(
                "{:>17}: {}",
                "User Public Key",
                hex::encode(public_key.serialize_uncompressed())
            );
        }

        verify_signature(&header, &file_buf, user_public_key.as_ref())?;
    }

    Ok(())
}

fn print_header(header: &Header) {
    let signature1 = header.signature.signature1.serialize_compact();
    let signature2 = header.signature.signature2.serialize_compact();

    println!("Firmware:");
    println!(
        "{:>17}: {:#010X} ({}) ",
        "Magic",
        header.information.magic,
        match header.information.magic {
            Information::MAGIC_COLOR => "color",
            Information::MAGIC_MONO => "mono",
            _ => "unknown",
        },
    );
    println!("{:>17}: {}", "Timestamp", header.information.timestamp);
    println!("{:>17}: {}", "Date", header.information.date);
    println!("{:>17}: {}", "Version", header.information.version);
    println!("{:>17}: {} bytes", "Length", header.information.length);
    println!("{:>17}: {}", "Key", header.signature.public_key1);
    println!("{:>17}: {}", "Signature", hex::encode(signature1));
    println!("{:>17}: {}", "Key", header.signature.public_key2);
    println!("{:>17}: {}", "Signature", hex::encode(signature2));
}

fn verify_signature(
    header: &Header,
    file_buf: &[u8],
    user_public_key: Option<&PublicKey>,
) -> anyhow::Result<()> {
    let header_len = usize::try_from(HEADER_LEN).unwrap();

    let download_hash = sha256::Hash::hash(&file_buf);
    let build_hash = sha256::Hash::hash(&file_buf[header_len..]);

    let mut engine = sha256d::Hash::engine();
    engine.input(&header.information.serialize());
    engine.input(&file_buf[header_len..]);
    let validation_hash = sha256d::Hash::from_engine(engine);

    // This one is just for debugging.
    let mut engine = sha256::Hash::engine();
    engine.input(&header.information.serialize());
    engine.input(&file_buf[header_len..]);
    let single_hash = sha256::Hash::from_engine(engine);

    let firmware_length = file_buf.len() - header_len;
    if firmware_length != usize::try_from(header.information.length).unwrap() {
        bail!(
            "invalid specified firmware length, on disk size is {}, specified one {}",
            firmware_length,
            header.information.length
        );
    }

    println!("Validation:");
    println!("{:>17}: {}", "Download Hash", download_hash);
    println!("{:>17}: {}", "Build Hash", build_hash);
    println!(
        "{:>17}: {}",
        "Validation Hash",
        hex::encode(validation_hash.to_byte_array())
    );
    println!(
        "{:>17}: {}",
        "Single Hash",
        hex::encode(single_hash.to_byte_array())
    );
    println!();

    foundation_firmware::verify_signature(&SECP256K1, &header, &validation_hash, user_public_key)
        .context("firmware signature verification failed.")?;

    println!("Firmware signature is valid!");

    Ok(())
}

// Poor's man DER parser.
fn parse_public_key(file_name: &PathBuf) -> anyhow::Result<PublicKey> {
    fs::read(file_name)
        .context("failed to read user public key")
        .and_then(|buf| {
            const LEN: usize = 88;
            if buf.len() != LEN {
                Err(anyhow!(
                    "public key length is wrong: {}, expected {LEN} bytes",
                    buf.len()
                ))
            } else {
                Ok(buf)
            }
        })
        .map(|buf| {
            let mut pk = [0; 65];
            pk[0] = 0x04;
            (&mut pk[1..]).copy_from_slice(&buf[24..]);
            pk
        })
        .and_then(|buf| PublicKey::from_slice(&buf).context("failed to parse public key"))
}
