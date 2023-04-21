// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=data/bcr-2020-006.json");
    println!("cargo:rerun-if-changed=data/bcr-2020-007.json");
    println!("cargo:rerun-if-changed=data/bcr-2020-008.json");
    println!("cargo:rerun-if-changed=data/bcr-2020-009.json");
    println!("cargo:rerun-if-changed=data/nip-19.json");
    println!("cargo:rerun-if-changed=data/seedqr.json");
}
