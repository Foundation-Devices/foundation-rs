// SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::{Error, Result};
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use faster_hex::hex_decode;
#[cfg(not(feature = "alloc"))]
use heapless::Vec;
use serde::Deserialize;

use super::request::Request;

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt-03", derive(defmt::Format))]
pub struct Work {
    pub job_id: tstring!(32),
    pub prev_hash: [u8; 32],
    pub coinb1: tvec!(u8, 128),
    pub coinb2: tvec!(u8, 130),
    #[cfg(feature = "alloc")]
    pub merkle_branch: Vec<[u8; 32]>,
    #[cfg(not(feature = "alloc"))]
    pub merkle_branch: Vec<[u8; 32], 16>,
    pub version: i32,
    pub nbits: u32,
    pub ntime: u32,
    pub clean_jobs: bool,
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt-03", derive(defmt::Format))]
pub enum Notification {
    SetVersionMask,
    Notify,
    SetDifficulty,
}

pub(crate) fn parse_method(resp: &[u8]) -> Result<Notification> {
    #[derive(Debug, Deserialize)]
    #[cfg_attr(feature = "defmt-03", derive(defmt::Format))]
    struct MethodOnly {
        method: tstring!(32),
    }
    match serde_json_core::from_slice::<MethodOnly>(resp)?
        .0
        .method
        .as_str()
    {
        "mining.set_version_mask" => Ok(Notification::SetVersionMask),
        "mining.notify" => Ok(Notification::Notify),
        "mining.set_difficulty" => Ok(Notification::SetDifficulty),
        _ => Err(Error::UnknownNotification),
    }
}

pub(crate) fn parse_set_version_mask(resp: &[u8]) -> Result<u32> {
    let mut v = [0; 4];
    hex_decode(
        serde_json_core::from_slice::<Request<tvecstring!(8, 1)>>(resp)?
            .0
            .params
            .ok_or(Error::RpcBadRequest)?
            .pop()
            .ok_or(Error::VecEmpty)?
            .as_bytes(),
        &mut v,
    )?;
    Ok(u32::from_be_bytes(v))
}

pub(crate) fn parse_notify(resp: &[u8]) -> Result<Work> {
    #[derive(Debug, Deserialize)]
    #[cfg_attr(feature = "defmt-03", derive(defmt::Format))]
    struct WorkRaw(
        // Job ID. This is included when miners submit a results so work can be matched with proper transactions.
        tstring!(32),
        // Hash of previous block. Used to build the header.
        tstring!(64),
        // Generation transaction (part 1). The miner inserts ExtraNonce1 and ExtraNonce2 after this section of the transaction data.
        tstring!(256),
        // Generation transaction (part 2). The miner appends this after the first part of the transaction data and the two ExtraNonce values.
        tstring!(260),
        // List of merkle branches. The generation transaction is hashed against the merkle branches to build the final merkle root.
        tvecstring!(64, 16),
        // Bitcoin block version. Used in the block header.
        tstring!(8),
        // nBits. The encoded network difficulty. Used in the block header.
        tstring!(8),
        // nTime. The current time. nTime rolling should be supported, but should not increase faster than actual time.
        tstring!(8),
        // Clean Jobs. If true, miners should abort their current work and immediately use the new job, even if it degrades hashrate in the short term.
        // If false, they can still use the current job, but should move to the new one as soon as possible without impacting hashrate.
        bool,
    );

    impl TryFrom<WorkRaw> for Work {
        type Error = Error;

        fn try_from(raw: WorkRaw) -> Result<Self> {
            let mut work = Work {
                job_id: raw.0,
                prev_hash: [0; 32],
                coinb1: Vec::new(),
                coinb2: Vec::new(),
                merkle_branch: Vec::new(),
                version: 0,
                nbits: 0,
                ntime: 0,
                clean_jobs: raw.8,
            };
            for i in 0..8 {
                hex_decode(
                    &raw.1.as_bytes()[8 * i..8 * (i + 1)],
                    &mut work.prev_hash[32 - 4 * (i + 1)..32 - 4 * i],
                )?;
            }
            #[cfg(feature = "alloc")]
            work.coinb1.resize(raw.2.len() / 2, 0);
            #[cfg(not(feature = "alloc"))]
            work.coinb1
                .resize(raw.2.len() / 2, 0)
                .map_err(|_| Error::FixedSizeTooSmall {
                    fixed: 70,
                    needed: raw.2.len() / 2,
                })?;
            hex_decode(raw.2.as_bytes(), &mut work.coinb1)?;
            #[cfg(feature = "alloc")]
            work.coinb2.resize(raw.3.len() / 2, 0);
            #[cfg(not(feature = "alloc"))]
            work.coinb2
                .resize(raw.3.len() / 2, 0)
                .map_err(|_| Error::FixedSizeTooSmall {
                    fixed: 88,
                    needed: raw.3.len() / 2,
                })?;
            hex_decode(raw.3.as_bytes(), &mut work.coinb2)?;
            for (_i, b) in raw.4.iter().enumerate() {
                let mut buf = [0; 32];
                hex_decode(b.as_bytes(), &mut buf)?;
                #[cfg(feature = "alloc")]
                work.merkle_branch.push(buf);
                #[cfg(not(feature = "alloc"))]
                work.merkle_branch
                    .push(buf)
                    .map_err(|_| Error::FixedSizeTooSmall {
                        fixed: 16,
                        needed: _i,
                    })?;
            }
            let mut v = [0; 4];
            hex_decode(raw.5.as_bytes(), &mut v)?;
            work.version = i32::from_be_bytes(v);
            hex_decode(raw.6.as_bytes(), &mut v)?;
            work.nbits = u32::from_be_bytes(v);
            hex_decode(raw.7.as_bytes(), &mut v)?;
            work.ntime = u32::from_be_bytes(v);
            Ok(work)
        }
    }

    serde_json_core::from_slice::<Request<WorkRaw>>(resp)?
        .0
        .params
        .ok_or(Error::RpcBadRequest)?
        .try_into()
}

pub(crate) fn parse_set_difficulty(resp: &[u8]) -> Result<f64> {
    serde_json_core::from_slice::<Request<tvec!(f64, 1)>>(resp)?
        .0
        .params
        .ok_or(Error::RpcBadRequest)?
        .pop()
        .ok_or(Error::VecEmpty)
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use alloc::vec::Vec;
    #[cfg(not(feature = "alloc"))]
    use core::str::FromStr;
    #[cfg(not(feature = "alloc"))]
    use heapless::Vec;

    use super::*;

    #[test]
    fn test_parse_set_version_mask() {
        let resp = br#"{"params":["1fffe000"], "id":null, "method": "mining.set_version_mask"}"#;
        assert_eq!(parse_set_version_mask(resp), Ok(0x1fff_e000));

        let resp = br#"{"params":["1fffe00z"], "id":null, "method": "mining.set_version_mask"}"#;
        assert_eq!(
            parse_set_version_mask(resp),
            Err(Error::HexError(faster_hex::Error::InvalidChar))
        );

        let resp = br#"{"params":["1fffe0000"], "id":null, "method": "mining.set_version_mask"}"#;
        #[cfg(not(feature = "alloc"))]
        assert_eq!(
            parse_set_version_mask(resp),
            Err(Error::JsonError(
                serde_json_core::de::Error::CustomErrorWithMessage(hstring!(
                    64,
                    "invalid length 9, expected a string no more than 8 bytes long"
                ))
            ))
        );
        #[cfg(feature = "alloc")]
        assert_eq!(
            parse_set_version_mask(resp),
            Err(Error::HexError(faster_hex::Error::InvalidLength(8)))
        );

        let resp = br#"{"params":["1fffe00"], "id":null, "method": "mining.set_version_mask"}"#;
        assert_eq!(
            parse_set_version_mask(resp),
            Err(Error::HexError(faster_hex::Error::InvalidLength(8)))
        );
    }

    #[test]
    fn test_notify() {
        // example from https://bitcointalk.org/index.php?topic=557866.5
        assert_eq!(
            parse_notify(br#"{"params": ["bf", "4d16b6f85af6e2198f44ae2a6de67f78487ae5611b77c6c0440b921e00000000","01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff20020862062f503253482f04b8864e5008","072f736c7573682f000000000100f2052a010000001976a914d23fcdf86f7e756a64a7a9688ef9903327048ed988ac00000000", [],"00000002", "1c2ac4af", "504e86b9", false], "id": null, "method": "mining.notify"}"#),
            Ok(Work {
                job_id: "bf".try_into().unwrap(),
                prev_hash: [
                    0x00, 0x00, 0x00, 0x00, 0x44, 0x0b, 0x92, 0x1e, 0x1b, 0x77, 0xc6, 0xc0, 0x48,
                    0x7a, 0xe5, 0x61, 0x6d, 0xe6, 0x7f, 0x78, 0x8f, 0x44, 0xae, 0x2a, 0x5a, 0xf6,
                    0xe2, 0x19, 0x4d, 0x16, 0xb6, 0xf8,
                ],
                coinb1: hvec!(
                    u8,
                    128,
                    [
                        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0xff, 0xff, 0xff, 0xff, 0x20, 0x02, 0x08, 0x62, 0x06, 0x2f, 0x50,
                        0x32, 0x53, 0x48, 0x2f, 0x04, 0xb8, 0x86, 0x4e, 0x50, 0x08,
                    ]
                ),
                coinb2: hvec!(
                    u8,
                    130,
                    [
                        0x07, 0x2f, 0x73, 0x6c, 0x75, 0x73, 0x68, 0x2f, 0x00, 0x00, 0x00, 0x00,
                        0x01, 0x00, 0xf2, 0x05, 0x2a, 0x01, 0x00, 0x00, 0x00, 0x19, 0x76, 0xa9,
                        0x14, 0xd2, 0x3f, 0xcd, 0xf8, 0x6f, 0x7e, 0x75, 0x6a, 0x64, 0xa7, 0xa9,
                        0x68, 0x8e, 0xf9, 0x90, 0x33, 0x27, 0x04, 0x8e, 0xd9, 0x88, 0xac, 0x00,
                        0x00, 0x00, 0x00,
                    ]
                ),
                merkle_branch: Vec::new(),
                version: 0x0000_00002,
                nbits: 0x1c2a_c4af,
                ntime: 0x504e_86b9,
                clean_jobs: false
            })
        );

        // example from actual mining job
        assert_eq!(
            parse_notify(br#"{"params": ["278", "9c16805af67958e9c183d0fa47e4b8245fea76e26cfe874b0000000e00000000","02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3b03219200005374726174756d207632204e6562756c6120506f6f6c","ffffffff0200f2052a01000000160014d4989f3137807deab9a76e549eef5c5a03448ca40000000000000000266a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf900000000",[],"20000000","19609307","66ab8012",true], "id": null, "method": "mining.notify"}"#),
            Ok(Work {
                job_id: "278".try_into().unwrap(),
                prev_hash: [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x6c, 0xfe, 0x87, 0x4b, 0x5f,
                    0xea, 0x76, 0xe2, 0x47, 0xe4, 0xb8, 0x24, 0xc1, 0x83, 0xd0, 0xfa, 0xf6, 0x79,
                    0x58, 0xe9, 0x9c, 0x16, 0x80, 0x5a,
                ],
                coinb1: hvec!(
                    u8,
                    128,
                    [
                        0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0xff, 0xff, 0xff, 0xff, 0x3b, 0x03, 0x21, 0x92, 0x00, 0x00, 0x53,
                        0x74, 0x72, 0x61, 0x74, 0x75, 0x6d, 0x20, 0x76, 0x32, 0x20, 0x4e, 0x65,
                        0x62, 0x75, 0x6c, 0x61, 0x20, 0x50, 0x6f, 0x6f, 0x6c,
                    ]
                ),
                coinb2: hvec!(
                    u8,
                    130,
                    [
                        0xff, 0xff, 0xff, 0xff, 0x02, 0x00, 0xf2, 0x05, 0x2a, 0x01, 0x00, 0x00,
                        0x00, 0x16, 0x00, 0x14, 0xd4, 0x98, 0x9f, 0x31, 0x37, 0x80, 0x7d, 0xea,
                        0xb9, 0xa7, 0x6e, 0x54, 0x9e, 0xef, 0x5c, 0x5a, 0x03, 0x44, 0x8c, 0xa4,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x26, 0x6a, 0x24, 0xaa,
                        0x21, 0xa9, 0xed, 0xe2, 0xf6, 0x1c, 0x3f, 0x71, 0xd1, 0xde, 0xfd, 0x3f,
                        0xa9, 0x99, 0xdf, 0xa3, 0x69, 0x53, 0x75, 0x5c, 0x69, 0x06, 0x89, 0x79,
                        0x99, 0x62, 0xb4, 0x8b, 0xeb, 0xd8, 0x36, 0x97, 0x4e, 0x8c, 0xf9, 0x00,
                        0x00, 0x00, 0x00,
                    ]
                ),
                merkle_branch: Vec::new(),
                version: 0x2000_0000,
                nbits: 0x1960_9307,
                ntime: 0x66ab_8012,
                clean_jobs: true
            })
        );

        // example from actual mining job
        assert_eq!(
            parse_notify(
                br#"{"id":null,"method":"mining.notify","params":["662ede","a80f3e7fb2fae8236812baa766c2c6141b9118530001c1ce0000000000000000","02000000010000000000000000000000000000000000000000000000000000000000000000ffffffff17035a0b0d5075626c69632d506f6f6c","ffffffff0294b1f512000000001976a91495e381440a0faf41a7206b86b0d770bcabfef2cf88ac0000000000000000266a24aa21a9edee8a2981199af032120e8bc567edb3d3f3335278b508ced184bcbff13137364d00000000",["48133ccb9355395e02960124db8bf4f98f3cb05908f5c27abc77f020fe13feee","bb4120b2bd74d2204588eed34911b311f1e9ec1561c0fe7730b795a3b5d28fa6","53e7786db850a2bb49a88c003f278aa48866ccdadc5bc7b27e77af1bf3ca2669","ce8944028b7360405f2929922e00e08276af6cab0f119aa8ca3bceb29e2306d2","b2debecba153be2fe9da0f193e33a9d1fe888779dfd855770f0f7020c4047f26","548b2b9331cc40b9d68fd142b1ae2322e33ddb1b65cdf94cfd089ec967362118","8af1d2d31f86c0a240a11f55320335560642f3633ba481929fc431a9996fc874","62e671ae9d5d20aa7fc7f45856367f3dedb96b1736ec559292c8b9e0134672b1","10d017262b9152c47aa4e261c84fb6e8fb07f0b760a4da172b09f548f42d1db4","f1b01197d16a068329d39cdcbe0040029b51095635f332ca91e426e5da8bbe7d","ef342a7b654060a5048aaf1d6b0ac18f51a0cee6d58856f21a9cbec799ee6e9e","f6bb407984e000a2a619e26a46e91e113001aebd563407ea6202d8b042cf9294","5d60ed1a9ee3bbfac2b0f24abf0c72fe7c39c4b51b046903a4dfe21ca5312c25"],"20000000","17031abe","66aad286",false]}"#
            ),
            Ok(Work {
                job_id: hstring!(32, "662ede"),
                prev_hash: [
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc1, 0xce, 0x1b,
                    0x91, 0x18, 0x53, 0x66, 0xc2, 0xc6, 0x14, 0x68, 0x12, 0xba, 0xa7, 0xb2, 0xfa,
                    0xe8, 0x23, 0xa8, 0x0f, 0x3e, 0x7f,
                ],
                coinb1: hvec!(
                    u8,
                    128,
                    [
                        0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x00, 0xff, 0xff, 0xff, 0xff, 0x17, 0x03, 0x5a, 0x0b, 0x0d, 0x50, 0x75,
                        0x62, 0x6c, 0x69, 0x63, 0x2d, 0x50, 0x6f, 0x6f, 0x6c,
                    ]
                ),
                coinb2: hvec!(
                    u8,
                    130,
                    [
                        0xff, 0xff, 0xff, 0xff, 0x02, 0x94, 0xb1, 0xf5, 0x12, 0x00, 0x00, 0x00,
                        0x00, 0x19, 0x76, 0xa9, 0x14, 0x95, 0xe3, 0x81, 0x44, 0x0a, 0x0f, 0xaf,
                        0x41, 0xa7, 0x20, 0x6b, 0x86, 0xb0, 0xd7, 0x70, 0xbc, 0xab, 0xfe, 0xf2,
                        0xcf, 0x88, 0xac, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x26,
                        0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed, 0xee, 0x8a, 0x29, 0x81, 0x19, 0x9a,
                        0xf0, 0x32, 0x12, 0x0e, 0x8b, 0xc5, 0x67, 0xed, 0xb3, 0xd3, 0xf3, 0x33,
                        0x52, 0x78, 0xb5, 0x08, 0xce, 0xd1, 0x84, 0xbc, 0xbf, 0xf1, 0x31, 0x37,
                        0x36, 0x4d, 0x00, 0x00, 0x00, 0x00,
                    ]
                ),
                merkle_branch: hveca!(u8, 32, 16, [
                    [
                        0x48, 0x13, 0x3c, 0xcb, 0x93, 0x55, 0x39, 0x5e, 0x02, 0x96, 0x01, 0x24, 0xdb, 0x8b,
                        0xf4, 0xf9, 0x8f, 0x3c, 0xb0, 0x59, 0x08, 0xf5, 0xc2, 0x7a, 0xbc, 0x77, 0xf0, 0x20,
                        0xfe, 0x13, 0xfe, 0xee,
                    ],
                    [
                        0xbb, 0x41, 0x20, 0xb2, 0xbd, 0x74, 0xd2, 0x20, 0x45, 0x88, 0xee, 0xd3, 0x49, 0x11,
                        0xb3, 0x11, 0xf1, 0xe9, 0xec, 0x15, 0x61, 0xc0, 0xfe, 0x77, 0x30, 0xb7, 0x95, 0xa3,
                        0xb5, 0xd2, 0x8f, 0xa6,
                    ],
                    [
                        0x53, 0xe7, 0x78, 0x6d, 0xb8, 0x50, 0xa2, 0xbb, 0x49, 0xa8, 0x8c, 0x00, 0x3f, 0x27,
                        0x8a, 0xa4, 0x88, 0x66, 0xcc, 0xda, 0xdc, 0x5b, 0xc7, 0xb2, 0x7e, 0x77, 0xaf, 0x1b,
                        0xf3, 0xca, 0x26, 0x69,
                    ],
                    [
                        0xce, 0x89, 0x44, 0x02, 0x8b, 0x73, 0x60, 0x40, 0x5f, 0x29, 0x29, 0x92, 0x2e, 0x00,
                        0xe0, 0x82, 0x76, 0xaf, 0x6c, 0xab, 0x0f, 0x11, 0x9a, 0xa8, 0xca, 0x3b, 0xce, 0xb2,
                        0x9e, 0x23, 0x06, 0xd2,
                    ],
                    [
                        0xb2, 0xde, 0xbe, 0xcb, 0xa1, 0x53, 0xbe, 0x2f, 0xe9, 0xda, 0x0f, 0x19, 0x3e, 0x33,
                        0xa9, 0xd1, 0xfe, 0x88, 0x87, 0x79, 0xdf, 0xd8, 0x55, 0x77, 0x0f, 0x0f, 0x70, 0x20,
                        0xc4, 0x04, 0x7f, 0x26,
                    ],
                    [
                        0x54, 0x8b, 0x2b, 0x93, 0x31, 0xcc, 0x40, 0xb9, 0xd6, 0x8f, 0xd1, 0x42, 0xb1, 0xae,
                        0x23, 0x22, 0xe3, 0x3d, 0xdb, 0x1b, 0x65, 0xcd, 0xf9, 0x4c, 0xfd, 0x08, 0x9e, 0xc9,
                        0x67, 0x36, 0x21, 0x18,
                    ],
                    [
                        0x8a, 0xf1, 0xd2, 0xd3, 0x1f, 0x86, 0xc0, 0xa2, 0x40, 0xa1, 0x1f, 0x55, 0x32, 0x03,
                        0x35, 0x56, 0x06, 0x42, 0xf3, 0x63, 0x3b, 0xa4, 0x81, 0x92, 0x9f, 0xc4, 0x31, 0xa9,
                        0x99, 0x6f, 0xc8, 0x74,
                    ],
                    [
                        0x62, 0xe6, 0x71, 0xae, 0x9d, 0x5d, 0x20, 0xaa, 0x7f, 0xc7, 0xf4, 0x58, 0x56, 0x36,
                        0x7f, 0x3d, 0xed, 0xb9, 0x6b, 0x17, 0x36, 0xec, 0x55, 0x92, 0x92, 0xc8, 0xb9, 0xe0,
                        0x13, 0x46, 0x72, 0xb1,
                    ],
                    [
                        0x10, 0xd0, 0x17, 0x26, 0x2b, 0x91, 0x52, 0xc4, 0x7a, 0xa4, 0xe2, 0x61, 0xc8, 0x4f,
                        0xb6, 0xe8, 0xfb, 0x07, 0xf0, 0xb7, 0x60, 0xa4, 0xda, 0x17, 0x2b, 0x09, 0xf5, 0x48,
                        0xf4, 0x2d, 0x1d, 0xb4,
                    ],
                    [
                        0xf1, 0xb0, 0x11, 0x97, 0xd1, 0x6a, 0x06, 0x83, 0x29, 0xd3, 0x9c, 0xdc, 0xbe, 0x00,
                        0x40, 0x02, 0x9b, 0x51, 0x09, 0x56, 0x35, 0xf3, 0x32, 0xca, 0x91, 0xe4, 0x26, 0xe5,
                        0xda, 0x8b, 0xbe, 0x7d,
                    ],
                    [
                        0xef, 0x34, 0x2a, 0x7b, 0x65, 0x40, 0x60, 0xa5, 0x04, 0x8a, 0xaf, 0x1d, 0x6b, 0x0a,
                        0xc1, 0x8f, 0x51, 0xa0, 0xce, 0xe6, 0xd5, 0x88, 0x56, 0xf2, 0x1a, 0x9c, 0xbe, 0xc7,
                        0x99, 0xee, 0x6e, 0x9e,
                    ],
                    [
                        0xf6, 0xbb, 0x40, 0x79, 0x84, 0xe0, 0x00, 0xa2, 0xa6, 0x19, 0xe2, 0x6a, 0x46, 0xe9,
                        0x1e, 0x11, 0x30, 0x01, 0xae, 0xbd, 0x56, 0x34, 0x07, 0xea, 0x62, 0x02, 0xd8, 0xb0,
                        0x42, 0xcf, 0x92, 0x94,
                    ],
                    [
                        0x5d, 0x60, 0xed, 0x1a, 0x9e, 0xe3, 0xbb, 0xfa, 0xc2, 0xb0, 0xf2, 0x4a, 0xbf, 0x0c,
                        0x72, 0xfe, 0x7c, 0x39, 0xc4, 0xb5, 0x1b, 0x04, 0x69, 0x03, 0xa4, 0xdf, 0xe2, 0x1c,
                        0xa5, 0x31, 0x2c, 0x25,
                    ]
                ]),
                version: 0x2000_0000,
                nbits: 0x1703_1abe,
                ntime: 0x66aa_d286,
                clean_jobs: false
            })
        );
    }

    #[test]
    fn test_parse_set_difficulty() {
        assert_eq!(
            parse_set_difficulty(
                br#"{"params": [2.5], "id": null, "method": "mining.set_difficulty"}"#
            ),
            Ok(2.5)
        );

        assert_eq!(
            parse_set_difficulty(
                br#"{"params": [2.5a], "id": null, "method": "mining.set_difficulty"}"#
            ),
            Err(Error::JsonError(
                serde_json_core::de::Error::ExpectedListCommaOrEnd
            ))
        );
    }

    #[test]
    fn test_parse_method() {
        assert_eq!(
            parse_method(
                br#"{"params":["1fffe000"], "id":null, "method": "mining.set_version_mask"}"#
            ),
            Ok(Notification::SetVersionMask)
        );

        assert_eq!(
            parse_method(
                br#"{"params": ["bf", "4d16b6f85af6e2198f44ae2a6de67f78487ae5611b77c6c0440b921e00000000","01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff20020862062f503253482f04b8864e5008","072f736c7573682f000000000100f2052a010000001976a914d23fcdf86f7e756a64a7a9688ef9903327048ed988ac00000000", [],"00000002", "1c2ac4af", "504e86b9", false], "id": null, "method": "mining.notify"}"#
            ),
            Ok(Notification::Notify)
        );

        assert_eq!(
            parse_method(br#"{"params": [2.5], "id": null, "method": "mining.set_difficulty"}"#),
            Ok(Notification::SetDifficulty)
        );

        assert_eq!(
            parse_method(br#"{"params": [], "id": null, "method": "mining.broken"}"#),
            Err(Error::UnknownNotification)
        );
    }
}
