// SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

use super::notification::Work;
use crate::{Error, Result};

use bitcoin::{
    block::{Header, Version},
    hash_types::{BlockHash, TxMerkleNode},
    hashes::{sha256d::Hash as DHash, Hash},
    CompactTarget,
};
use heapless::Vec;

#[derive(Debug)]
pub struct Job {
    pub job_id: u64,
    pub extranonce2: Vec<u8, 8>,
    pub version_bits: i32,
    pub header: Header,
}

#[cfg(feature = "defmt-03")]
impl defmt::Format for Job {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(
            fmt,
            "Job {{ job_id: {}, extranonce2: {:?}, version_bits: {}, header: {{ version: {:x}, prev_block_hash: {:x}, merkle_root: {:x}, time: {:x}, bits: {:x}, nonce: {:x} }} }}",
            self.job_id,
            self.extranonce2,
            self.version_bits,
            self.header.version.to_consensus(),
            self.header.prev_blockhash.to_byte_array(),
            self.header.merkle_root.to_byte_array(),
            self.header.time,
            self.header.bits.to_consensus(),
            self.header.nonce
        );
    }
}

#[derive(Debug, Default)]
#[cfg_attr(feature = "defmt-03", derive(defmt::Format))]
pub(crate) struct JobCreator {
    job_id: u64,
    last_work: Option<Work>,
    version_mask: i32,
    pub(crate) version_rolling: bool,
    version_bits: u16,
    extranonce1: Vec<u8, 8>,
    extranonce2_size: usize,
    pub(crate) extranonce2_rolling: bool,
    extranonce2: Vec<u8, 8>,
    pub(crate) ntime_rolling: bool,
    ntime_bits: u32,
}

impl JobCreator {
    pub(crate) fn set_version_mask(&mut self, mask: u32) {
        self.version_mask = mask as i32;
    }

    pub(crate) fn set_extranonces(
        &mut self,
        extranonce1: Vec<u8, 8>,
        extranonce2_size: usize,
    ) -> Result<()> {
        self.extranonce1 = extranonce1;
        self.extranonce2_size = extranonce2_size;
        self.extranonce2
            .resize_default(extranonce2_size)
            .map_err(|_| Error::VecFull)
    }

    pub(crate) fn set_work(&mut self, work: Work) -> Result<()> {
        self.last_work = Some(work);
        self.version_bits = 0;
        self.extranonce2
            .resize_default(self.extranonce2_size)
            .map_err(|_| Error::VecFull)?;
        self.extranonce2.fill(0);
        Ok(())
    }

    fn merkle_root(&self, work: &Work) -> Result<[u8; 32]> {
        let mut coinbase = Vec::<u8, 1024>::new();
        coinbase
            .extend_from_slice(work.coinb1.as_slice())
            .map_err(|_| Error::VecFull)?;
        coinbase
            .extend_from_slice(self.extranonce1.as_slice())
            .map_err(|_| Error::VecFull)?;
        coinbase
            .extend_from_slice(self.extranonce2.as_slice())
            .map_err(|_| Error::VecFull)?;
        coinbase
            .extend_from_slice(work.coinb2.as_slice())
            .map_err(|_| Error::VecFull)?;
        let coinbase_id = DHash::hash(coinbase.as_slice()).to_byte_array();
        let mut merkle_root = coinbase_id;
        for node in &work.merkle_branch {
            let mut to_hash = [0; 64];
            to_hash[..32].clone_from_slice(merkle_root.as_slice());
            to_hash[32..].copy_from_slice(node.as_slice());
            merkle_root = DHash::hash(to_hash.as_slice()).to_byte_array();
        }
        Ok(merkle_root)
    }

    pub(crate) fn roll(&mut self) -> Result<Job> {
        let work = self.last_work.as_ref().ok_or(Error::NoWork)?;
        let rolled_version = if self.version_rolling {
            self.version_bits = self.version_bits.wrapping_add(1);
            (work.version & !self.version_mask)
                | (((self.version_bits as i32) << self.version_mask.trailing_zeros())
                    & self.version_mask) // TODO: test this
        } else {
            work.version
        };
        if self.extranonce2_rolling {
            for i in (0..self.extranonce2_size).rev() {
                match self.extranonce2[i].checked_add(1) {
                    Some(v) => {
                        self.extranonce2[i] = v;
                        break;
                    }
                    None => self.extranonce2[i] = 0,
                }
            }
        }
        let rolled_ntime = if self.ntime_rolling {
            self.ntime_bits = self.ntime_bits.wrapping_add(1);
            work.ntime + self.ntime_bits
        } else {
            work.ntime
        };
        self.job_id += self.job_id.wrapping_add(1);
        Ok(Job {
            job_id: self.job_id,
            extranonce2: self.extranonce2.clone(),
            version_bits: rolled_version,
            header: Header {
                version: Version::from_consensus(rolled_version),
                prev_blockhash: BlockHash::from_byte_array(work.prev_hash),
                merkle_root: TxMerkleNode::from_byte_array(self.merkle_root(work)?),
                time: rolled_ntime,
                bits: CompactTarget::from_consensus(work.nbits),
                nonce: 0,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_root() {
        // example from https://github.com/stratum-mining/stratum/pull/305/files
        let mut coinb1 = Vec::new();
        coinb1
            .extend_from_slice(&[
                1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 75, 3, 63, 146, 11, 250, 190, 109,
                109, 86, 6, 110, 64, 228, 218, 247, 203, 127, 75, 141, 53, 51, 197, 180, 38, 117,
                115, 221, 103, 2, 11, 85, 213, 65, 221, 74, 90, 97, 128, 91, 182, 1, 0, 0, 0, 0, 0,
                0, 0, 49, 101, 7, 7, 139, 168, 76, 0, 1, 0, 0, 0, 0, 0, 0, 70, 84, 183, 110, 24,
                47, 115, 108, 117, 115, 104, 47, 0, 0, 0, 0, 3,
            ])
            .unwrap();
        let mut coinb2 = Vec::new();
        coinb2
            .extend_from_slice(&[
                25, 118, 169, 20, 124, 21, 78, 209, 220, 89, 96, 158, 61, 38, 171, 178, 223, 46,
                163, 213, 135, 205, 140, 65, 136, 172, 0, 0, 0, 0, 0, 0, 0, 0, 44, 106, 76, 41, 82,
                83, 75, 66, 76, 79, 67, 75, 58, 216, 82, 49, 182, 148, 133, 228, 178, 20, 248, 55,
                219, 145, 83, 227, 86, 32, 97, 240, 182, 3, 175, 116, 196, 69, 114, 83, 46, 0, 71,
                230, 205, 0, 0, 0, 0, 0, 0, 0, 0, 38, 106, 36, 170, 33, 169, 237, 179, 75, 32, 206,
                223, 111, 113, 150, 112, 248, 21, 36, 163, 123, 107, 168, 153, 76, 233, 86, 77,
                218, 162, 59, 48, 26, 180, 38, 62, 34, 3, 185, 0, 0, 0, 0,
            ])
            .unwrap();
        let mut merkle_branch = Vec::new();
        merkle_branch
            .push([
                122, 97, 64, 124, 164, 158, 164, 14, 87, 119, 226, 169, 34, 196, 251, 51, 31, 131,
                109, 250, 13, 54, 94, 6, 177, 27, 156, 154, 101, 30, 123, 159,
            ])
            .unwrap();
        merkle_branch
            .push([
                180, 113, 121, 253, 215, 85, 129, 38, 108, 2, 86, 66, 46, 12, 131, 139, 130, 87,
                29, 92, 59, 164, 247, 114, 251, 140, 129, 88, 127, 196, 125, 116,
            ])
            .unwrap();
        merkle_branch
            .push([
                171, 77, 225, 148, 80, 32, 41, 157, 246, 77, 161, 49, 87, 139, 214, 236, 149, 164,
                192, 128, 195, 9, 5, 168, 131, 27, 250, 9, 60, 179, 206, 94,
            ])
            .unwrap();
        merkle_branch
            .push([
                6, 187, 202, 75, 155, 220, 255, 166, 199, 35, 182, 220, 20, 96, 123, 41, 109, 40,
                186, 142, 13, 139, 230, 164, 116, 177, 217, 23, 16, 123, 135, 202,
            ])
            .unwrap();
        merkle_branch
            .push([
                109, 45, 171, 89, 223, 39, 132, 14, 150, 128, 241, 113, 136, 227, 105, 123, 224,
                48, 66, 240, 189, 186, 222, 49, 173, 143, 80, 90, 110, 219, 192, 235,
            ])
            .unwrap();
        merkle_branch
            .push([
                196, 7, 21, 180, 228, 161, 182, 132, 28, 153, 242, 12, 210, 127, 157, 86, 62, 123,
                181, 33, 84, 3, 105, 129, 148, 162, 5, 152, 64, 7, 196, 156,
            ])
            .unwrap();
        merkle_branch
            .push([
                22, 16, 18, 180, 109, 237, 68, 167, 197, 10, 195, 134, 11, 119, 219, 184, 49, 140,
                239, 45, 27, 210, 212, 120, 186, 60, 155, 105, 106, 219, 218, 32,
            ])
            .unwrap();
        merkle_branch
            .push([
                83, 228, 21, 241, 42, 240, 8, 254, 109, 156, 59, 171, 167, 46, 183, 60, 27, 63,
                241, 211, 235, 179, 147, 99, 46, 3, 22, 166, 159, 169, 183, 159,
            ])
            .unwrap();
        merkle_branch
            .push([
                230, 81, 3, 190, 66, 73, 200, 55, 94, 135, 209, 50, 92, 193, 114, 202, 141, 170,
                124, 142, 206, 29, 88, 9, 22, 110, 203, 145, 238, 66, 166, 35,
            ])
            .unwrap();
        merkle_branch
            .push([
                43, 106, 86, 239, 237, 74, 208, 202, 247, 133, 88, 42, 15, 77, 163, 186, 85, 26,
                89, 151, 5, 19, 30, 122, 108, 220, 215, 104, 152, 226, 113, 55,
            ])
            .unwrap();
        merkle_branch
            .push([
                148, 76, 200, 221, 206, 54, 56, 45, 252, 60, 123, 202, 195, 73, 144, 65, 168, 184,
                59, 130, 145, 229, 250, 44, 213, 70, 175, 128, 34, 31, 102, 80,
            ])
            .unwrap();
        merkle_branch
            .push([
                203, 112, 102, 31, 49, 147, 24, 25, 245, 61, 179, 146, 205, 127, 126, 100, 78, 204,
                228, 146, 209, 154, 89, 194, 209, 81, 57, 167, 88, 251, 44, 76,
            ])
            .unwrap();
        let work = Work {
            job_id: "662ede".try_into().unwrap(),
            prev_hash: [
                0xa8, 0x0f, 0x3e, 0x7f, 0xb2, 0xfa, 0xe8, 0x23, 0x68, 0x12, 0xba, 0xa7, 0x66, 0xc2,
                0xc6, 0x14, 0x1b, 0x91, 0x18, 0x53, 0x00, 0x01, 0xc1, 0xce, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ],
            coinb1,
            coinb2,
            merkle_branch,
            version: 0x2000_0000,
            nbits: 0x1703_1abe,
            ntime: 0x66aa_d286,
            clean_jobs: false,
        };
        let mut job_creator = JobCreator::default();
        let mut extranonce1 = Vec::new();
        extranonce1.extend_from_slice(&[120, 55, 179, 37]).unwrap();
        job_creator.set_extranonces(extranonce1, 4).unwrap();
        assert_eq!(
            job_creator.merkle_root(&work),
            Ok([
                73, 100, 41, 247, 106, 44, 1, 242, 3, 64, 100, 1, 98, 155, 40, 91, 170, 255, 170,
                29, 193, 255, 244, 71, 236, 29, 134, 218, 94, 45, 78, 77,
            ])
        );
    }
}
