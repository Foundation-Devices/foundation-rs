// SPDX-FileCopyrightText: © 2023 Foundation Devices, Inc. <hello@foundationdevices.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use embedded_io::Write;

pub fn encode_compact_size<W: Write>(mut w: W, v: u64) -> Result<usize, W::Error> {
    match v {
        0..=0xFC => w.write(&[v as u8]),
        0xFD..=0xFFFF => {
            let mut buf = [0; 3];
            buf[0] = 0xFD;
            buf[1..].copy_from_slice(&(v as u16).to_le_bytes());
            w.write(&buf)
        }
        0x10000..=0xFFFFFFFF => {
            let mut buf = [0; 5];
            buf[0] = 0xFE;
            buf[1..].copy_from_slice(&(v as u32).to_le_bytes());
            w.write(&buf)
        }
        _ => {
            let mut buf = [0; 9];
            buf[0] = 0xFF;
            buf[1..].copy_from_slice(&(v as u64).to_le_bytes());
            w.write(&buf)
        }
    }
}

#[cfg(test)]
pub mod test {
    #[test]
    fn encode_compact_size() {
        // u8
        let mut tmp = [0u8; 1];
        let len = super::encode_compact_size((&mut tmp) as &mut [_], 0xFC).unwrap();
        assert_eq!(len, tmp.len());
        assert_eq!(tmp, [0xFC]);

        // u16
        let mut tmp = [0u8; 3];
        let len = super::encode_compact_size((&mut tmp) as &mut [_], 0xFFFF).unwrap();
        assert_eq!(len, tmp.len());
        assert_eq!(tmp, [0xFD, 0xFF, 0xFF]);

        // u32
        let mut tmp = [0u8; 5];
        let len = super::encode_compact_size((&mut tmp) as &mut [_], 0xFFFF_FFFF).unwrap();
        assert_eq!(len, tmp.len());
        assert_eq!(tmp, [0xFE, 0xFF, 0xFF, 0xFF, 0xFF]);

        // u64
        let mut tmp = [0u8; 9];
        let len =
            super::encode_compact_size((&mut tmp) as &mut [_], 0xFFFF_FFFF_FFFF_FFFF).unwrap();
        assert_eq!(len, tmp.len());
        assert_eq!(tmp, [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    }
}
