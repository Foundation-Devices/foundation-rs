// SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::{Error, Result};
use faster_hex::hex_string;
use heapless::{String, Vec};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt-03", derive(defmt::Format))]
pub(crate) enum ReqKind {
    Configure,
    Connect,
    Authorize,
    Submit,
}

///Request representation.
///
///Note that omitting `id` means that request is notification, rather than call, which expects
///response.
///This can be used to indicate lack of interest in response.
///
///Type parameters:
///
///- `P` - to specify type of `params` field, which is optional. Normally it should be collection of values or object. But choice is yours.
///- `T` - specifies textual type. By default it uses static buffer of 32 bytes, which is more than enough in normal cases.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "defmt-03", derive(defmt::Format))]
pub struct Request<P> {
    #[serde(skip_serializing_if = "Option::is_none")]
    ///An identifier established by the Client.
    ///
    ///If not present, request is notification to which
    ///there should be no response.
    pub id: Option<u64>,
    ///A String containing the name of the method to be invoked
    ///
    ///By default is static buffer of 32 bytes.
    pub method: String<32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ///A Structured value that holds the parameter values to be used during the invocation of the method
    pub params: Option<P>,
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt-03", derive(defmt::Format))]
pub struct VersionRolling {
    /// Bits set to 1 can be changed by the miner.
    /// If a miner changes bits with mask value 0, the server will reject the submit.
    pub mask: Option<u32>,
    /// Minimum number of bits that it needs for efficient version rolling in hardware.
    pub min_bit_count: Option<u8>,
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt-03", derive(defmt::Format))]
pub struct Info {
    /// Exact URL used by the mining software to connect to the stratum server.
    pub connection_url: Option<String<32>>,
    /// Manufacturer specific hardware revision string.
    pub hw_version: Option<String<32>>,
    /// Manufacturer specific software version.
    pub sw_version: Option<String<32>>,
    /// Unique identifier of the mining device.
    pub hw_id: Option<String<32>>,
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt-03", derive(defmt::Format))]
pub struct Extensions {
    /// This extension allows the miner to change the value of some bits in the version field
    /// in the block header. Currently there are no standard bits used for version rolling
    /// so they need to be negotiated between a miner and a server.
    pub version_rolling: Option<VersionRolling>,
    /// This extension allows miner to request a minimum difficulty for the connected machine.
    /// It solves a problem in the original stratum protocol where there is no way how to
    /// communicate hard limit of the connected device.
    pub minimum_difficulty: Option<u32>,
    /// Miner advertises its capability of receiving message "mining.set_extranonce" message
    /// (useful for hash rate routing scenarios).
    pub subscribe_extranonce: Option<()>,
    /// Miner provides additional text-based information.
    pub info: Option<Info>,
}

pub(crate) fn configure(id: u64, exts: Extensions, buf: &mut [u8]) -> Result<usize> {
    let method = "mining.configure".try_into().unwrap();

    type ExtList = Vec<String<32>, 4>;

    #[derive(Debug, Serialize)]
    #[cfg_attr(feature = "defmt-03", derive(defmt::Format))]
    struct ExtParams {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "version-rolling.mask")]
        version_rolling_mask: Option<String<8>>,

        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "version-rolling.min-bit-count")]
        version_rolling_min_bit_count: Option<String<8>>,

        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "minimum-difficulty.value")]
        minimum_difficulty_value: Option<u32>,

        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "info.connection-url")]
        info_connection_url: Option<String<32>>,

        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "info.hw-version")]
        info_hw_version: Option<String<32>>,

        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "info.sw-version")]
        info_sw_version: Option<String<32>>,

        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "info.hw-id")]
        info_hw_id: Option<String<32>>,
    }

    #[derive(Debug, Serialize)]
    #[cfg_attr(feature = "defmt-03", derive(defmt::Format))]
    struct ConfigureParams(ExtList, ExtParams);

    let mut ext_list = Vec::new();
    let mut ext_params = ExtParams {
        version_rolling_mask: None,
        version_rolling_min_bit_count: None,
        minimum_difficulty_value: None,
        info_connection_url: None,
        info_hw_version: None,
        info_sw_version: None,
        info_hw_id: None,
    };
    if let Some(version_rolling) = &exts.version_rolling {
        ext_list
            .push("version-rolling".try_into().unwrap())
            .unwrap();
        if let Some(mask) = version_rolling.mask {
            ext_params.version_rolling_mask = Some(hex_string::<8>(&mask.to_be_bytes()));
        }
        if let Some(min_bit_count) = version_rolling.min_bit_count {
            let min_bit_count = min_bit_count as u32;
            ext_params.version_rolling_min_bit_count =
                Some(hex_string::<8>(&min_bit_count.to_be_bytes()));
        }
    }
    if let Some(minimum_difficulty) = &exts.minimum_difficulty {
        ext_list
            .push("minimum-difficulty".try_into().unwrap())
            .unwrap();
        ext_params.minimum_difficulty_value = Some(*minimum_difficulty);
    }
    if let Some(()) = &exts.subscribe_extranonce {
        ext_list
            .push("subscribe-extranonce".try_into().unwrap())
            .unwrap();
    }
    if let Some(info) = &exts.info {
        ext_list.push("info".try_into().unwrap()).unwrap();
        if let Some(connection_url) = &info.connection_url {
            ext_params.info_connection_url = Some(connection_url.clone());
        }
        if let Some(hw_version) = &info.hw_version {
            ext_params.info_hw_version = Some(hw_version.clone());
        }
        if let Some(sw_version) = &info.sw_version {
            ext_params.info_sw_version = Some(sw_version.clone());
        }
        if let Some(hw_id) = &info.hw_id {
            ext_params.info_hw_id = Some(hw_id.clone());
        }
    }
    let params = Some(ConfigureParams(ext_list, ext_params));
    let req = Request::<ConfigureParams> {
        method,
        params,
        id: Some(id),
    };
    serde_json_core::to_slice(&req, buf).map_err(|_| Error::JsonBufferFull)
}

pub(crate) fn connect(id: u64, identifier: Option<String<32>>, buf: &mut [u8]) -> Result<usize> {
    let method = "mining.subscribe".try_into().unwrap();
    let mut vec = Vec::<String<32>, 1>::new();
    if let Some(identifier) = identifier {
        vec.push(identifier).map_err(|_| Error::VecFull)?;
    }
    let params = Some(vec);
    let req = Request::<Vec<String<32>, 1>> {
        method,
        params,
        id: Some(id),
    };
    serde_json_core::to_slice(&req, buf).map_err(|_| Error::JsonBufferFull)
}

pub(crate) fn authorize(
    id: u64,
    user: String<64>,
    pass: String<64>,
    buf: &mut [u8],
) -> Result<usize> {
    let method = "mining.authorize".try_into().unwrap();
    let mut vec = Vec::<String<64>, 2>::new();
    vec.push(user).map_err(|_| Error::VecFull)?;
    vec.push(pass).map_err(|_| Error::VecFull)?;
    let params = Some(vec);
    let req = Request::<Vec<String<64>, 2>> {
        method,
        params,
        id: Some(id),
    };
    serde_json_core::to_slice(&req, buf).map_err(|_| Error::JsonBufferFull)
}

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt-03", derive(defmt::Format))]
pub struct Share {
    pub job_id: String<64>,
    pub extranonce2: Vec<u8, 8>,
    pub ntime: u32,
    pub nonce: u32,
    pub version_bits: Option<u32>,
}

pub(crate) fn submit(id: u64, user: String<64>, share: Share, buf: &mut [u8]) -> Result<usize> {
    let method = "mining.submit".try_into().unwrap();
    let mut vec = Vec::<String<64>, 6>::new();
    vec.push(user).map_err(|_| Error::VecFull)?;
    vec.push(share.job_id).map_err(|_| Error::VecFull)?;
    vec.push(hex_string::<64>(share.extranonce2.as_slice()))
        .map_err(|_| Error::VecFull)?;
    vec.push(hex_string::<64>(&share.ntime.to_be_bytes()))
        .map_err(|_| Error::VecFull)?;
    vec.push(hex_string::<64>(&share.nonce.to_be_bytes()))
        .map_err(|_| Error::VecFull)?;
    if let Some(v) = share.version_bits {
        vec.push(hex_string::<64>(&v.to_be_bytes()))
            .map_err(|_| Error::VecFull)?;
    }
    let params = Some(vec);
    let req = Request::<Vec<String<64>, 6>> {
        method,
        params,
        id: Some(id),
    };
    serde_json_core::to_slice(&req, buf).map_err(|_| Error::JsonBufferFull)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_configure() {
        let mut buf = [0u8; 1024];
        let exts = Extensions {
            version_rolling: Some(VersionRolling {
                mask: Some(0x1fffe000),
                min_bit_count: Some(2),
            }),
            minimum_difficulty: None,
            subscribe_extranonce: None,
            info: None,
        };
        let len = configure(0, exts, buf.as_mut_slice());
        assert!(len.is_ok());
        assert_eq!(len.unwrap(), 146);
        assert_eq!(&buf[..146], br#"{"id":0,"method":"mining.configure","params":[["version-rolling"],{"version-rolling.mask":"1fffe000","version-rolling.min-bit-count":"00000002"}]}"#);

        let exts = Extensions {
            version_rolling: Some(VersionRolling {
                mask: Some(0x1fffe000),
                min_bit_count: Some(2),
            }),
            minimum_difficulty: Some(2048),
            subscribe_extranonce: None,
            info: None,
        };
        let len = configure(0, exts, buf.as_mut_slice());
        assert!(len.is_ok());
        assert_eq!(len.unwrap(), 199);
        assert_eq!(&buf[..199], br#"{"id":0,"method":"mining.configure","params":[["version-rolling","minimum-difficulty"],{"version-rolling.mask":"1fffe000","version-rolling.min-bit-count":"00000002","minimum-difficulty.value":2048}]}"#);
    }

    #[test]
    fn test_connect() {
        let mut buf = [0u8; 1024];
        let len = connect(0, Some("test".try_into().unwrap()), buf.as_mut_slice());
        assert!(len.is_ok());
        assert_eq!(len.unwrap(), 54);
        assert_eq!(
            &buf[..54],
            br#"{"id":0,"method":"mining.subscribe","params":["test"]}"#
        );

        let len = connect(1, Some("".try_into().unwrap()), buf.as_mut_slice());
        assert!(len.is_ok());
        assert_eq!(len.unwrap(), 50);
        assert_eq!(
            &buf[..50],
            br#"{"id":1,"method":"mining.subscribe","params":[""]}"#
        );

        let len = connect(1, None, buf.as_mut_slice());
        assert!(len.is_ok());
        assert_eq!(len.unwrap(), 48);
        assert_eq!(
            &buf[..48],
            br#"{"id":1,"method":"mining.subscribe","params":[]}"#
        );
    }

    #[test]
    fn test_authorize() {
        let mut buf = [0u8; 1024];
        let len = authorize(
            1,
            "slush.miner1".try_into().unwrap(),
            "password".try_into().unwrap(),
            buf.as_mut_slice(),
        );
        assert!(len.is_ok());
        assert_eq!(len.unwrap(), 73);
        assert_eq!(
            &buf[..73],
            br#"{"id":1,"method":"mining.authorize","params":["slush.miner1","password"]}"#
        );

        let len = authorize(
            2,
            "".try_into().unwrap(),
            "".try_into().unwrap(),
            buf.as_mut_slice(),
        );
        assert!(len.is_ok());
        assert_eq!(len.unwrap(), 53);
        assert_eq!(
            &buf[..53],
            br#"{"id":2,"method":"mining.authorize","params":["",""]}"#
        );
    }

    #[test]
    fn test_submit() {
        let mut buf = [0u8; 1024];
        let share = Share {
            job_id: "bf".try_into().unwrap(),
            extranonce2: hvec!(u8, 8, &[0, 0, 0, 1]),
            ntime: 1347323629,
            nonce: 0xb295_7c02,
            version_bits: None,
        };
        let len = super::submit(
            1,
            "slush.miner1".try_into().unwrap(),
            share,
            buf.as_mut_slice(),
        );
        assert!(len.is_ok());
        assert_eq!(len.unwrap(), 97);
        assert_eq!(&buf[..97], br#"{"id":1,"method":"mining.submit","params":["slush.miner1","bf","00000001","504e86ed","b2957c02"]}"#);
    }
}
