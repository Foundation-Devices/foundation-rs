// SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{Error, Result};
use core::str::FromStr;
use heapless::{String, Vec};
use hex::ToHex;
use json_rpc_types::{Id, Version};
use serde::Serialize;

#[derive(Debug)]
pub struct VersionRolling {
    // Bits set to 1 can be changed by the miner.
    // If a miner changes bits with mask value 0, the server will reject the submit.
    pub mask: Option<u32>,
    // Minimum number of bits that it needs for efficient version rolling in hardware.
    pub min_bit_count: u8,
}

#[derive(Debug)]
pub struct Info {
    // Exact URL used by the mining software to connect to the stratum server.
    pub connection_url: Option<String<32>>,
    // Manufacturer specific hardware revision string.
    pub hw_version: Option<String<32>>,
    // Manufacturer specific software version.
    pub sw_version: Option<String<32>>,
    // Unique identifier of the mining device.
    pub hw_id: Option<String<32>>,
}

#[derive(Debug)]
pub struct Extensions {
    // This extension allows the miner to change the value of some bits in the version field
    // in the block header. Currently there are no standard bits used for version rolling
    // so they need to be negotiated between a miner and a server.
    pub version_rolling: Option<VersionRolling>,
    // This extension allows miner to request a minimum difficulty for the connected machine.
    // It solves a problem in the original stratum protocol where there is no way how to
    // communicate hard limit of the connected device.
    pub minimum_difficulty: Option<u32>,
    // Miner advertises its capability of receiving message "mining.set_extranonce" message
    // (useful for hash rate routing scenarios).
    pub subscribe_extranonce: Option<()>,
    // Miner provides additional text-based information.
    pub info: Option<Info>,
}

/// # Configure Request
///
/// Create a client configure request.
///
/// ## Parameters
///
/// id: must be an unique integer to identify the request.
///     Will be used when a response is received to match corresponding request.
///
/// exts: a list of extensions to configure.
///
/// ## Example
/// ```
/// use stratum_v1::client_req::{configure_request, Extensions, VersionRolling};
/// use heapless::Vec;
///
/// let mut buf = [0u8; 1024];
/// let mut exts = Extensions {
///     version_rolling: Some(VersionRolling{mask: Some(0x1fffe000), min_bit_count: 2}),
///     minimum_difficulty: None,
///     subscribe_extranonce: None,
///     info: None,
/// };
/// let len = configure_request(0, exts, buf.as_mut_slice());
/// assert!(len.is_ok());
/// assert_eq!(len.unwrap(),153);
/// assert_eq!(&buf[0..153], br#"{"jsonrpc":"2.0","method":"mining.configure","params":[["version-rolling"],{"version-rolling.mask":"1fffe000","version-rolling.min-bit-count":2}],"id":0}"#);
///
/// let mut exts = Extensions {
///     version_rolling: Some(VersionRolling{mask: Some(0x1fffe000), min_bit_count: 2}),
///     minimum_difficulty: Some(2048),
///     subscribe_extranonce: None,
///     info: None,
/// };
/// let len = configure_request(0, exts, buf.as_mut_slice());
/// assert!(len.is_ok());
/// assert_eq!(len.unwrap(),206);
/// assert_eq!(&buf[0..206], br#"{"jsonrpc":"2.0","method":"mining.configure","params":[["version-rolling","minimum-difficulty"],{"version-rolling.mask":"1fffe000","version-rolling.min-bit-count":2,"minimum-difficulty.value":2048}],"id":0}"#);
/// ```
pub fn configure_request(id: u64, exts: Extensions, buf: &mut [u8]) -> Result<usize> {
    let method = String::from_str("mining.configure").unwrap();

    type ExtList = Vec<String<32>, 4>;

    #[derive(Debug, Serialize)]
    struct ExtParams {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "version-rolling.mask")]
        version_rolling_mask: Option<String<8>>,

        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "version-rolling.min-bit-count")]
        version_rolling_min_bit_count: Option<u8>,

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
            .push(String::from_str("version-rolling").unwrap())
            .unwrap();
        if let Some(mask) = &version_rolling.mask {
            ext_params.version_rolling_mask = Some(mask.to_be_bytes().encode_hex());
        }
        ext_params.version_rolling_min_bit_count = Some(version_rolling.min_bit_count);
    }
    if let Some(minimum_difficulty) = &exts.minimum_difficulty {
        ext_list
            .push(String::from_str("minimum-difficulty").unwrap())
            .unwrap();
        ext_params.minimum_difficulty_value = Some(*minimum_difficulty);
    }
    if let Some(()) = &exts.subscribe_extranonce {
        ext_list
            .push(String::from_str("subscribe-extranonce").unwrap())
            .unwrap();
    }
    if let Some(info) = &exts.info {
        ext_list.push(String::from_str("info").unwrap()).unwrap();
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
    let req = json_rpc_types::Request::<ConfigureParams, String<16>> {
        jsonrpc: Version::V2,
        method,
        params,
        id: Some(Id::Num(id)),
    };
    serde_json_core::to_slice(&req, buf).map_err(Error::msg)
}

/// # Connect Request
///
/// Create a client connection request.
///
/// ## Parameters
///
/// id: must be an unique integer to identify the request.
///     Will be used when a response is received to match corresponding request.
///
/// identifier: a string to identify the client to the pool.
///
/// ## Example
/// ```
/// use core::str::FromStr;
/// use heapless::String;
/// use stratum_v1::client_req::connect_request;
///
/// let mut buf = [0u8; 1024];
/// let len = connect_request(0, Some(String::<32>::from_str("test").unwrap()), buf.as_mut_slice());
/// assert!(len.is_ok());
/// assert_eq!(len.unwrap(),70);
/// assert_eq!(&buf[0..70], br#"{"jsonrpc":"2.0","method":"mining.subscribe","params":["test"],"id":0}"#);
///
/// let len = connect_request(1, Some(String::<32>::from_str("").unwrap()), buf.as_mut_slice());
/// assert!(len.is_ok());
/// assert_eq!(len.unwrap(),66);
/// assert_eq!(&buf[0..66], br#"{"jsonrpc":"2.0","method":"mining.subscribe","params":[""],"id":1}"#);
///
/// let len = connect_request(1, None, buf.as_mut_slice());
/// assert!(len.is_ok());
/// assert_eq!(len.unwrap(),64);
/// assert_eq!(&buf[0..64], br#"{"jsonrpc":"2.0","method":"mining.subscribe","params":[],"id":1}"#);
/// ```
pub fn connect_request(id: u64, identifier: Option<String<32>>, buf: &mut [u8]) -> Result<usize> {
    let method = String::from_str("mining.subscribe").unwrap();
    let mut vec = Vec::<String<32>, 1>::new();
    if let Some(identifier) = identifier {
        vec.push(identifier).map_err(Error::msg)?;
    }
    let params = Some(vec);
    let req = json_rpc_types::Request::<Vec<String<32>, 1>, String<16>> {
        jsonrpc: Version::V2,
        method,
        params,
        id: Some(Id::Num(id)),
    };
    serde_json_core::to_slice(&req, buf).map_err(Error::msg)
}

/// # Authorize Request
///
/// Create a client authorize request.
///
/// ## Parameters
///
/// id: must be an unique integer to identify the request.
///     Will be used when a response is received to match corresponding request.
///
/// user: a string with user name.
///       Usually composed by "<UserName>.<WorkerName>".
///
/// pass: a string with user password.
///
/// ## Example
/// ```
/// use core::str::FromStr;
/// use heapless::String;
/// use stratum_v1::client_req::authorize_request;
///
/// let mut buf = [0u8; 1024];
/// let len = authorize_request(1, String::<32>::from_str("slush.miner1").unwrap(), String::<32>::from_str("password").unwrap(), buf.as_mut_slice());
/// assert!(len.is_ok());
/// assert_eq!(len.unwrap(),89);
/// assert_eq!(&buf[0..89], br#"{"jsonrpc":"2.0","method":"mining.authorize","params":["slush.miner1","password"],"id":1}"#);
///
/// let len = authorize_request(2, String::<32>::from_str("").unwrap(), String::<32>::from_str("").unwrap(), buf.as_mut_slice());
/// assert!(len.is_ok());
/// assert_eq!(len.unwrap(),69);
/// assert_eq!(&buf[0..69], br#"{"jsonrpc":"2.0","method":"mining.authorize","params":["",""],"id":2}"#);
/// ```
pub fn authorize_request(
    id: u64,
    user: String<32>,
    pass: String<32>,
    buf: &mut [u8],
) -> Result<usize> {
    let method = String::from_str("mining.authorize").unwrap();
    let mut vec = Vec::<String<32>, 2>::new();
    vec.push(user).map_err(Error::msg)?;
    vec.push(pass).map_err(Error::msg)?;
    let params = Some(vec);
    let req = json_rpc_types::Request::<Vec<String<32>, 2>, String<16>> {
        jsonrpc: Version::V2,
        method,
        params,
        id: Some(Id::Num(id)),
    };
    serde_json_core::to_slice(&req, buf).map_err(Error::msg)
}

pub struct Share {
    pub user: String<32>,
    pub job_id: String<32>,
    pub extranonce2: u32,
    pub ntime: u32,
    pub nonce: u32,
    pub version_bits: Option<u32>,
}

/// # Submit Request
///
/// Create a client submit request.
///
/// ## Parameters
///
/// id: must be an unique integer to identify the request.
///     Will be used when a response is received to match corresponding request.
///
/// user: a string with user name. Max 32 characters.
///       Usually composed by "<UserName>.<WorkerName>".
///
/// job_id: a string with the Job ID given in the Mining Job Notification.
///
/// extranonce2: a 32-bits unsigned integer with the share's Extranonce2.
///
/// ntime: a 32-bits unsigned integer with the share's nTime.
///
/// nonce: a 32-bits unsigned integer with the share's nOnce.
///
/// version_bits: an optional 32-bits unsigned integer with the share's version_bits.
///
/// ## Example
/// ```
/// use core::str::FromStr;
/// use heapless::String;
/// use stratum_v1::client_req::{submit_request, Share};
///
/// let mut buf = [0u8; 1024];
/// let share = Share {
///     user: String::<32>::from_str("slush.miner1").unwrap(),
///     job_id: String::<32>::from_str("bf").unwrap(),
///     extranonce2: 1,
///     ntime: 1347323629,
///     nonce: 0xb2957c02,
///     version_bits: None,
/// };
/// let len = submit_request(1, share, buf.as_mut_slice());
/// assert!(len.is_ok());
/// assert_eq!(len.unwrap(),113);
/// assert_eq!(&buf[0..113], br#"{"jsonrpc":"2.0","method":"mining.submit","params":["slush.miner1","bf","00000001","504e86ed","b2957c02"],"id":1}"#);
/// ```
pub fn submit_request(id: u64, share: Share, buf: &mut [u8]) -> Result<usize> {
    let method = String::from_str("mining.submit").unwrap();
    let mut vec = Vec::<String<32>, 6>::new();
    vec.push(share.user).map_err(Error::msg)?;
    vec.push(share.job_id).map_err(Error::msg)?;
    vec.push(
        share
            .extranonce2
            .to_be_bytes()
            .as_ref()
            .encode_hex::<String<32>>(),
    )
    .map_err(Error::msg)?;
    vec.push(
        share
            .ntime
            .to_be_bytes()
            .as_ref()
            .encode_hex::<String<32>>(),
    )
    .map_err(Error::msg)?;
    vec.push(
        share
            .nonce
            .to_be_bytes()
            .as_ref()
            .encode_hex::<String<32>>(),
    )
    .map_err(Error::msg)?;
    if let Some(v) = share.version_bits {
        vec.push(v.to_be_bytes().as_ref().encode_hex::<String<32>>())
            .map_err(Error::msg)?;
    }
    let params = Some(vec);
    let req = json_rpc_types::Request::<Vec<String<32>, 6>, String<13>> {
        jsonrpc: Version::V2,
        method,
        params,
        id: Some(Id::Num(id)),
    };
    serde_json_core::to_slice(&req, buf).map_err(Error::msg)
}
