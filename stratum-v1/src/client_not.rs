// SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{Error, Result};
use heapless::{String, Vec};
use serde::Deserialize;

/// # Parse Notification Method
///
/// In order to know which kind of notification we are dealing with, we need to parse the notification method.
///
/// ## Parameters
///
/// resp: The slice notification to parse.
///
/// ## Examples
/// ```
/// use stratum_v1::client_not::parse_notification_method;
/// use heapless::String;
///
/// let resp = br#"{"params":["00003000"], "id":null, "method": "mining.set_version_mask"}"#;
/// assert_eq!(parse_notification_method(resp).unwrap(), String::<32>::from("mining.set_version_mask"));
///
/// let resp = br#"{"params": ["bf", "4d16b6f85af6e2198f44ae2a6de67f78487ae5611b77c6c0440b921e00000000","01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff20020862062f503253482f04b8864e5008","072f736c7573682f000000000100f2052a010000001976a914d23fcdf86f7e756a64a7a9688ef9903327048ed988ac00000000", [],"00000002", "1c2ac4af", "504e86b9", false], "id": null, "method": "mining.notify"}"#;
/// assert_eq!(parse_notification_method(resp).unwrap(), String::<32>::from("mining.notify"));
///
/// let resp = br#"{ "id": null, "method": "mining.set_difficulty", "params": [2]}"#;
/// assert_eq!(parse_notification_method(resp).unwrap(), String::<32>::from("mining.set_difficulty"));
/// ```
pub fn parse_notification_method(resp: &[u8]) -> Result<String<32>> {
    #[derive(Deserialize)]
    struct MethodOnly {
        method: String<32>,
    }
    Ok(serde_json_core::from_slice::<MethodOnly>(resp)
        .map_err(Error::msg)?
        .0
        .method)
}

/// # Parse Notification Set Version Mask
///
/// Parses the notification with the `set_version_mask` method.
///
/// ## Parameters
///
/// resp: The notification slice to parse.
///
/// ## Examples
/// ```
/// use stratum_v1::client_not::parse_notification_set_version_mask;
///
/// let resp = br#"{"params":["00003000"], "id":null, "method": "mining.set_version_mask"}"#;
/// let r = parse_notification_set_version_mask(resp);
/// println!("{:?}", r);
/// assert_eq!(parse_notification_set_version_mask(resp).unwrap(), 0x00003000);
/// ```
pub fn parse_notification_set_version_mask(resp: &[u8]) -> Result<u32> {
    #[derive(Deserialize)]
    struct SetVersionMaskNotificationParams(
        // mask: The meaning is the same as the "version-rolling.mask" return parameter.
        #[serde(deserialize_with = "hex::deserialize")] Vec<u8, 8>,
    );
    let v: Vec<u8, 4> = hex::decode_heapless(
        serde_json_core::from_slice::<json_rpc_types::Request<Vec<String<8>, 1>, String<64>>>(resp)
            .map_err(Error::msg)?
            .0
            .params
            .unwrap()
            .pop()
            .unwrap(),
    )
    .expect("decode error");
    Ok(u32::from_be_bytes(v[0..4].try_into().unwrap()))
}
