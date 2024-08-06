// SPDX-FileCopyrightText: © 2024 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

use crate::{Error, Extensions, Info, Result, VersionRolling};
use faster_hex::hex_decode;
use heapless::{String, Vec};
use serde::{Deserialize, Deserializer};

pub(crate) fn parse_id(resp: &[u8]) -> Result<Option<u64>> {
    #[derive(Debug, Deserialize)]
    #[cfg_attr(feature = "defmt-03", derive(defmt::Format))]
    struct IdOnly {
        id: Option<u64>,
    }
    let id = serde_json_core::from_slice::<IdOnly>(resp)?.0.id;
    match id {
        None => Ok(None),
        Some(id) => Ok(Some(id)),
    }
}

///Response representation.
///
///When omitting `id`, it shall be serialized as `null` and means you're unable to identify `id` of
///`Request`.
///Note that JSON-RPCv2 specifies that `id` must be always present, therefore you're encouraged to
///treat missing `id` as error, unless response is error itself, in which case it might be
///indication that server treats request as invalid (e.g. unable to parse request's id).
///
///`jsonrpc` may be omitted during deserialization and defaults to v2.
///
///Type parameters:
///
///- `R`  - Type of payload for successful response
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "defmt-03", derive(defmt::Format))]
pub struct Response<R> {
    ///An identifier established by the Client.
    ///
    ///If not present, it is sent in response to invalid request (e.g. unable to recognize id).
    ///
    ///Must be present always, so `None` is serialized as `null`
    pub id: Option<u64>,

    ///Content of response, depending on whether it is success or failure.
    pub payload: Result<R>,
}

impl<'de, R: Deserialize<'de>> Deserialize<'de> for Response<R> {
    fn deserialize<D: Deserializer<'de>>(der: D) -> core::result::Result<Self, D::Error> {
        use core::marker::PhantomData;
        use serde::de::{self, Visitor};

        #[derive(Debug, Deserialize)]
        #[cfg_attr(feature = "defmt-03", derive(defmt::Format))]
        struct RespErr(isize, String<32>, Option<String<32>>);

        impl From<RespErr> for Error {
            fn from(err: RespErr) -> Self {
                Error::Pool {
                    code: err.0,
                    message: err.1,
                    detail: err.2,
                }
            }
        }

        struct MapVisit<R>(PhantomData<R>);

        enum Key {
            Result,
            Error,
            Id,
        }

        struct KeyVisitor;

        impl<'a> Visitor<'a> for KeyVisitor {
            type Value = Key;

            #[inline]
            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("Key must be a string and one of the following values: ['result', 'error', 'id']")
            }

            #[inline]
            fn visit_str<E: serde::de::Error>(
                self,
                text: &str,
            ) -> core::result::Result<Self::Value, E> {
                if text.eq_ignore_ascii_case("result") {
                    Ok(Key::Result)
                } else if text.eq_ignore_ascii_case("error") {
                    Ok(Key::Error)
                } else if text.eq_ignore_ascii_case("id") {
                    Ok(Key::Id)
                } else {
                    Err(serde::de::Error::invalid_value(
                        serde::de::Unexpected::Str(text),
                        &self,
                    ))
                }
            }
        }

        impl<'a> Deserialize<'a> for Key {
            #[inline]
            fn deserialize<D: Deserializer<'a>>(des: D) -> core::result::Result<Self, D::Error> {
                des.deserialize_str(KeyVisitor)
            }
        }

        impl<'de, R: Deserialize<'de>> Visitor<'de> for MapVisit<R> {
            type Value = Response<R>;

            #[inline]
            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("Object resembling JSON-RPC response type")
            }

            fn visit_map<A: de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> core::result::Result<Self::Value, A::Error> {
                //Normally you'd use unitialized struct, but it is highly unlikely to guarantee
                //safety of field-by-field initialization
                let mut result = None;
                let mut id = None;

                while let Some(key) = map.next_key::<Key>()? {
                    match key {
                        //If for some reason user wishes to convey success with NULL, we need to respect that.
                        //This cannot be the case for error as its format is well defined
                        //And while spec does say `result` field MUST be object, theoretically NULL should qualify too.
                        //This is hack because bitch cannot have specialization stabilized forever
                        Key::Result if core::mem::size_of::<R>() == 0 => {
                            // Error has priority over Result, if both exist Result is ignored
                            if result.is_none() {
                                result = Some(Ok(map.next_value::<R>()?));
                            }
                        }
                        Key::Result => {
                            match map.next_value::<Option<R>>()? {
                                Some(value) => {
                                    // Error has priority over Result, if both exist Result is ignored
                                    if result.is_none() {
                                        result = Some(Ok(value));
                                    }
                                }
                                None => continue,
                            }
                        }
                        Key::Error => match map.next_value::<Option<RespErr>>()? {
                            Some(error) => {
                                // Error has priority over Result, if both exist Result is ignored
                                result = Some(Err(error));
                            }
                            None => continue,
                        },
                        Key::Id => {
                            id = map.next_value::<Option<u64>>()?;
                        }
                    }
                }

                Ok(Self::Value {
                    payload: match result {
                        Some(payload) => payload.map_err(|e| e.into()),
                        None => {
                            return Err(serde::de::Error::custom(
                                "JSON-RPC Response is missing either result or error field.",
                            ));
                        }
                    },
                    id,
                })
            }
        }

        der.deserialize_map(MapVisit(PhantomData))
    }
}

pub(crate) fn parse_configure(resp: &[u8]) -> Result<Extensions> {
    #[derive(Debug, Deserialize)]
    #[cfg_attr(feature = "defmt-03", derive(defmt::Format))]
    pub struct ConfigureRespRaw {
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "version-rolling")]
        pub version_rolling: Option<bool>,

        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "version-rolling.mask")]
        pub version_rolling_mask: Option<String<8>>,

        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "version-rolling.min-bit-count")]
        pub version_rolling_min_bit_count: Option<u8>,

        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "minimum-difficulty")]
        pub minimum_difficulty: Option<bool>,

        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "minimum-difficulty.value")]
        pub minimum_difficulty_value: Option<u32>,

        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "subscribe-extranonce")]
        pub subscribe_extranonce: Option<bool>,

        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "info")]
        pub info: Option<bool>,

        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "info.connection-url")]
        pub info_connection_url: Option<String<32>>,

        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "info.hw-version")]
        pub info_hw_version: Option<String<32>>,

        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "info.sw-version")]
        pub info_sw_version: Option<String<32>>,

        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "info.hw-id")]
        pub info_hw_id: Option<String<32>>,
    }

    impl TryFrom<ConfigureRespRaw> for Extensions {
        type Error = Error;

        fn try_from(raw: ConfigureRespRaw) -> Result<Self> {
            Ok(Extensions {
                version_rolling: if raw.version_rolling.is_some_and(|v| v) {
                    Some(VersionRolling {
                        mask: if raw.version_rolling_mask.is_some() {
                            let mut v = [0; 4];
                            hex_decode(raw.version_rolling_mask.unwrap().as_bytes(), &mut v)?;
                            Some(u32::from_be_bytes(v))
                        } else {
                            None
                        },
                        min_bit_count: raw.version_rolling_min_bit_count,
                    })
                } else {
                    None
                },
                minimum_difficulty: if raw.minimum_difficulty.is_some_and(|v| v) {
                    raw.minimum_difficulty_value
                } else {
                    None
                },
                subscribe_extranonce: if raw.subscribe_extranonce.is_some_and(|v| v) {
                    Some(())
                } else {
                    None
                },
                info: if raw.info.is_some_and(|v| v) {
                    Some(Info {
                        connection_url: raw.info_connection_url,
                        hw_version: raw.info_hw_version,
                        sw_version: raw.info_sw_version,
                        hw_id: raw.info_hw_id,
                    })
                } else {
                    None
                },
            })
        }
    }

    serde_json_core::from_slice::<Response<ConfigureRespRaw>>(resp)?
        .0
        .payload
        .map_err(|_| Error::RpcOther)?
        .try_into()
}

pub type Subscription = Vec<String<32>, 2>;

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt-03", derive(defmt::Format))]
pub struct ConnectResp {
    pub subscriptions: Vec<Subscription, 2>,
    pub extranonce1: Vec<u8, 8>,
    pub extranonce2_size: usize,
}

pub(crate) fn parse_connect(resp: &[u8]) -> Result<ConnectResp> {
    #[derive(Debug, Deserialize)]
    #[cfg_attr(feature = "defmt-03", derive(defmt::Format))]
    struct ConnectRespRaw(
        // Subscriptions details - 2-tuple with name of subscribed notification and subscription ID. Theoretically it may be used for unsubscribing, but obviously miners won't use it.
        Vec<Vec<String<32>, 2>, 2>,
        // Extranonce1 - Hex-encoded, per-connection unique string which will be used for coinbase serialization later. Keep it safe!
        String<16>,
        // Extranonce2_size - Represents expected length of extranonce2 which will be generated by the miner.
        usize,
    );

    impl TryFrom<ConnectRespRaw> for ConnectResp {
        type Error = Error;

        fn try_from(raw: ConnectRespRaw) -> Result<Self> {
            Ok(Self {
                subscriptions: raw.0,
                extranonce1: {
                    let mut v = Vec::new();
                    v.resize(raw.1.len() / 2, 0).map_err(|_| Error::VecFull)?;
                    hex_decode(raw.1.as_bytes(), v.as_mut_slice())?;
                    v
                },
                extranonce2_size: raw.2,
            })
        }
    }

    serde_json_core::from_slice::<Response<ConnectRespRaw>>(resp)?
        .0
        .payload?
        .try_into()
}

pub(crate) fn parse_authorize(resp: &[u8]) -> Result<bool> {
    serde_json_core::from_slice::<Response<bool>>(resp)?
        .0
        .payload
}

pub(crate) fn parse_submit(resp: &[u8]) -> Result<bool> {
    serde_json_core::from_slice::<Response<bool>>(resp)?
        .0
        .payload
}

#[cfg(test)]
mod tests {
    use heapless::Vec;

    use super::*;

    #[test]
    fn test_parse_id() {
        let resp = br#"{"id": 1, "result": [ [ ["mining.set_difficulty", "b4b6693b72a50c7116db18d6497cac52"], ["mining.notify", "ae6812eb4cd7735a302a8a9dd95cf71f"]], "08000002", 4], "error": null}"#;
        assert_eq!(parse_id(resp), Ok(Some(1)));

        let resp =
            br#"{"error":null,"id":2,"result":[[["mining.notify","e26e1928"]],"e26e1928",4]}"#;
        assert_eq!(parse_id(resp), Ok(Some(2)));

        let resp = br#"{ "id": null, "method": "mining.set_difficulty", "params": [2]}"#;
        assert_eq!(parse_id(resp), Ok(None));

        let resp = br#"{ "id": "ab", "method": "mining.set_difficulty", "params": [2]}"#;
        assert_eq!(
            parse_id(resp),
            Err(Error::JsonError(serde_json_core::de::Error::InvalidType))
        );
    }

    #[test]
    fn test_parse_configure() {
        let resp = br#"{"error": null,"id": 1,"result": {"version-rolling": true,"version-rolling.mask": "18000000","minimum-difficulty": true}}"#;
        assert_eq!(
            parse_configure(resp),
            Ok(Extensions {
                version_rolling: Some(VersionRolling {
                    mask: Some(0x1800_0000),
                    min_bit_count: None
                }),
                minimum_difficulty: None,
                subscribe_extranonce: None,
                info: None,
            })
        );
    }

    #[test]
    fn test_parse_connect() {
        let resp = br#"{"id": 1, "result": [ [ ["mining.set_difficulty", "b4b6693b72a50c7116db18d6497cac52"], ["mining.notify", "ae6812eb4cd7735a302a8a9dd95cf71f"]], "08000002", 4], "error": null}"#;
        let mut subs = Vec::new();
        let mut sub = Vec::new();
        sub.push("mining.set_difficulty".try_into().unwrap())
            .unwrap();
        sub.push("b4b6693b72a50c7116db18d6497cac52".try_into().unwrap())
            .unwrap();
        subs.push(sub).unwrap();
        let mut sub = Vec::new();
        sub.push("mining.notify".try_into().unwrap()).unwrap();
        sub.push("ae6812eb4cd7735a302a8a9dd95cf71f".try_into().unwrap())
            .unwrap();
        subs.push(sub).unwrap();
        let mut extranonce1 = Vec::new();
        extranonce1
            .extend_from_slice(&[0x08, 0x00, 0x00, 0x02])
            .unwrap();
        assert_eq!(
            parse_connect(resp),
            Ok(ConnectResp {
                subscriptions: subs,
                extranonce1,
                extranonce2_size: 4,
            })
        );

        let resp = br#"{"id":2,"result":[[["mining.set_difficulty","1"],["mining.notify","1"]],"00",6],"error":null}"#;
        let mut subs = Vec::new();
        let mut sub = Vec::new();
        sub.push("mining.set_difficulty".try_into().unwrap())
            .unwrap();
        sub.push("1".try_into().unwrap()).unwrap();
        subs.push(sub).unwrap();
        let mut sub = Vec::new();
        sub.push("mining.notify".try_into().unwrap()).unwrap();
        sub.push("1".try_into().unwrap()).unwrap();
        subs.push(sub).unwrap();
        let mut extranonce1 = Vec::new();
        extranonce1.extend_from_slice(&[0x00]).unwrap();
        assert_eq!(
            parse_connect(resp),
            Ok(ConnectResp {
                subscriptions: subs,
                extranonce1,
                extranonce2_size: 6,
            })
        );

        let resp =
            br#"{"id":2,"error":null,"result":[[["mining.notify","e26e1928"]],"e26e1928",4]}"#;
        let mut subs = Vec::new();
        let mut sub = Vec::new();
        sub.push("mining.notify".try_into().unwrap()).unwrap();
        sub.push("e26e1928".try_into().unwrap()).unwrap();
        subs.push(sub).unwrap();
        let mut extranonce1 = Vec::new();
        extranonce1
            .extend_from_slice(&[0xe2, 0x6e, 0x19, 0x28])
            .unwrap();
        assert_eq!(
            parse_connect(resp),
            Ok(ConnectResp {
                subscriptions: subs,
                extranonce1,
                extranonce2_size: 4,
            })
        );

        let resp = br#"{"id": 10, "result": null, "error": [20, "Other/Unknown", null]}"#;
        assert_eq!(
            parse_connect(resp),
            Err(Error::Pool {
                code: 20,
                message: "Other/Unknown".try_into().unwrap(),
                detail: None
            })
        );
    }

    #[test]
    fn test_parse_authorize() {
        let resp = br#"{"id": 2, "result": true, "error": null}"#;
        assert_eq!(parse_authorize(resp), Ok(true));

        let resp = br#"{"id":3,"result":true,"error":null}"#;
        assert_eq!(parse_authorize(resp), Ok(true));

        let resp = br#"{"id": 10, "result": null, "error": [25, "Not subscribed", null]}"#;
        assert_eq!(
            parse_authorize(resp),
            Err(Error::Pool {
                code: 25,
                message: "Not subscribed".try_into().unwrap(),
                detail: None
            })
        );

        // Public-Pool
        let resp =
            br#"{"id":3,"result":null,"error":[20,"Authorization validation error",", slush"]}"#;
        assert_eq!(
            parse_authorize(resp),
            Err(Error::Pool {
                code: 20,
                message: "Authorization validation error".try_into().unwrap(),
                detail: Some(", slush".try_into().unwrap()),
            })
        );

        // Braiins Pool
        let resp = br#"{"id":3,"result":false,"error":null}"#;
        assert_eq!(parse_authorize(resp), Ok(false));
    }

    #[test]
    fn test_parse_submit() {
        let resp = br#"{"id": 2, "result": true, "error": null}"#;
        assert_eq!(parse_submit(resp), Ok(true));

        // Public-Pool
        let resp = br#"{"id":5,"result":null,"error":[23,"Difficulty too low",""]}"#;
        assert_eq!(
            parse_submit(resp),
            Err(Error::Pool {
                code: 23,
                message: "Difficulty too low".try_into().unwrap(),
                detail: Some("".try_into().unwrap())
            })
        );
        let resp = br#"{"id":84,"result":null,"error":[21,"Job not found",""]}"#;
        assert_eq!(
            parse_submit(resp),
            Err(Error::Pool {
                code: 21,
                message: "Job not found".try_into().unwrap(),
                detail: Some("".try_into().unwrap())
            })
        );
        // Philon Proxy
        let resp = br#"{"error":[23,"Low difficulty share",null],"id":26,"result":false}"#;
        assert_eq!(
            parse_submit(resp),
            Err(Error::Pool {
                code: 23,
                message: "Low difficulty share".try_into().unwrap(),
                detail: None
            })
        );
        let resp = br#"{"error":[-32601,"Method not found",null],"id":1708966505,"result":false}"#;
        assert_eq!(
            parse_submit(resp),
            Err(Error::Pool {
                code: -32601,
                message: "Method not found".try_into().unwrap(),
                detail: None
            })
        );
        // Braiins Pool
        let resp = br#"{"id":87,"result":null,"error":[30,"SInvalidJobId",null]}"#;
        assert_eq!(
            parse_submit(resp),
            Err(Error::Pool {
                code: 30,
                message: "SInvalidJobId".try_into().unwrap(),
                detail: None
            })
        );
        let resp = br#"{"id":87,"result":null,"error":[33,"SInvalidVersion",null]}"#;
        assert_eq!(
            parse_submit(resp),
            Err(Error::Pool {
                code: 33,
                message: "SInvalidVersion".try_into().unwrap(),
                detail: None
            })
        );
        let resp = br#"{"id":5,"result":null,"error":[34,"SInvalidTime",null]}"#;
        assert_eq!(
            parse_submit(resp),
            Err(Error::Pool {
                code: 34,
                message: "SInvalidTime".try_into().unwrap(),
                detail: None
            })
        );
        let resp = br#"{"id":5,"result":null,"error":[35,"SInvalidExnSize",null]}"#;
        assert_eq!(
            parse_submit(resp),
            Err(Error::Pool {
                code: 35,
                message: "SInvalidExnSize".try_into().unwrap(),
                detail: None
            })
        );
        let resp = br#"{"id":5,"result":null,"error":[38,"STooLowDiff",null]}"#;
        assert_eq!(
            parse_submit(resp),
            Err(Error::Pool {
                code: 38,
                message: "STooLowDiff".try_into().unwrap(),
                detail: None
            })
        );
        let resp = br#"{"id":5,"result":null,"error":[39,"SStaleJobNoSub",null]}"#;
        assert_eq!(
            parse_submit(resp),
            Err(Error::Pool {
                code: 39,
                message: "SStaleJobNoSub".try_into().unwrap(),
                detail: None
            })
        );
    }
}
