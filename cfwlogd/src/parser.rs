// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Copyright 2019 Joyent, Inc.

use std::net::Ipv6Addr;

use chrono::{DateTime, TimeZone, Utc};
use nom::{be_u128, be_u16};
use serde::Serialize;
use uuid::Uuid;

#[cfg(target_endian = "little")]
const NATIVE_ENDIAN: nom::Endianness = nom::Endianness::Little;

#[cfg(target_endian = "big")]
const NATIVE_ENDIAN: nom::Endianness = nom::Endianness::Big;

#[derive(Debug, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CfwEvType {
    Block,
    Begin,
    End,
    Unknown, // Catch all (perhaps the kernel version is ahead of userland?)
}

impl From<u16> for CfwEvType {
    fn from(val: u16) -> CfwEvType {
        match val {
            1 => CfwEvType::Block,
            2 => CfwEvType::Begin,
            3 => CfwEvType::End,
            _ => CfwEvType::Unknown,
        }
    }
}

#[derive(Debug, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    In,
    Out,
}

impl From<u8> for Direction {
    fn from(val: u8) -> Direction {
        match val {
            1 => Direction::In,
            2 => Direction::Out,
            // This should never happen
            _ => panic!("unknown direction: {}", val),
        }
    }
}

#[derive(Debug, PartialEq, Serialize)]
pub enum Protocol {
    AH,
    ESP,
    ICMP,
    ICMPV6,
    TCP,
    UDP,
    UNKNOWN,
}

impl From<u8> for Protocol {
    fn from(val: u8) -> Protocol {
        match val {
            1 => Protocol::ICMP,
            6 => Protocol::TCP,
            17 => Protocol::UDP,
            50 => Protocol::ESP,
            51 => Protocol::AH,
            58 => Protocol::ICMPV6,
            // catch all in case fwadm ever supports additional protocols
            _ => Protocol::UNKNOWN,
        }
    }
}

#[derive(Debug, Serialize, PartialEq)]
#[serde(untagged)]
pub enum CfwEvent {
    Traffic(TrafficEvent),
}

impl CfwEvent {
    pub fn zone(&self) -> u32 {
        match &*self {
            CfwEvent::Traffic(event) => event.zonedid,
        }
    }
}

#[derive(Debug, PartialEq, Serialize)]
pub struct TrafficEvent {
    pub event: CfwEvType,
    #[serde(skip)]
    pub length: u16,
    #[serde(skip)]
    pub zonedid: u32,
    #[serde(skip)]
    pub rule_id: u32,
    pub source_port: u16,
    pub destination_port: u16,
    pub protocol: Protocol,
    pub direction: Direction,
    pub source_ip: Ipv6Addr,
    pub destination_ip: Ipv6Addr,
    pub timestamp: DateTime<Utc>,
    #[serde(rename = "rule")]
    pub rule_uuid: Uuid,
}

// Parse an entire event
named!(pub traffic_event( &[u8] ) -> CfwEvent,
    do_parse!(
        event: u16!(NATIVE_ENDIAN) >>
        length: u16!(NATIVE_ENDIAN) >>
        zonedid: u32!(NATIVE_ENDIAN) >>
        rule_id: u32!(NATIVE_ENDIAN) >>
        source_port: be_u16 >>
        destination_port: be_u16 >>
        protocol: take!(1) >>
        direction: take!(1) >>
        // padding
        _reserved: take!(6) >>
        source_ip: be_u128 >>
        destination_ip: be_u128 >>
        time_sec: i64!(NATIVE_ENDIAN) >>
        time_usec: i64!(NATIVE_ENDIAN) >>
        rule_uuid: take!(16) >>
        (CfwEvent::Traffic(TrafficEvent{
                event: CfwEvType::from(event),
                length,
                zonedid,
                rule_id,
                protocol: Protocol::from(protocol[0]),
                direction: Direction::from(direction[0]),
                source_port,
                destination_port,
                source_ip: Ipv6Addr::from(source_ip),
                destination_ip: Ipv6Addr::from(destination_ip),
                timestamp: Utc.timestamp(time_sec, (time_usec * 1000) as u32),
                rule_uuid: Uuid::from_slice(rule_uuid)
                    .expect("we should have 16 bytes exactly"),
            })
        )
    )
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_event() {
        let mut event = testutils::generate_event();
        std::dbg!(&event);
        let now = chrono::offset::Utc::now();
        let ts = Utc.timestamp(now.timestamp(), now.timestamp_subsec_micros() * 1000);
        let uuid = Uuid::parse_str("a7963143-14da-48d6-bef0-422f305d1556").unwrap();

        // customize some values in the generated event
        event.time_sec = ts.timestamp();
        event.time_usec = ts.timestamp_subsec_micros() as i64;
        event.rule_uuid = uuid.as_bytes().clone();

        let bytes = event.as_bytes();
        let cfw_event = traffic_event(bytes);
        std::dbg!(&cfw_event);

        // parsed successfully
        assert!(cfw_event.is_ok());
        let cfw_event = cfw_event.unwrap();

        // no leftover bytes after parsing
        let leftover: Vec<u8> = vec![];
        assert_eq!(cfw_event.0, leftover.as_slice(), "no bytes left over");
        match cfw_event.1 {
            CfwEvent::Traffic(e) => {
                assert_eq!(e.event, CfwEvType::from(event.event));
                assert_eq!(e.length, event.length);
                assert_eq!(e.zonedid, event.zonedid);
                assert_eq!(e.rule_id, event.rule_id);
                assert_eq!(e.protocol, Protocol::from(event.protocol));
                assert_eq!(e.direction, Direction::from(event.direction));
                assert_eq!(e.source_port, u16::from_be(event.source_port));
                assert_eq!(e.destination_port, u16::from_be(event.destination_port));
                assert_eq!(e.source_ip, Ipv6Addr::from(u128::from_be(event.source_ip)));
                assert_eq!(
                    e.destination_ip,
                    Ipv6Addr::from(u128::from_be(event.destination_ip))
                );
                assert_eq!(e.timestamp, ts);
                assert_eq!(e.rule_uuid, uuid);
            }
        }
    }
}
