// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Copyright 2019 Joyent, Inc.

use std::net::Ipv6Addr;

use chrono::{DateTime, TimeZone, Utc};
use nom::bytes::complete::take;
use nom::error::VerboseError;
use nom::number::complete::{be_u128, be_u16, le_i64, le_u16, le_u32, le_u8};
use nom::IResult;
use serde::Serialize;
use std::boxed::Box;
use uuid::Uuid;

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
    Unknown(UnknownEvent),
}

impl CfwEvent {
    pub fn zone(&self) -> u32 {
        match &*self {
            CfwEvent::Traffic(event) => event.zonedid,
            CfwEvent::Unknown(event) => event.zonedid,
        }
    }
}

#[derive(Debug, PartialEq, Serialize)]
pub struct UnknownEvent {
    pub event: CfwEvType,
    #[serde(skip)]
    pub raw_event: u16,
    #[serde(skip)]
    pub length: u16,
    #[serde(skip)]
    pub zonedid: u32,
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

type CfwEventHeader = (u16, u16, u32);

/// Read the common bytes of all events, aka event type, length, and zonedid.
fn cfwevent_parse_header<'a>(
    bytes: &'a [u8],
) -> IResult<&'a [u8], CfwEventHeader, VerboseError<&'a [u8]>> {
    let (bytes, event) = le_u16(bytes)?;
    let (bytes, length) = le_u16(bytes)?;
    let (bytes, zonedid) = le_u32(bytes)?;
    Ok((bytes, (event, length, zonedid)))
}

/// Parse an UnknownEvent type variant so that we can skip past the associated bytes.
fn cfwevent_parse_unknown<'a>(
    header: CfwEventHeader,
    bytes: &'a [u8],
) -> IResult<&'a [u8], Box<CfwEvent>, VerboseError<&'a [u8]>> {
    // Take everything after the first 8 bytes (event + length + zonedid).
    let (bytes, _skip) = take(header.1 - 8)(bytes)?;
    Ok((
        bytes,
        Box::new(CfwEvent::Unknown(UnknownEvent {
            event: CfwEvType::Unknown,
            raw_event: header.0,
            length: header.1,
            zonedid: header.2,
        })),
    ))
}

/// Parse an TrafficEvent type variant that was generated due to a firewall rule match.
fn cfwevent_parse_traffic<'a>(
    evtype: CfwEvType,
    header: CfwEventHeader,
    bytes: &'a [u8],
) -> IResult<&'a [u8], Box<CfwEvent>, VerboseError<&'a [u8]>> {
    let (bytes, rule_id) = le_u32(bytes)?;
    let (bytes, source_port) = be_u16(bytes)?;
    let (bytes, destination_port) = be_u16(bytes)?;
    let (bytes, protocol) = le_u8(bytes)?;
    let (bytes, direction) = le_u8(bytes)?;
    let (bytes, _padding) = take(6usize)(bytes)?;
    let (bytes, source_ip) = be_u128(bytes)?;
    let (bytes, destination_ip) = be_u128(bytes)?;
    let (bytes, time_sec) = le_i64(bytes)?;
    let (bytes, time_usec) = le_i64(bytes)?;
    let (bytes, rule_uuid) = take(16usize)(bytes)?;
    Ok((
        bytes,
        Box::new(CfwEvent::Traffic(TrafficEvent {
            event: evtype,
            length: header.1,
            zonedid: header.2,
            rule_id,
            protocol: Protocol::from(protocol),
            direction: Direction::from(direction),
            source_port,
            destination_port,
            source_ip: Ipv6Addr::from(source_ip),
            destination_ip: Ipv6Addr::from(destination_ip),
            timestamp: Utc.timestamp(time_sec, (time_usec * 1000) as u32),
            rule_uuid: Uuid::from_slice(rule_uuid).expect("we should have 16 bytes exactly"),
        })),
    ))
}

/// Parse a single CfwEvent out of the provided bytes returning a slice that points at the next
/// event.
pub fn cfwevent_parse<'a>(
    bytes: &'a [u8],
) -> IResult<&'a [u8], Box<CfwEvent>, VerboseError<&'a [u8]>> {
    let (bytes, header) = cfwevent_parse_header(bytes)?;
    let event_type = CfwEvType::from(header.0);
    match event_type {
        CfwEvType::Unknown => cfwevent_parse_unknown(header, bytes),
        _ => cfwevent_parse_traffic(event_type, header, bytes),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_traffic_event() {
        let mut event = testutils::generate_event();
        let now = chrono::offset::Utc::now();
        let ts = Utc.timestamp(now.timestamp(), now.timestamp_subsec_micros() * 1000);
        let uuid = Uuid::parse_str("a7963143-14da-48d6-bef0-422f305d1556").unwrap();

        // customize some values in the generated event
        event.time_sec = ts.timestamp();
        event.time_usec = ts.timestamp_subsec_micros() as i64;
        event.rule_uuid = uuid.as_bytes().clone();

        let bytes = event.as_bytes();
        let cfw_event = cfwevent_parse(bytes);

        // parsed successfully
        assert!(cfw_event.is_ok());
        let cfw_event = cfw_event.unwrap();

        assert!(cfw_event.0.is_empty(), "no bytes left over");
        match *cfw_event.1 {
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
            _ => panic!("unexpected CfwEvType"),
        }
    }

    #[test]
    fn parse_unknown_event() {
        let event = testutils::generate_unknown_event();
        let bytes = event.as_bytes();
        let cfw_event = cfwevent_parse(bytes);

        // parsed successfully
        assert!(cfw_event.is_ok());
        let cfw_event = cfw_event.unwrap();

        assert!(cfw_event.0.is_empty(), "no bytes left over");
        match *cfw_event.1 {
            CfwEvent::Unknown(e) => {
                assert_eq!(e.event, CfwEvType::from(event.event));
                assert_eq!(e.length, event.length);
                assert_eq!(e.zonedid, event.zonedid);
            }
            _ => panic!("unexpected CfwEvType"),
        }
    }

    #[test]
    fn parse_mixed_events() {
        let event = testutils::generate_event();
        let tbytes = event.as_bytes();

        let uevent = testutils::generate_unknown_event();
        let ubytes = uevent.as_bytes();

        let mut mixed = vec![];
        mixed.extend_from_slice(&tbytes);
        mixed.extend_from_slice(&ubytes);
        mixed.extend_from_slice(&ubytes);
        mixed.extend_from_slice(&tbytes);
        mixed.extend_from_slice(&tbytes);

        let mut count = 0;
        let mut traffic_count = 0;
        let mut unknown_count = 0;
        let mut bytes: &[u8] = &mixed;
        loop {
            let (leftover, event) = cfwevent_parse(bytes).expect("failed to parse CfwEvents");
            match *event {
                CfwEvent::Traffic(_) => traffic_count += 1,
                CfwEvent::Unknown(_) => unknown_count += 1,
            };
            bytes = leftover;
            count += 1;
            if bytes.is_empty() {
                break;
            };
        }

        assert_eq!(5, count, "saw exactly 5 events");
        assert_eq!(3, traffic_count, "saw exactly 3 traffic events");
        assert_eq!(2, unknown_count, "saw exactly 2 unknown events");
    }

    #[test]
    #[should_panic]
    fn garbage_data_fails_to_parse() {
        // Try to pass in 100 bytes of random garbage to the parser
        let random_bytes: Vec<u8> = std::iter::repeat_with(|| rand::random::<u8>())
            .take(100)
            .collect();
        let (_leftover, _event) = cfwevent_parse(&random_bytes).unwrap();
    }

    #[test]
    #[should_panic]
    fn not_enough_bytes_fails_to_parse() {
        let mut short = testutils::generate_unknown_event();
        // Today the "sizeof (cfwev_t)" = 88 bytes, so pick something decently bigger
        short.length = 1000;
        let (_leftover, _event) = cfwevent_parse(short.as_bytes()).unwrap();
    }
}
