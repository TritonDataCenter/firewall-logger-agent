use std::net::IpAddr;

use chrono::{DateTime, TimeZone, Utc};
use nom::{be_u128, be_u16, le_u16, le_u32, le_u64};
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Serialize)]
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

#[derive(Debug, Serialize)]
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

#[derive(Debug, Serialize)]
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

#[derive(Debug, Serialize)]
pub struct EventInfo {
    pub event_type: CfwEvType,
    pub length: u16,
    pub zonedid: u32,
}

/// Peek at the event size
named!(pub peek_event_size( &[u8] ) -> usize,
    do_parse!(
        _event_type: take!(2)>>
        length: le_u16 >>
        (length as usize)
    )
);

/// Peek at the first 8 byes aka the EventInfo
named!(pub peek_event( &[u8] ) -> EventInfo,
    do_parse!(
        event_type: le_u16 >>
        length: le_u16 >>
        zonedid: le_u32 >>
        (
            EventInfo{
                event_type: CfwEvType::from(event_type),
                length,
                zonedid,
            }
        )
    )
);

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum CfwEvent {
    Traffic(TrafficEvent),
}

impl CfwEvent {
    pub fn len(&self) -> usize {
        match &*self {
            CfwEvent::Traffic(event) => event.length as usize,
        }
    }

    pub fn zone(&self) -> u32 {
        match &*self {
            CfwEvent::Traffic(event) => event.zonedid,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct TrafficEvent {
    pub event: CfwEvType,
    #[serde(skip)]
    pub length: u16,
    #[serde(skip)]
    pub zonedid: u32,
    #[serde(skip)]
    pub rule_id: u16,
    pub protocol: Protocol,
    pub direction: Direction,
    pub source_port: u16,
    pub destination_port: u16,
    pub source_ip: IpAddr,
    pub destination_ip: IpAddr,
    pub timestamp: DateTime<Utc>,
    #[serde(rename = "rule")]
    pub rule_uuid: Uuid,
}

// Parse an entire event
named!(pub traffic_event( &[u8] ) -> CfwEvent,
    do_parse!(
        event: le_u16 >>
        length: le_u16 >>
        zonedid: le_u32 >>
        rule_id: le_u16 >>
        protocol: take!(1) >>
        direction: take!(1) >>
        source_port: be_u16 >>
        destination_port: be_u16 >>
        source_ip: be_u128 >>
        destination_ip: be_u128 >>
        time_sec: le_u64 >>
        time_usec: le_u64 >>
        rule_uuid: take!(16) >>
        (
            CfwEvent::Traffic(TrafficEvent{
                event: CfwEvType::from(event),
                length,
                zonedid,
                rule_id,
                protocol: Protocol::from(protocol[0]),
                direction: Direction::from(direction[0]),
                source_port,
                destination_port,
                source_ip: IpAddr::from(source_ip.to_be_bytes()),
                destination_ip: IpAddr::from(destination_ip.to_be_bytes()),
                timestamp: Utc.timestamp(time_sec as i64, time_usec as u32),
                rule_uuid: Uuid::from_slice(rule_uuid)
                    .expect("we should have 16 bytes exactly"),
            })
        )
    )
);
