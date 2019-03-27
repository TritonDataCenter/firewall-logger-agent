use std::net::IpAddr;

use chrono::{TimeZone, Utc};
use nom::{be_u128, be_u16, le_u16, le_u32, le_u64};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
pub struct EventInfo {
    pub event_type: CfwEvType,
    pub length: u16,
    pub zonedid: u32,
}

// Parse an entire event
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

#[derive(Debug, Serialize, Deserialize)]
pub enum CfwEvent {
    Traffic(TrafficEvent),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrafficEvent {
    pub cfwev_type: CfwEvType,
    pub cfwev_length: u16,
    pub cfwev_zonedid: u32,
    pub cfwev_ruleid: u16,
    pub cfwev_protocol: Protocol,
    pub cfwev_direction: Direction,
    pub cfwev_sport: u16,
    pub cfwev_dport: u16,
    pub cfwev_saddr: IpAddr,
    pub cfwev_daddr: IpAddr,
    pub cfwev_tstamp: String,
    pub cfwev_ruleuuid: Uuid,
}

// Parse an entire event
named!(pub traffic_event( &[u8] ) -> CfwEvent,
    do_parse!(
        cfwev_type: le_u16 >>
        cfwev_length: le_u16 >>
        cfwev_zonedid: le_u32 >>
        cfwev_ruleid: le_u16 >>
        cfwev_protocol: take!(1) >>
        cfwev_direction: take!(1) >>
        cfwev_sport: be_u16 >>
        cfwev_dport: be_u16 >>
        cfwev_saddr: be_u128 >>
        cfwev_daddr: be_u128 >>
        cfwev_time_sec: le_u64 >>
        cfwev_time_usec: le_u64 >>
        cfwev_ruleuuid: take!(16) >>
        (
            CfwEvent::Traffic(TrafficEvent{
                cfwev_type: CfwEvType::from(cfwev_type),
                cfwev_length,
                cfwev_zonedid,
                cfwev_ruleid,
                cfwev_protocol: Protocol::from(cfwev_protocol[0]),
                cfwev_direction: Direction::from(cfwev_direction[0]),
                cfwev_sport,
                cfwev_dport,
                cfwev_saddr: IpAddr::from(cfwev_saddr.to_be_bytes()),
                cfwev_daddr: IpAddr::from(cfwev_daddr.to_be_bytes()),
                cfwev_tstamp: Utc.timestamp(cfwev_time_sec as i64, cfwev_time_usec as u32).to_string(),
                cfwev_ruleuuid: Uuid::from_slice(cfwev_ruleuuid)
                    .expect("we should have 16 bytes exactly"),
            })
        )
    )
);
