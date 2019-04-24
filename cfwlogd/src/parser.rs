use std::net::Ipv6Addr;

use chrono::{DateTime, TimeZone, Utc};
use nom::{be_u128, be_u16, le_i64, le_u16, le_u32};
use serde::Serialize;
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

// Peek at the event size
//named!(pub peek_event_size( &[u8] ) -> usize,
//    do_parse!(
//        _event_type: take!(2)>>
//        length: le_u16 >>
//        (length as usize)
//    )
//);

#[derive(Debug, Serialize)]
pub struct EventInfo {
    pub event_type: CfwEvType,
    pub length: u16,
    pub zonedid: u32,
}

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
    pub source_ip: Ipv6Addr,
    pub destination_ip: Ipv6Addr,
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
        time_sec: le_i64 >>
        time_usec: le_i64 >>
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
mod parser_tests {
    use super::*;

    // C representation of a cfw event
    #[repr(C)]
    pub struct cfwev_s {
        pub event: u16,
        pub length: u16,
        pub zonedid: u32,
        pub rule_id: u16,
        pub protocol: u8,
        pub direction: u8,
        pub source_port: u16,
        pub destination_port: u16,
        pub source_ip: u128,
        pub destination_ip: u128,
        pub time_sec: i64,
        pub time_usec: i64,
        pub rule_uuid: [u8; 16],
    }

    /// Create a slice of bytes that represents what `/dev/ipfev` will return to us
    unsafe fn cfwev_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
        ::std::slice::from_raw_parts((p as *const T) as *const u8, ::std::mem::size_of::<T>())
    }

    #[test]
    fn parse_event() {
        let ip_s: u128 = "::ffff:172.24.4.150".parse::<Ipv6Addr>().unwrap().into();
        let ip_d: u128 = "::ffff:172.24.4.151".parse::<Ipv6Addr>().unwrap().into();
        let port_s: u16 = 2222;
        let port_d: u16 = 22;
        let now = chrono::offset::Utc::now();
        // unix timeval only comtains microseconds
        let ts = Utc.timestamp(now.timestamp(), now.timestamp_subsec_micros() * 1000);
        let uuid = Uuid::parse_str("441862be-a3d4-4891-83c0-5022abec182f").unwrap();

        let event = cfwev_s {
            event: 1,
            length: 80,
            zonedid: 16,
            rule_id: 6,
            protocol: 6,
            direction: 1,
            source_port: port_s.to_be(),
            destination_port: port_d.to_be(),
            source_ip: ip_s.to_be(),
            destination_ip: ip_d.to_be(),
            time_sec: ts.timestamp(),
            time_usec: ts.timestamp_subsec_micros() as i64,
            rule_uuid: uuid.as_bytes().clone(),
        };

        let bytes = unsafe { cfwev_as_u8_slice(&event) };
        let cfw_event = traffic_event(bytes);

        // parsed successfully
        assert!(cfw_event.is_ok());
        let cfw_event = cfw_event.unwrap();

        // no leftover bytes after parsing
        let leftover: Vec<u8> = vec![];
        assert_eq!(cfw_event.0, leftover.as_slice());
        match cfw_event.1 {
            CfwEvent::Traffic(e) => {
                assert_eq!(e.event, CfwEvType::from(event.event));
                assert_eq!(e.length, event.length);
                assert_eq!(e.zonedid, event.zonedid);
                assert_eq!(e.rule_id, event.rule_id);
                assert_eq!(e.protocol, Protocol::from(event.protocol));
                assert_eq!(e.direction, Direction::from(event.direction));
                assert_eq!(e.source_port, port_s);
                assert_eq!(e.destination_port, port_d);
                assert_eq!(e.source_ip, Ipv6Addr::from(ip_s));
                assert_eq!(e.destination_ip, Ipv6Addr::from(ip_d));
                assert_eq!(e.timestamp, ts);
                assert_eq!(e.rule_uuid, uuid);
            }
        }
    }
}
