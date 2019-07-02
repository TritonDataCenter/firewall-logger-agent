// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Copyright 2019 Joyent, Inc.

use chrono::{TimeZone, Utc};
use rand::{thread_rng, Rng};
use std::net::Ipv6Addr;
use uuid::Uuid;
use vminfod_client::Zone;

// C representation of a cfw event aka cfwev_t.
#[derive(PartialEq, Debug)]
#[repr(C)]
pub struct Event {
    pub event: u16,
    pub length: u16,
    pub zonedid: u32,
    pub rule_id: u32,
    pub source_port: u16,
    pub destination_port: u16,
    pub protocol: u8,
    pub direction: u8,
    pub reserved: [u8; 6],
    pub source_ip: u128,
    pub destination_ip: u128,
    pub time_sec: i64,
    pub time_usec: i64,
    pub rule_uuid: [u8; 16],
}

impl Event {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            ::std::slice::from_raw_parts(
                (self as *const Self) as *const u8,
                ::std::mem::size_of::<Self>(),
            )
        }
    }
}

// C representation of a future event type
#[derive(PartialEq, Debug)]
#[repr(C)]
pub struct UnknownEvent {
    pub event: u16,
    pub length: u16,
    pub zonedid: u32,
    _extra: [u8; 10],
}

impl UnknownEvent {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            ::std::slice::from_raw_parts(
                (self as *const Self) as *const u8,
                ::std::mem::size_of::<Self>(),
            )
        }
    }
}

pub fn generate_unknown_event() -> UnknownEvent {
    UnknownEvent {
        event: 200,
        length: std::mem::size_of::<UnknownEvent>() as u16,
        zonedid: 16,
        _extra: [0; 10],
    }
}

pub fn generate_event() -> Event {
    let mut rng = thread_rng();

    let ip_s: u128 = "::ffff:172.24.4.150".parse::<Ipv6Addr>().unwrap().into();
    let ip_d: u128 = "::ffff:172.24.4.151".parse::<Ipv6Addr>().unwrap().into();
    let port_s: u16 = rng.gen_range(1, 65535);
    let port_d: u16 = rng.gen_range(1, 65535);
    let now = chrono::offset::Utc::now();
    // unix timeval only contains microseconds
    let ts = Utc.timestamp(now.timestamp(), now.timestamp_subsec_micros() * 1000);
    let uuid = Uuid::new_v4();

    Event {
        event: 1,
        length: std::mem::size_of::<Event>() as u16,
        zonedid: 16,
        rule_id: rng.gen_range(0, u32::max_value()),
        source_port: port_s.to_be(),
        destination_port: port_d.to_be(),
        protocol: 6,  // TCP
        direction: 1, // In
        reserved: [0; 6],
        source_ip: ip_s.to_be(),
        destination_ip: ip_d.to_be(),
        time_sec: ts.timestamp(),
        time_usec: i64::from(ts.timestamp_subsec_micros()),
        rule_uuid: *uuid.as_bytes(),
    }
}

pub fn generate_event_for_zone(z: &Zone) -> Event {
    let mut e = generate_event();
    e.zonedid = z.zonedid;
    e
}

pub fn create_zone() -> Zone {
    let mut rng = thread_rng();
    Zone {
        uuid: Uuid::new_v4().to_hyphenated().to_string(),
        alias: Some("zone1".to_owned()),
        owner_uuid: Uuid::new_v4().to_string(),
        firewall_enabled: true,
        zonedid: rng.gen_range(0, u32::max_value()),
    }
}

pub fn generate_zones(n: usize) -> Vec<Zone> {
    std::iter::repeat_with(create_zone).take(n).collect()
}
