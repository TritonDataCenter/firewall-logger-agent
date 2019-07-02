// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Copyright 2019 Joyent, Inc.

pub mod client;
pub mod linefeed;

use std::thread;

#[macro_use]
extern crate log;

// use fully qualified path (crate::*) here until jenkins is no longer on rust 1.31
use crate::client::Client;
use serde::Deserialize;

#[derive(Deserialize, Debug)]
#[serde(tag = "type")]
pub enum VminfodEvent {
    #[serde(rename = "ready")]
    Ready(ReadyEvent),
    #[serde(rename = "create")]
    Create(CreateEvent),
    #[serde(rename = "modify")]
    Modify(ModifyEvent),
    #[serde(rename = "delete")]
    Delete(DeleteEvent),
}

#[derive(Deserialize, Debug)]
pub struct ReadyEvent {
    pub vms: String,
}

#[derive(Deserialize, Debug)]
pub struct CreateEvent {
    pub vm: Zone,
}

#[derive(Deserialize, Debug)]
pub struct ModifyEvent {
    pub vm: Zone,
    pub changes: Vec<Changes>,
}

#[derive(Deserialize, Debug)]
pub struct DeleteEvent {
    pub zonename: String,
    pub uuid: String,
}

#[derive(Deserialize, Debug)]
pub struct Zone {
    pub uuid: String,
    pub alias: Option<String>,
    pub owner_uuid: String,
    pub firewall_enabled: bool,
    pub zonedid: u32,
}

#[derive(Deserialize, Debug)]
pub struct Changes {
    pub path: Vec<Option<String>>,
}

/// Starts a new thread that runs a tokio executor/runtime responsible for watching a vminfod event
/// stream and sending corresponding events back over the receive half of a channel
pub fn start_vminfod_stream<S: Into<String>>(
    version: S,
) -> (
    crossbeam_channel::Receiver<VminfodEvent>,
    thread::JoinHandle<()>,
) {
    // We allow up to 10 events to be buffered
    const NUM_EVENTS_BUFFERED: usize = 10;

    let version = version.into();
    let (tx, rx) = crossbeam_channel::bounded(NUM_EVENTS_BUFFERED);

    (
        rx,
        thread::Builder::new()
            .name("vminfod_client".to_string())
            .spawn(move || {
                let c = Client::new(version, tx);
                c.run();
            })
            .expect("vminfod client thread spawn failed."),
    )
}
