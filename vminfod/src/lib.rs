pub mod client;
pub mod linefeed;

use std::thread;

#[macro_use]
extern crate log;

use client::Client;
use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub enum EventType {
    #[serde(rename = "ready")]
    Ready,
    #[serde(rename = "create")]
    Create,
    #[serde(rename = "modify")]
    Modify,
    #[serde(rename = "delete")]
    Delete,
}

#[derive(Deserialize, Debug)]
pub struct Zone {
    pub uuid: String,
    pub alias: String,
    pub owner_uuid: String,
    pub firewall_enabled: bool,
    pub zonedid: u32,
}

#[derive(Deserialize, Debug)]
pub struct VminfodEvent {
    #[serde(rename = "type")]
    pub event_type: EventType,
    pub vms: Option<String>,
    pub vm: Option<Zone>,
}

/// Starts a new thread that runs a tokio executor/runtime responsible for watching a vminfod event
/// stream and sending corresponding events back over the receive half of a channel
pub fn start_vminfod_stream() -> (
    crossbeam_channel::Receiver<VminfodEvent>,
    thread::JoinHandle<()>,
) {
    // We allow up to 10 events to be buffered
    const NUM_EVENTS_BUFFERED: usize = 10;

    let (tx, rx) = crossbeam_channel::bounded(NUM_EVENTS_BUFFERED);

    (
        rx,
        thread::Builder::new()
            .name("vminfod_client".to_string())
            .spawn(move || {
                let c = Client::new(tx);
                c.run();
            })
            .expect("vminfod client thread spawn failed."),
    )
}
