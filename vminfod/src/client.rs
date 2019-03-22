use crate::linefeed::Lines;
use crossbeam_channel::Sender;
use futures::{Future, Stream};
use hyper::{Client as HyperClient, Uri};
use serde::Deserialize;
use tokio::runtime::current_thread::Runtime;

use std::string::FromUtf8Error;

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
    pub zonedid: i32,
}

#[derive(Deserialize, Debug)]
pub struct VminfodEvent {
    #[serde(rename = "type")]
    pub event_type: EventType,
    pub vms: Option<serde_json::Value>,
    pub vm: Option<Zone>,
}

enum Error {
    Hyper(hyper::Error),
    FromUtf8(FromUtf8Error),
}

impl From<FromUtf8Error> for Error {
    fn from(err: FromUtf8Error) -> Error {
        Error::FromUtf8(err)
    }
}

pub(crate) struct Client {
    sender: Sender<VminfodEvent>,
    event_endpoint: Uri,
}

impl Client {
    pub(crate) fn new(sender: Sender<VminfodEvent>) -> Self {
        let url = "http://10.0.1.22:9090/events"
            .parse::<hyper::Uri>()
            .unwrap();

        Client {
            sender,
            event_endpoint: url,
        }
    }

    pub(crate) fn run(&self) {
        let tx = self.sender.clone();
        let client = HyperClient::new();
        let connection = client
            .get(self.event_endpoint.clone())
            .map_err(|e| {
                dbg!(e);
            })
            .and_then(|res| {
                Lines::new(res.into_body().map_err(Error::Hyper))
                    .for_each(move |line| {
                        let event: VminfodEvent = serde_json::from_str(&line).unwrap();
                        tx.send(event).unwrap();
                        Ok(())
                    })
                    .map_err(|_| println!("ignoring for_each error for now"))
            });

        // The vminfod stream is processed by the current thread rather than a pool of threads, as
        // additional futures will not be spawned into the runtime.
        let mut rt = Runtime::new().expect("failed to create vminfod tokio runtime");
        rt.spawn(connection);
        rt.run().expect("failed to run vminfod tokio runtime");
    }
}
