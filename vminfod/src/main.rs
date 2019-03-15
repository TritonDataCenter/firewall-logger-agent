pub mod linefeed;

use std::string::FromUtf8Error;

use futures::{Future, Stream};
use hyper::{rt, Client};
use linefeed::Lines;
use serde::Deserialize;

#[derive(Deserialize, Debug)]
enum EventType {
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
struct Zone {
    uuid: String,
    alias: String,
    owner_uuid: String,
    zonedid: i32,
}

#[derive(Deserialize, Debug)]
struct VminfodEvent {
    #[serde(rename = "type")]
    event_type: EventType,
    vms: Option<serde_json::Value>,
    vm: Option<Zone>,
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

fn main() {
    let url = "http://10.0.1.22:9090/events"
        .parse::<hyper::Uri>()
        .unwrap();
    let client = Client::new();

    let connection = client
        .get(url)
        .map_err(|e| {
            dbg!(e);
        })
        .and_then(|res| {
            Lines::new(res.into_body().map_err(Error::Hyper))
                .for_each(|line| {
                    let event: VminfodEvent = serde_json::from_str(&line).unwrap();
                    println!("event: {:#?}", event);
                    Ok(())
                })
                .map_err(|_| println!("ignoring for_each error for now"))
        });

    // Run the runtime with the future trying to fetch and print this URL.
    //
    // Note that in more complicated use cases, the runtime should probably
    // run on its own, and futures should just be spawned into it.
    rt::run(connection);
}
