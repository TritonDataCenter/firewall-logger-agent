// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Copyright 2019 Joyent, Inc.

use crate::linefeed::Lines;
use crate::VminfodEvent;
use crossbeam_channel::Sender;
use futures::{Future, Stream};
use hyper::{Body, Client as HyperClient, Request};
use tokio::runtime::current_thread::Runtime;

use std::string::FromUtf8Error;

#[derive(Debug)]
enum Error {
    Hyper(hyper::Error),
    Serde(serde_json::error::Error),
    FromUtf8(FromUtf8Error),
}

impl From<serde_json::error::Error> for Error {
    fn from(err: serde_json::error::Error) -> Error {
        Error::Serde(err)
    }
}

impl From<FromUtf8Error> for Error {
    fn from(err: FromUtf8Error) -> Error {
        Error::FromUtf8(err)
    }
}

pub(crate) struct Client {
    sender: Sender<VminfodEvent>,
    version: String,
}

impl Client {
    pub(crate) fn new(version: String, sender: Sender<VminfodEvent>) -> Self {
        Client { version, sender }
    }

    pub(crate) fn run(&self) {
        let req = Request::builder()
            .method("GET")
            .header(
                "User-Agent",
                format!(
                    "cfwlogd v{} - VminfodWatcher (firewall-logger-agent)",
                    self.version
                ),
            )
            .uri("http://127.0.0.1:9090/events")
            .body(Body::empty())
            .expect("invalid hyper request params");

        let tx = self.sender.clone();
        let client = HyperClient::new();
        let connection = client
            .request(req)
            .map_err(|e| {
                error!("failed to connect to vminfod: {}", e);
            })
            .and_then(|res| {
                Lines::new(res.into_body().map_err(Error::Hyper))
                    .for_each(move |line| {
                        let event: VminfodEvent = serde_json::from_str(&line)?;
                        tx.send(event)
                            .expect("vminfod receiving channel should always be listening");
                        Ok(())
                    })
                    .map_err(|e| error!("vminfod event stream closed: {:#?}", e))
            });

        // The vminfod stream is processed by the current thread rather than a pool of threads
        let mut rt = Runtime::new().expect("failed to create vminfod tokio runtime");
        rt.spawn(connection);
        rt.run().expect("failed to run vminfod tokio runtime");
    }
}
