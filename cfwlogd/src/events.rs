// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Copyright 2019 Joyent, Inc.

//! Event processing pipeline implementation that is responsible for reading from an `EventSource`
//! and parsing the returned events and passing them off to a `Logger`
//!
//!
//!                        +---------------+        +--------------+ -----> zone1 Logger
//!  +---------------+     | device reader |        | event fanout | -----> zone2 Logger
//!  |  EventSource  |---> |    thread     |------->|    thread    | -----> zone3 Logger
//!  +---------------+     +---------------+        +--------------+ -----> zone4 Logger
//!
//! The pipeline consists of a main device reading thread that sits in a tight loop.  This thread
//! will read as many events as it can up to an upper bound via read(2) from the passed in
//! `EventSource` such as "/dev/ipfev". This thread will parse the raw bytes into `CfwEvent`s and
//! send them to the event fanout thread over a channel. This channel is bounded to some capacity
//! based on the `EventSources`'s returned sizing but also features an upper and lower bound. This
//! is to prevent endless memory growth if the userland daemon cannot keep up with its
//! `EventSource`. Once the event fanout thread receives a parsed event it will attempt to wait a
//! small amount of time in hopes of coalescing multiple events coming down the channel. After
//! waiting the fanout thread will loop over each of the received events and attempt to send off
//! the event to the appropriate `Logger` if one exists.  If the `Logger` does not exist it will
//! spawn a new `Logger` thread for the zone and proceed to send it the `Logger` via an unbounded
//! channel. These channels are unbounded because writing to disk is almost always slower than the
//! `EventSource` producing events. The `Logger` then takes care of serializing the event into json
//! and writing it out to the appropriate log file.
//!

use crate::logger::{self, Logger};
use crate::parser::{self, CfwEvent};
use crate::zones::{Vmobjs, Zonedid};
use crossbeam::channel::{self, Receiver, Select, Sender, TrySendError};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;

const RING_CAPACITY_MULTIPLIER: usize = 512;

/// Holds a Mutex protected mapping of zonedid to Logging thread
pub type Loggers = Arc<Mutex<HashMap<Zonedid, Logger>>>;

/// Trait that represents a Firewall Event Source
pub trait EventSource: Send {
    /// Reads n events into the given buffer, returning how many bytes were read.
    fn read_events(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;
    /// Returns a tuple that tells you the largest event size, and the max number of events that
    /// may be returned in a single read.
    fn event_sizing(&mut self) -> std::io::Result<(usize, usize)>;
}

/// Clamp the ringsize so that it falls somewhere between the min and max values.
fn clamp_ring_size(min: usize, max: usize, value: usize) -> usize {
    if value > max {
        max
    } else if value < min {
        min
    } else {
        value
    }
}

/// Start a thread that consumes events from an `EventSource`.
/// The consumed events will be sent to the returned `Receiver`.
pub fn start_event_reader<T: EventSource + 'static>(
    mut device: T,
) -> (Receiver<Box<CfwEvent>>, thread::JoinHandle<()>) {
    let (max, ringsize) = device.event_sizing().unwrap_or_else(|e| {
        error!("failed to get ring size from device: {}", e);
        std::process::exit(e.raw_os_error().unwrap_or(-1));
    });
    debug!(
        "device responded with max event size: {}, ring size: {}",
        &max, &ringsize
    );
    // This value is kind of picked out of thin air based on initial testing during development.
    // It's quite possible this will need to be tuned at some point in the future. We could make
    // the channel unbounded at the cost of some performance, but it's probably a good idea to have
    // some sort of backpressure control here so we don't endlessly grow in memory. Testing also
    // showed that selecting a small ringsize provides the potential for cfwlogd to drop events
    // so we set the ringsize lower bound to 1024. We also set an upper bound to 2048 so that we
    // don't needlessly allocate a large chunk of memory at startup.
    let rs = clamp_ring_size(1024, 2048, ringsize);
    debug!(
        "sizing the channel capacity to {} * {}",
        rs, RING_CAPACITY_MULTIPLIER
    );
    let capacity = RING_CAPACITY_MULTIPLIER * rs;
    let (tx, rx) = channel::bounded(capacity);
    (
        rx,
        thread::Builder::new()
            .name("EventReader".to_owned())
            .spawn(move || {
                // a buffer that can hold a full read of the ringbuffer
                let mut buf = vec![0; max * ringsize];

                loop {
                    let size = match device.read_events(&mut buf) {
                        Ok(size) => size,
                        Err(e) => {
                            match e.kind() {
                                std::io::ErrorKind::Interrupted => continue,
                                _ => {
                                    // We failed to read from the EventSource so let's log the
                                    // error and drop our `Sender` so that we can shutdown
                                    // gracefully"
                                    error!("failed to read from the EventSource: {:?}", e);
                                    break;
                                }
                            }
                        }
                    };

                    if parse_events(&buf[..size], &tx) {
                        // The recv channel is closed so we can stop reading events
                        break;
                    }
                }
            })
            .expect("failed to start event reader thread"),
    )
}

/// Takes a buffer of bytes and slices them up into `CfwEvent`s that are then sent to the provided
/// `Sender`.
fn parse_events(bytes: &[u8], sender: &Sender<Box<CfwEvent>>) -> bool {
    let mut bytes = bytes;
    loop {
        // Leaving this as an expect call because if we ever get out of sync or the device returns
        // us not enough data we will be in a very bad place in terms of figuring out how to
        // continue so it's best we just crash.
        let (leftover, event) = parser::cfwevent_parse(&bytes).expect("event parsing failed");
        if let Err(e) = sender.try_send(event) {
            match e {
                // Unfortunately we have to drop an event
                // CMON TRITON-1755
                TrySendError::Full(dropped_event) => warn!(
                    "processing channel is full ({} queued) so we are dropping an event for \\
                     zonedid: {}",
                    sender.len(),
                    dropped_event.zone()
                ),
                // We are in the process of shutting down
                TrySendError::Disconnected(_) => {
                    info!("the event processing channel has disconnected");
                    return true;
                }
            }
        }
        bytes = leftover;
        if bytes.is_empty() {
            break;
        };
    }
    false
}

/// Starts a thread that will receive `CfwEvent`s and fan them out to per zone logging threads.
pub fn start_event_fanout(
    events: Receiver<Box<CfwEvent>>,
    shutdown: Receiver<()>,
    vmobjs: Vmobjs,
) -> (Loggers, thread::JoinHandle<()>) {
    let loggers: Loggers = Arc::new(Mutex::new(HashMap::new()));
    let loggers2 = Arc::clone(&loggers);
    (
        loggers,
        thread::Builder::new()
            .name("EventFanout".to_owned())
            .spawn(move || fanout_events(events, shutdown, vmobjs, loggers2))
            .expect("failed to start event fanout thread"),
    )
}

/// Fanout events coming from the Receiver into the appropriate Logger, creating a new Logger if
/// one does not yet exist.
fn fanout_events(
    events: Receiver<Box<CfwEvent>>,
    shutdown: Receiver<()>,
    vmobjs: Vmobjs,
    mut loggers: Loggers,
) {
    let mut sel = Select::new();
    let events_ready = sel.recv(&events);
    let shutdown_ready = sel.recv(&shutdown);

    loop {
        match sel.ready() {
            // This should never be a Disconnected message because the thread holding the tx end of
            // the channel will never close it. There's also no way to currently check if the
            // channel is disconnected given the current API.
            i if i == events_ready => {
                thread::sleep(std::time::Duration::from_nanos(500_000));
                queue_zone_events(
                    events.try_iter().take(1024).collect(),
                    &vmobjs,
                    &mut loggers,
                )
            }
            i if i == shutdown_ready => {
                shutdown
                    .recv()
                    .expect("the signal rx should never outlive the tx");
                debug!("event fanout thread received shutdown signal");
                break;
            }
            _ => unreachable!(),
        }
    }

    // Attempt to grab all of the events that are currently in the queue so we can
    // shutdown the receiver as quickly as possible. We use "take()" here so that we
    // don't end up in a situation where this processing thread is being blasted with
    // incoming events and we can't disconnect in a timely manner.
    drop(sel);
    let drain: Vec<_> = events.try_iter().take(events.len()).collect();
    drop(events);
    debug!(
        "event processing thread drained {} remaining events before shutdown",
        drain.len()
    );
    queue_zone_events(drain, &vmobjs, &mut loggers);

    info!("event processing thread exiting");
}

/// For a given cfw event, find or create a `Logger` thats responsible for serializing the event to
/// disk.
#[allow(clippy::vec_box)] // The bounded channel operates on Box<CfwEvent> already.
fn queue_zone_events(events: Vec<Box<CfwEvent>>, vmobjs: &Vmobjs, loggers: &mut Loggers) {
    let mut loggers = loggers.lock().unwrap();
    for event in events {
        if let CfwEvent::Unknown(_) = *event {
            continue;
        };
        let zonedid = event.zone();
        let logger = match loggers.entry(zonedid) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => match logger::start_logger(zonedid, Arc::clone(&vmobjs)) {
                Some(logger) => {
                    info!("new logging thread started for zonedid {}", zonedid);
                    entry.insert(logger)
                }
                None => {
                    // CMON TRITON-1755
                    error!(
                        "unable to match zonedid {} to vm object; dropping event",
                        zonedid
                    );
                    continue;
                }
            },
        };
        if let Err(e) = logger.try_send(event) {
            match e {
                TrySendError::Disconnected(_) => {
                    warn!(
                        "failed to log event for zone {} (logger channel disconnected)",
                        zonedid
                    );
                    loggers.remove(&zonedid);
                }
                TrySendError::Full(_) => {
                    // CMON TRITON-1755
                    warn!(
                        "failed to log event for zone {} (logger channel is full)",
                        zonedid
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossbeam::sync::ShardedLock;
    use std::time::Duration;

    struct MockEventSource {}

    impl EventSource for MockEventSource {
        fn read_events(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let event = testutils::generate_event();
            let bytes = event.as_bytes();
            assert!(
                buf.len() >= bytes.len(),
                "the provided buffer must be able to hold at least one event"
            );
            buf[..bytes.len()].copy_from_slice(bytes);
            Ok(bytes.len())
        }
        fn event_sizing(&mut self) -> std::io::Result<(usize, usize)> {
            Ok((testutils::generate_event().as_bytes().len(), 1))
        }
    }

    #[test]
    fn parse_events_test() {
        let num_events = 10;
        let (tx, rx) = crossbeam::channel::unbounded();
        let event = testutils::generate_event();

        let mut bytes = vec![];
        std::iter::repeat(event.as_bytes())
            .take(num_events)
            .for_each(|b| bytes.extend_from_slice(b));

        let done = parse_events(&bytes, &tx);

        // Parse_events returns false because the channel is still open
        assert!(!done);
        // There should be num_events in the rx half of the channel
        assert_eq!(
            rx.len(),
            num_events,
            "the rx channel contains the same number of events passed in"
        );

        // drop the sender so we can easily iterate over all the events in the channel
        drop(tx);
        let cfwevent = parser::cfwevent_parse(event.as_bytes()).unwrap().1;
        for e in rx.iter() {
            assert_eq!(cfwevent, e, "all events match the passed in events");
        }
    }

    #[test]
    fn start_event_reader_test() {
        let device = MockEventSource {};
        let (events, _handle) = start_event_reader(device);
        let event = events.recv_timeout(Duration::from_secs(1));
        assert!(
            event.is_ok(),
            "at least one event has made it through the returned rx channel"
        );
    }

    #[test]
    fn queue_zone_events_test() {
        let mut loggers: Loggers = Arc::new(Mutex::new(HashMap::new()));
        let vmobjs: Vmobjs = Arc::new(ShardedLock::new(HashMap::new()));

        // Test that we don't create a logger for a zone we don't know about
        let event = testutils::generate_event();
        let cfwevent = parser::cfwevent_parse(event.as_bytes()).unwrap().1;
        queue_zone_events(vec![cfwevent], &vmobjs, &mut loggers);

        let logs = loggers.lock().unwrap();
        assert!(logs.is_empty(), "there were no loggers created");
        drop(logs);

        // Make a fake zone for our test
        let zone1 = testutils::create_zone();
        let event = testutils::generate_event_for_zone(&zone1);
        let customer_uuid = zone1.owner_uuid.clone();

        let mut vms = vmobjs.write().unwrap();
        vms.insert(zone1.zonedid, zone1);
        drop(vms);

        // Test that we create a logger for a zone found in vmobjs
        let cfwevent = parser::cfwevent_parse(event.as_bytes()).unwrap().1;
        queue_zone_events(vec![cfwevent], &vmobjs, &mut loggers);
        let mut logs = loggers.lock().unwrap();
        assert_eq!(logs.len(), 1, "there is exactly one logger created");
        for (zonedid, logger) in logs.drain() {
            assert_eq!(zonedid, event.zonedid, "zonedid's match");
            // Shutdown the logger so the file flushes
            logger.shutdown().expect("failed to shutdown logger");
        }
        drop(logs);

        // make sure that the directory for the logs appeared and clean it up
        assert_eq!(
            true,
            std::fs::remove_dir_all(format!("{}/{}", crate::logger::LOG_DIR, customer_uuid))
                .is_ok(),
            "successfully cleaned up test files"
        );
    }

    #[test]
    fn start_event_fanout_test() {
        let vmobjs: Vmobjs = Arc::new(ShardedLock::new(HashMap::new()));

        let zone1 = testutils::create_zone();
        let event = testutils::generate_event_for_zone(&zone1);
        let customer_uuid = zone1.owner_uuid.clone();

        let mut vms = vmobjs.write().unwrap();
        vms.insert(zone1.zonedid, zone1);
        drop(vms);

        let cfwevent = parser::cfwevent_parse(event.as_bytes()).unwrap().1;

        let (tx, rx) = crossbeam::channel::unbounded();
        let (stx, srx) = crossbeam::channel::unbounded();
        let (loggers, handle) = start_event_fanout(rx, srx, Arc::clone(&vmobjs));

        let logs = loggers.lock().unwrap();
        assert!(logs.is_empty(), "no loggers exist yet");
        drop(logs);

        assert!(
            tx.send(cfwevent).is_ok(),
            "successfully sent CfwEvent to fanout thread"
        );

        assert!(stx.send(()).is_ok(), "shutdown signal sent");
        // should be plenty of time for the thread to shutdown
        thread::sleep(Duration::from_millis(500));
        let cfwevent = parser::cfwevent_parse(event.as_bytes()).unwrap().1;
        assert!(
            tx.send(cfwevent).is_err(),
            "thread should no longer be accepting CfwEvents"
        );
        // XXX not sure how to deal with this potentially hanging forever other than setting a
        // timeout in a test runner like jenkins. Although if we made it this far in the test then
        // it's looking like the thread has already actually shutdown.
        assert!(handle.join().is_ok(), "thread shutdown");

        // make sure that the directory for the logs appeared and clean it up
        assert_eq!(
            true,
            std::fs::remove_dir_all(format!("{}/{}", crate::logger::LOG_DIR, customer_uuid))
                .is_ok(),
            "successfully cleaned up test files"
        );
    }
}
