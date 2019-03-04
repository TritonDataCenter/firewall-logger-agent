// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Copyright 2019 Joyent, Inc.

use crate::parser::CfwEvent;
use crate::zones::{Vmobjs, Zonedid};
use crossbeam::channel::{self, Select, SendError};
use failure::Error;
use serde::Serialize;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

/// Configure where log files will be created
#[cfg(not(test))]
const LOG_DIR: &str = "/var/log/firewall";
#[cfg(test)]
const LOG_DIR: &str = "/var/tmp/cfwlogd-tests";

/// Capacity used for Logger's BufWriter.  This may need to be tuned later.
const BUF_SIZE: usize = 1024 * 1024;

#[derive(Debug, Serialize)]
struct LogEvent<'a> {
    #[serde(flatten)]
    event: CfwEvent,
    vm: &'a str,
    alias: &'a str,
}

/// A signal that can be sent to the logger
#[derive(PartialEq)]
pub enum LoggerSignal {
    /// Tell the thread to flush and continue
    Flush,
    /// Tell the thread to flush and shutdown
    Shutdown,
    /// Tell the thread to flush and rotate the log file
    Rotate,
}

/// A Logger represents a thread tied to a specific zone that is responsible for logging out
/// CfwEvents to disk.
pub struct Logger {
    /// Zone UUID
    pub uuid: String,
    /// Threads handle
    handle: thread::JoinHandle<()>,
    /// Send half of a channel that's used to get CfwEvents into the Logger
    sender: channel::Sender<CfwEvent>,
    /// Send half of a channel that's used to signal the Logger to preform specific actions
    signal: channel::Sender<LoggerSignal>,
}

impl Logger {
    /// Send an event to the logger to be logged out to disk
    pub fn send(&self, e: CfwEvent) -> Result<(), SendError<CfwEvent>> {
        self.sender.send(e)
    }

    /// Flushes the loggers internal `BufWriter` to disk
    pub fn flush(&self) -> Result<(), SendError<LoggerSignal>> {
        self.signal.send(LoggerSignal::Flush)
    }

    /// Flushes the loggers internal `BufWriter` to disk, and reopens "current.log"
    pub fn rotate(&self) -> Result<(), SendError<LoggerSignal>> {
        self.signal.send(LoggerSignal::Rotate)
    }

    /// Flushes the loggers internal `BufWriter` to disk, and shutdowns the `Logger`, therefore
    /// requiring ownership of self to be consumed.
    pub fn shutdown(self) -> Result<(), SendError<LoggerSignal>> {
        self.signal.send(LoggerSignal::Shutdown).and_then(|_| {
            self.handle.join().unwrap();
            Ok(())
        })
    }
}

/// Open "current.log" in "RW" for the given customer and zone.
fn open_file(vm: &str, customer: &str) -> std::io::Result<File> {
    let path: PathBuf = [LOG_DIR, customer, vm, "current.log"].iter().collect();
    // we know the unwrap is safe because we just created the path above
    std::fs::create_dir_all(path.parent().unwrap())?;
    Ok(OpenOptions::new().append(true).create(true).open(path)?)
}

/// Given a collection of `CfwEvent`, serialize them out to disk as JSON formatted logs.
fn log_events<W: Write>(
    events: Vec<CfwEvent>,
    mut writer: W,
    vmobjs: &Vmobjs,
) -> Result<(), Error> {
    // force the event type for now
    let vmobjs = vmobjs.read().unwrap();
    for event in events {
        let vmobj = vmobjs
            .get(&event.zone())
            .expect("we should have the zonedid:uuid mapping already");
        // Check if the zone has an alias set, if not we provide a default one
        // Note instead of String::as_ref we could also use "|s| &**s"
        let alias = vmobj.alias.as_ref().map_or("", String::as_ref);
        let event = LogEvent {
            event,
            vm: &vmobj.uuid,
            alias: &alias,
        };
        // TODO these errors no longer make sense when its multiple events being processed
        serde_json::to_writer(&mut writer, &event)?;
        writer.write_all(b"\n")?;
    }
    Ok(())
}

fn _start_logger(
    vm: String,
    customer: String,
    vmobjs: Vmobjs,
    events: channel::Receiver<CfwEvent>,
    signal: channel::Receiver<LoggerSignal>,
) -> thread::JoinHandle<()> {
    thread::Builder::new()
        .name("logger".to_owned())
        .spawn(move || {
            let file = match open_file(&vm, &customer) {
                Ok(file) => file,
                Err(e) => {
                    // XXX CMON?
                    error!("failed to open log file: {}", e);
                    return;
                }
            };

            let mut writer = BufWriter::with_capacity(BUF_SIZE, file);
            let mut sel = Select::new();
            let events_ready = sel.recv(&events);
            let signal_ready = sel.recv(&signal);
            loop {
                match sel.ready() {
                    i if i == events_ready => {
                        thread::sleep(std::time::Duration::from_nanos(500_000));
                        if let Err(e) =
                            log_events(events.try_iter().take(1024).collect(), &mut writer, &vmobjs)
                        {
                            error!("failed to log event(s): {}", e);
                        }
                    }
                    i if i == signal_ready => {
                        // TODO handle disconnected channel
                        if let Ok(signal) = signal.recv() {
                            match signal {
                                LoggerSignal::Rotate => {
                                    let _ = writer.flush();
                                    let file = match open_file(&vm, &customer) {
                                        Ok(file) => file,
                                        Err(e) => {
                                            // XXX CMON?
                                            error!("failed to open log file after rotation: {}", e);
                                            return;
                                        }
                                    };
                                    // drop the old writer and create a new one
                                    writer = BufWriter::with_capacity(1024 * 1024, file);
                                }
                                LoggerSignal::Shutdown => break,
                                LoggerSignal::Flush => {
                                    // XXX handle error
                                    info!("flushing log for {}", &vm);
                                    let _ = writer.flush();
                                }
                            }
                        }
                    }
                    _ => unreachable!(),
                }
            }

            // We are shutting down now so we drain the channel and then drop it
            if let Err(e) = log_events(events.try_iter().collect(), &mut writer, &vmobjs) {
                error!("failed to log event: {}", e);
            }
            drop(sel);
            drop(events);
            let _res = writer.flush();
        })
        .expect("failed to spawn IpfReader thread")
}

/// Return a Logger if we have information for the zone already otherwise return None
pub fn start_logger(zonedid: Zonedid, vmobjs: Vmobjs) -> Option<Logger> {
    let (event_tx, event_rx) = channel::unbounded();
    let (signal_tx, signal_rx) = channel::bounded(1);
    let vms = vmobjs.read().unwrap();
    if let Some(vm) = vms.get(&zonedid) {
        let handle = _start_logger(
            vm.uuid.clone(),
            vm.owner_uuid.clone(),
            Arc::clone(&vmobjs),
            event_rx,
            signal_rx,
        );
        return Some(Logger {
            uuid: vm.uuid.clone(),
            handle,
            sender: event_tx,
            signal: signal_tx,
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser;
    use crate::zones::Vmobjs;
    use crossbeam::sync::ShardedLock;
    use std::collections::HashMap;
    use std::io::Read;
    use std::path::PathBuf;

    #[test]
    fn open_file_test() {
        let vm = "zone1";
        let customer = "customer1";
        let _f = open_file(vm, customer).expect("failed to open file");
        let mut path: PathBuf = [LOG_DIR, customer, vm, "current.log"].iter().collect();
        assert!(path.as_path().is_file(), "current.log file path is correct");
        path.pop(); //current.log
        path.pop(); // zone name
        std::fs::remove_dir_all(path).expect("failed to cleanup log dir");
    }

    #[test]
    fn log_events_test() {
        let num_events = 4;
        let vmobjs: Vmobjs = Arc::new(ShardedLock::new(HashMap::new()));

        let zone1 = testutils::create_zone();

        let events = std::iter::repeat_with(|| {
            let event = testutils::generate_event_for_zone(&zone1);
            parser::traffic_event(event.as_bytes()).unwrap().1
        })
        .take(num_events)
        .collect();

        let mut vms = vmobjs.write().unwrap();
        vms.insert(zone1.zonedid, zone1);
        drop(vms);

        let mut writer = vec![];
        assert!(
            log_events(events, &mut writer, &vmobjs).is_ok(),
            "logs written to writer"
        );

        let mut buf = String::new();
        writer
            .as_slice()
            .read_to_string(&mut buf)
            .expect("failed to read all of the bytes from the writer");

        let lines: Vec<&str> = buf.lines().collect();

        assert_eq!(
            num_events,
            lines.len(),
            "all events were written to the writer"
        );
    }

    #[test]
    fn start_logger_test() {
        let vmobjs: Vmobjs = Arc::new(ShardedLock::new(HashMap::new()));
        let logger = start_logger(10, Arc::clone(&vmobjs));
        assert!(
            logger.is_none(),
            "no logger is created for an unknown zonedid",
        );

        let zone1 = testutils::create_zone();
        let zonedid = zone1.zonedid;
        let mut vms = vmobjs.write().unwrap();
        vms.insert(zone1.zonedid, zone1);
        drop(vms);

        let logger = start_logger(zonedid, Arc::clone(&vmobjs));
        assert!(
            logger.is_some(),
            "logger is created when we have the correct zone info",
        );
    }
}
