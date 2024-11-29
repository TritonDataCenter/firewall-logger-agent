// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Copyright 2019 Joyent, Inc.

//! A Logger is a thread that is responsible for receiving CfwEvents and logging them out to the
//! appropriate directory in the current.log file. A Logger can also be told to perform a variety
//! of tasks such as flushing its internal buffer to disk, flushing its buffer to disk and
//! reopening current.log, or to simply flush its buffer to disk and shutdown.
//!

use crate::parser::CfwEvent;
use crate::zones::{Vmobjs, Zonedid};
use crossbeam::channel::{self, Select, SendError, TrySendError};
use serde::Serialize;
use std::boxed::Box;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

/// Configure where log files will be created
/// We are now chrooting into "/var/log/firewall" so the base dir should just be "/"
#[cfg(not(test))]
pub const LOG_DIR: &str = "/";
#[cfg(test)]
pub const LOG_DIR: &str = "/var/tmp/cfwlogd-tests";

/// Capacity used for Logger's BufWriter.  This may need to be tuned later.
const BUF_SIZE: usize = 1024 * 1024;

#[derive(Debug, Serialize)]
struct LogEvent<'a> {
    #[serde(flatten)]
    event: &'a CfwEvent,
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

/// A Logger represents a thread tied to a specific zone that is responsible persisting CfwEvents
/// to disk as newline separated json.
pub struct Logger {
    /// Zone UUID
    pub uuid: String,
    /// Threads handle
    handle: thread::JoinHandle<()>,
    /// Send half of a channel that's used to get CfwEvents into the Logger
    sender: channel::Sender<Box<CfwEvent>>,
    /// Send half of a channel that's used to signal the Logger to perform specific actions
    signal: channel::Sender<LoggerSignal>,
}

impl Logger {
    /// Send an event to the logger to be logged out to disk
    pub fn try_send(&self, e: Box<CfwEvent>) -> Result<(), TrySendError<Box<CfwEvent>>> {
        self.sender.try_send(e)
    }

    /// Flushes the logger's internal `BufWriter` to disk
    pub fn flush(&self) -> Result<(), SendError<LoggerSignal>> {
        self.signal.send(LoggerSignal::Flush)
    }

    /// Flushes the logger's internal `BufWriter` to disk, and reopens "current.log"
    pub fn rotate(&self) -> Result<(), SendError<LoggerSignal>> {
        self.signal.send(LoggerSignal::Rotate)
    }

    /// Flushes the logger's internal `BufWriter` to disk, and shutdowns the `Logger`, therefore
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
#[allow(clippy::vec_box)] // The bounded channel operates on Box<CfwEvent> already.
fn log_events<W: Write>(events: Vec<Box<CfwEvent>>, mut writer: W, vmobjs: &Vmobjs) {
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
            event: &event,
            vm: &vmobj.uuid,
            alias: &alias,
        };
        // We decided that the only reason we would fail to write here would be due to something
        // like ENOSPC/EDQUOT in which case none of the loggers are likely to make any forward
        // progress so we will force unwrap the results and abort if we hit this scenario.
        serde_json::to_writer(&mut writer, &event).expect("failed to CfwEvent to the BufWriter");
        writer
            .write_all(b"\n")
            .expect("failed to write newline to the BufWriter");
    }
}

// Process a signal sent to the Logger, and return true if the Logger was told to shutdown
fn logger_handle_signal(
    vm: &str,
    customer: &str,
    signal: LoggerSignal,
    writer: &mut BufWriter<File>,
) -> bool {
    match signal {
        LoggerSignal::Rotate => {
            let _ = writer.flush();
            let file = match open_file(vm, customer) {
                Ok(file) => file,
                Err(e) => {
                    // CMON TRITON-1755
                    error!("failed to open {}'s log file after rotation: {}", &vm, e);
                    return true;
                }
            };
            // Drop the old writer and create a new one
            *writer = BufWriter::with_capacity(1024 * 1024, file);
        }
        LoggerSignal::Shutdown => return true,
        LoggerSignal::Flush => {
            info!("flushing log for {}", vm);
            // If flushing fails, we are once again most likely hitting something like ENOSPC,
            // which means we should just abort to let the operator know we are in a bad place.
            writer
                .flush()
                .unwrap_or_else(|_| panic!("failed to flush log for {}", vm));
        }
    }
    false
}

/// Start the actual logging thread that receives events or signals on channels and loops forever
/// until it is told to no longer do so.
fn _start_logger(
    vm: String,
    customer: String,
    vmobjs: Vmobjs,
    events: channel::Receiver<Box<CfwEvent>>,
    signal: channel::Receiver<LoggerSignal>,
) -> thread::JoinHandle<()> {
    thread::Builder::new()
        .name(vm.clone())
        .spawn(move || {
            let file = match open_file(&vm, &customer) {
                Ok(file) => file,
                Err(e) => {
                    // CMON TRITON-1755
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
                        // Wait a small amount of time in hopes of coalescing events coming down
                        // the channel, which helps reduce the number of calls to yield(2) and
                        // reduces lock contention on the vmobjs rw lock.
                        thread::sleep(std::time::Duration::from_nanos(500_000));
                        log_events(events.try_iter().take(1024).collect(), &mut writer, &vmobjs)
                    }
                    i if i == signal_ready => match signal.recv() {
                        Ok(signal) => {
                            if logger_handle_signal(&vm, &customer, signal, &mut writer) {
                                break;
                            }
                        }
                        Err(_) => {
                            warn!(
                                "{}'s signal channel was disconnected which means the \\
                                 Logger itself was dropped so we can safely shutdown as well",
                                &vm
                            );
                        }
                    },
                    _ => unreachable!(),
                }
            }

            // We are shutting down now so we drain the channel and then drop it
            log_events(events.try_iter().collect(), &mut writer, &vmobjs);
            drop(sel);
            drop(events);
            let _res = writer.flush();
        })
        .expect("failed to spawn Logger thread")
}

/// Return a Logger if we have information for the zone already otherwise return None
pub fn start_logger(zonedid: Zonedid, vmobjs: Vmobjs) -> Option<Logger> {
    // We bound the loggers incoming queue so that we don't endlessly consume memory, since the
    // event reading thread is able to geenrate events faster than we can serialize to JSON and
    // write to disk.  This means each thread can consume somewhere around:
    // (channel-capacity * sizeof (CfwEvent)) + (channel-capacity * sizeof (CfwEvent *))
    // In addition to other things such as the BufWriter buffer size and umem PTC which is enabled
    // in the SMF manifest.
    let (event_tx, event_rx) = channel::bounded(500_000);
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
        path.pop(); // current.log
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
            parser::cfwevent_parse(event.as_bytes()).unwrap().1
        })
        .take(num_events)
        .collect();

        let mut vms = vmobjs.write().unwrap();
        vms.insert(zone1.zonedid, zone1);
        drop(vms);

        let mut writer = vec![];
        log_events(events, &mut writer, &vmobjs);

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
