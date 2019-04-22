use crate::logger::{self, Logger};
use crate::parser::{self, EventInfo};
use crate::zones::{Vmobjs, Zonedid};
use bytes::Bytes;
use crossbeam::channel::{self, select, Receiver, TrySendError};
use failure::{Error, ResultExt};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;

pub type Loggers = Arc<Mutex<HashMap<Zonedid, Logger>>>;

/// Wrapper around the ipfev device
struct IpfevDevice {
    fd: File,
}

impl IpfevDevice {
    /// Create a new `IpfevDevice`
    fn new<P: AsRef<Path>>(device: P) -> Result<Self, Error> {
        let device = device.as_ref();
        let fd = File::open(device).context("failed to open ipfev device")?;
        info!("connected to {}", device.display());
        Ok(IpfevDevice { fd })
    }

    /// Pull at least one event from the ipfev device into the provided buffer
    fn read_events(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let size = self
            .fd
            .read(buf)
            .context("failed to read from ipfev device")?;

        // The device should never return from a read with 0 bytes
        assert!(size > 0);
        Ok(size)
    }
}

/// This will start a thread that consumes events from an `IpfevDevice`.
/// The events will then be sent off to a Queue that can be processed by another thread.
///
/// The current design is less than ideal. Currently we read up to n events that will fit into our
/// on stack buffer.  That buffer is then converted into a `Bytes` object, which means we have to
/// copy the data yet again to a heap allocated ownership. We don't read directly into a `Bytes`
/// because we are unsure how many events will be read from `IpfevDevice`, which means in the worst
/// case scenario we have a large `Bytes` object that contains a single cfw event.
pub fn start_ipfreader() -> (Receiver<Bytes>, thread::JoinHandle<()>) {
    let capacity = 5 * 1024;
    let (tx, rx) = channel::bounded(capacity);
    (
        rx,
        thread::Builder::new()
            .name("ipf_reader".to_owned())
            .spawn(move || {
                // We may need to adjust the size of this value. It's based off the original size
                // of the ipfev in kernel ringbuffer.  The hope is that ipfev will provide an ioctl
                // interface that gives us some basic info like the size of the largest message
                // type, and the size of the ring buffer.
                const BUFSIZE: usize = 81920;
                let mut buf = [0; BUFSIZE];

                // If the device fails to open there is no point in continuing.
                let mut device = IpfevDevice::new("/dev/ipfev").unwrap();

                loop {
                    let size = device
                        .read_events(&mut buf)
                        .context("failed to read from ipfev device")
                        .unwrap();

                    // Allocate some space on the heap for the slab of event(s). This is the source
                    // of our double copy but its needed for now.
                    let bytes = Bytes::from(&buf[..size]);

                    if let Err(e) = tx.try_send(bytes) {
                        match e {
                            // Unfortunately we have to drop a chunk of bytes
                            TrySendError::Full(_dropped_event) => {
                                warn!("processing channel is full so we are dropping event(s)")
                            }
                            // We are in the process of shutting down
                            TrySendError::Disconnected(_) => {
                                info!("the event processing channel has disconnected");
                                break;
                            }
                        }
                    }
                }
            })
            .expect("failed to start ipf reader thread"),
    )
}

/// For a given cfw event, find or create a `Logger` thats responsible for serializing the event to
/// disk.
fn queue_zone_event(info: &EventInfo, event: Bytes, vmobjs: &Vmobjs, loggers: &mut Loggers) {
    let mut loggers = loggers.lock().unwrap();
    let logger = match loggers.entry(info.zonedid) {
        Entry::Occupied(entry) => entry.into_mut(),
        Entry::Vacant(entry) => match logger::start_logger(info.zonedid, vmobjs.clone()) {
            Some(logger) => {
                info!("new logging thread started for zonedid {}", info.zonedid);
                entry.insert(logger)
            }
            None => {
                // XXX CMON
                error!(
                    "unable to match zonedid {} to vm object; dropping event",
                    info.zonedid
                );
                return;
            }
        },
    };
    if logger.send(event).is_err() {
        // Receive side of the log was disconnected somehow, so we drop the entry allowing it to be
        // recreated on the next event.
        // XXX CMON
        error!(
            "failed to log event for zone {} (logger channel disconnected)",
            info.zonedid
        );
        loggers.remove(&info.zonedid);
    }
}

#[inline]
/// Slice up a `Bytes` chunk into individual cfw events and queue the corresponding event into a
/// zone appropriate logger.
fn process_chunk(bytes: Bytes, vmobjs: &Vmobjs, mut loggers: &mut Loggers) {
    let mut offset = 0;
    while offset < bytes.len() {
        let (_leftover, info) =
            parser::peek_event(&bytes[offset..]).expect("failed to peek at event");
        let size = info.length as usize;

        let event = bytes.slice(offset, offset + size);
        queue_zone_event(&info, event, vmobjs, &mut loggers);

        offset += size;
    }
}

fn process_events(
    events: Receiver<Bytes>,
    shutdown: Receiver<()>,
    vmobjs: Vmobjs,
    mut loggers: Loggers,
) {
    // loop over events until we receive a shutdown signal
    loop {
        select! {
            // TODO if the ipfev consuming thread hits an error and closes its channel we should
            // bring down the process since no progress will be made and crashing the program
            // potentially loses events
            recv(events) -> bytes => {
                if let Ok(bytes) = bytes {
                    process_chunk(bytes, &vmobjs, &mut loggers);
                }
            }
            recv(shutdown) -> signal => {
                if signal.is_ok() {
                    debug!("event processing thread received shutdown signal");
                    break;
                };
            }
        }
    }

    // Attempt to grab all of the events that are currently in the queue so we can
    // shutdown the receiver as quickly as possible. We use "take()" here so that we
    // don't end up in a situation where this processing thread is being blasted with
    // incoming events and we can't disconnect in a timely manor.
    let drain: Vec<_> = events.try_iter().take(events.len()).collect();
    drop(events);
    debug!(
        "event processing thread drained {} remaining events before shutdown",
        drain.len()
    );
    for bytes in drain {
        process_chunk(bytes, &vmobjs, &mut loggers);
    }

    info!("event processing thread exiting");
}

pub fn start_eventprocessor(
    events: Receiver<Bytes>,
    shutdown: Receiver<()>,
    vmobjs: Vmobjs,
) -> (Loggers, thread::JoinHandle<()>) {
    let mapping: HashMap<Zonedid, Logger> = HashMap::new();
    let loggers = Arc::new(Mutex::new(mapping));
    let loggers2 = loggers.clone();
    (
        loggers,
        thread::Builder::new()
            .name("ipf_event_processor".to_owned())
            .spawn(move || process_events(events, shutdown, vmobjs, loggers2))
            .expect("failed to start ipf event processing thread"),
    )
}
