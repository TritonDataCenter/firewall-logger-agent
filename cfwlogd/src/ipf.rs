use crate::logger::{self, Logger};
use crate::parser::{self, EventInfo};
use crate::zones::{Vmobjs, Zonedid};
use bytes::Bytes;
use crossbeam::channel::{self, Receiver, TrySendError};
use crossbeam::queue::ArrayQueue;
use failure::{Error, ResultExt};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;

type Loggers = Arc<Mutex<HashMap<Zonedid, Logger>>>;

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
    let capacity = 1024;
    let (tx, rx) = channel::bounded(capacity);
    (
        rx,
        thread::Builder::new()
            .name("ipf_reader".to_string())
            .spawn(move || {
                // We may need to adjust the size of this value. It's based off the original size
                // of the ipfev in kernel ringbuffer.  The hope is that ipfev will provide an ioctl
                // interface that gives us some basic info like the size of the largest message
                // type, and the size of the ring buffer.
                const BUFSIZE: usize = 81920;
                let mut buf = [0; BUFSIZE];

                // A secondary buffer to fill if our channel has gotten a bit behind.
                let queue = ArrayQueue::new(capacity);

                // If the device fails to open there is no point in continuing.
                let mut device = IpfevDevice::new("/dev/ipfev").unwrap();

                loop {
                    // TODO: once again we may choose to shutdown this thread when this happens
                    // allowing the logging queues to drain to disk before halting the world
                    let size = device
                        .read_events(&mut buf)
                        .context("failed to read from ipfev device")
                        .unwrap();

                    // Allocate some space on the heap for the slab of event(s). This is the source
                    // of our double copy but its needed for now.
                    let bytes = Bytes::from(&buf[..size]);

                    // The secondary queue is not empty so we need to drain it into the receiving
                    // channel first.  This is to ensure events maintain order.
                    // FIXME: drain the queue before trying to buffer up the next bytes!
                    if queue.len() > 0 {
                        match queue.push(bytes) {
                            Ok(()) => {
                                loop {
                                    // Try to drain as much of the queue into the processing
                                    // channel as possible.
                                    if let Ok(bytes) = queue.pop() {
                                        // the receiving queue is full again so stop trying to
                                        // drain the queue
                                        if tx.try_send(bytes).is_err() { break };
                                    } else {
                                        break;
                                    }
                                }
                            }
                            Err(_) => {
                                warn!("secondary event queue is full so we are dropping event(s)")
                            }
                        }
                    // The secondary queue does not contain anything, so we are safe to try pushing
                    // directly into the receiving channel.
                    } else {
                        if let Err(e) = tx.try_send(bytes) {
                            match e {
                                // Our attempt to push into the primary channel failed so try to
                                // send it to the secondary queue.
                                TrySendError::Full(t) => {
                                    queue.push(t).unwrap_or_else(|_| {
                                        warn!("secondary event queue is full so we are dropping event(s)")
                                    });
                                }
                                // This means cfwlogd will make no further progress so we should
                                // kill the program
                                //
                                // TODO: we should have this thread close and allow the various
                                // logging queues to exit cleanly before the program comes to a
                                // halt. We should look at using `WaitGroups` to achieve this
                                TrySendError::Disconnected(_) => {
                                    panic!("the event processing thread has disconnected!");
                                }
                            }
                        }
                    }

                    trace!("receiver queue length: {}", tx.len());
                    trace!("secondary queue lenth: {}", queue.len());
                }
            })
            .expect("failed to start ipf reader thread"),
    )
}

fn queue_zone_event(info: &EventInfo, event: Bytes, vmobjs: &Vmobjs, loggers: &mut Loggers) {
    let mut loggers = loggers.lock().unwrap();
    let logger = match loggers.entry(info.zonedid) {
        Entry::Occupied(entry) => entry.into_mut(),
        Entry::Vacant(entry) => match logger::start_logger(info.zonedid, vmobjs.clone()) {
            Some(logger) => entry.insert(logger),
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
    if let Err(_) = logger.send(event) {
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

pub fn start_eventprocessor(
    rx: Receiver<Bytes>,
    vmobjs: Vmobjs,
) -> (Loggers, thread::JoinHandle<()>) {
    let mapping: HashMap<Zonedid, Logger> = HashMap::new();
    let loggers = Arc::new(Mutex::new(mapping));
    let mut loggers2 = loggers.clone();
    (
        loggers,
        thread::Builder::new()
            .name("ipf_event_processor".to_string())
            .spawn(move || {
                for bytes in rx.iter() {
                    let mut offset = 0;
                    while offset < bytes.len() {
                        let (_leftover, info) =
                            parser::peek_event(&bytes[offset..]).expect("failed to peek at event");
                        let size = info.length as usize;

                        let event = bytes.slice(offset, size);
                        queue_zone_event(&info, event, &vmobjs, &mut loggers2);

                        offset += size;
                    }
                }
            })
            .expect("failed to start ipf event processing thread"),
    )
}
