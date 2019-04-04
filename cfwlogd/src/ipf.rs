use bytes::Bytes;
use failure::{Error, ResultExt};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::thread;

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
pub fn start_ipfreader() -> thread::JoinHandle<()> {
    thread::Builder::new()
        .name("ipf_reader".to_string())
        .spawn(move || {
            // We may need to adjust the size of this value. It's based off the original size of
            // the ipfev in kernel ringbuffer.  The hope is that ipfev will provide an ioctl
            // interface that gives us some basic info like the size of the largest message type,
            // and the size of the ring buffer.
            const BUFSIZE: usize = 81920;
            let mut buf = [0; BUFSIZE];

            // If the device fails to open there is no point in continuing
            let mut device = IpfevDevice::new("/dev/ipfev").unwrap();

            loop {
                let size = device
                    .read_events(&mut buf)
                    .context("failed to read from ipfev device")
                    .unwrap();

                let bytes = Bytes::from(&buf[..size]);
                match queue.push(bytes); {
                    Ok() => (),
                    PushError(_) => {
                        // XXX we might want a secondary queue that we can use if the main one is
                        // full to process retries.
                        // It also might be nice to keep some sort of metrics of events that are
                        // dropped for something like cmon
                        info!("the events queue is full so we are dropping a chunk of events");
                    }
                }
            }
        })
        .expect("failed to start ipf reader thread")
}
