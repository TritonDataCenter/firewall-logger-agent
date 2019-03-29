use failure::{Error, ResultExt};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;

/// Wrapper around the ipfev device
pub struct IpfevDevice {
    fd: File,
}

impl IpfevDevice {
    /// Create a new `IpfevDevice`
    pub fn new<P: AsRef<Path>>(device: P) -> Result<Self, Error> {
        let device = device.as_ref();
        let fd = File::open(device).context("failed to open ipfev device")?;
        info!("connected to {}", device.display());
        Ok(IpfevDevice { fd })
    }

    /// Pull at least one event from the ipfev device into the provided buffer
    pub fn read_events(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let size = self
            .fd
            .read(buf)
            .context("failed to read from ipfev device")?;

        // The device should never return from a read with 0 bytes
        assert!(size > 0);
        Ok(size)
    }
}

// Start a thread that will be reading events from the `IpfevDevice`
// and put them in a queue
//pub fn start_reader(device: IpfevDevice) -> thread::JoinHandle<()> {
//    thread::Builder::new()
//        .name("ipfreader".to_string())
//        .spawn(move || {
//            let mut buf = [0; 100];
//            loop {
//                device.fd.read_events(&mut buf).unwrap();
//
//                drop(ipf);
//                // process the bytes
//            }
//        })
//        .expect("failed to spawn IpfReader thread")
//}
