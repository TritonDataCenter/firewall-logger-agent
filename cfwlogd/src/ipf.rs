// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Copyright 2019 Joyent, Inc.

//! This is the implementation of an EventSource for ipfilter.

use crate::events::EventSource;
use libc::c_int;
use std::fs::File;
use std::io::Read;
use std::os::unix::io::AsRawFd;
use std::path::Path;

/// SIOCIPFCFWCFG generated from:
/// _IOR('r', 98, struct ipfcfwcfg)
/// This _MUST_ be recomputed if any changes to `Ipfcfwcfg` are made.
const SIOCIPFCFWCFG: c_int = 1_075_343_970;

// C representation of a cfw event
#[repr(C)]
#[derive(Default)]
pub struct Ipfcfwcfg {
    pub max_event_size: u32,
    pub ring_size: u32,
    pub num_reports: u64,
    pub num_drops: u64,
}

/// Wrapper around the ipfev device
pub struct IpfevDevice {
    fd: File,
}

impl IpfevDevice {
    /// Create a new `IpfevDevice`
    pub fn new<P: AsRef<Path>>(device: P) -> std::io::Result<Self> {
        let device = device.as_ref();
        let fd = File::open(device)?;
        info!("connected to {}", device.display());
        Ok(IpfevDevice { fd })
    }
}

impl EventSource for IpfevDevice {
    /// Pull at least one event from the ipfev device into the provided buffer
    fn read_events(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let size = self.fd.read(buf)?;
        // The device should never return from a read with 0 bytes
        assert!(size > 0);
        Ok(size)
    }

    /// Dynamically read the largest known event size and the current sizing of the ring buffer
    fn event_sizing(&mut self) -> std::io::Result<(usize, usize)> {
        let mut cfg = Ipfcfwcfg::default();
        unsafe {
            let cfg_ptr = &mut cfg as *mut Ipfcfwcfg;
            match libc::ioctl(self.fd.as_raw_fd(), SIOCIPFCFWCFG, cfg_ptr) {
                -1 => Err(std::io::Error::last_os_error()),
                _ => Ok((cfg.max_event_size as usize, cfg.ring_size as usize)),
            }
        }
    }
}
