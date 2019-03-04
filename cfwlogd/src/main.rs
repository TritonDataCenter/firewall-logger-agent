// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Copyright 2019 Joyent, Inc.

//! cfwlogd is a userland daemon that is responsible for translating firewall events into json
//! logs.  It does so by attaching to a kernel device such as `/dev/ipfev` and reading in a
//! buffer of bytes.  cfwlogd is then responsible for parsing the buffer into cloud
//! firewall logs that will be serialized out to disk as json in
//! `/var/log/firewall/<customer>/<vm>/<timestamp>.log`
//!
//!
//!                      cfwlogd's current design
//!
//!
//! gz process 127.0.0.1:9090
//! +-------------------+
//! |  vminfod process  |
//! +-------------------+
//!         |
//!         |
//!         v                Kernel Device
//!   Vminfod Thread         +------------+
//! +-----------------+      | /dev/ipfev |
//! | vminfod watcher |      +------------+
//! +-----------------+            |
//!         |                      v
//!         |                Userland Daemon
//!         |                  +---------+
//!         -----------------> | cfwlogd |
//!                            +---------+
//!                                |
//!                                v
//!                       Processing Threads
//!                  -----------------------------
//!                  |             |             |
//!                +-----+      +-----+      +-----+
//!                | vm1 |      | vm2 |      | vm3 |
//!                +-----+      +-----+      +-----+
//!                  |             |             |
//!                  v             v             v
//!              +--------+    +--------+    +--------+
//!              |vm1.log |    |vm2.log |    |vm3.log |
//!              +--------+    +--------+    +--------+
//!
//!
//! In summary, cfwlogd must correlate the firewall log events it gets from the kernel with the
//! apprpriate zone information that contains the customer uuid, the vm uuid, and the vm  alias.
//! It does this by spawning a `vminfod` watcher thread that is responsible for tracking vminfod
//! events as they arrive. Each binary payload from the kernel contains a `zonedid` which is a
//! unique id per vm until the box is rebooted, this allows cfwlogd to keep track of what event is
//! for what vm. Also, becauase cfwlogd gets vminfod events in real time it is able to track things
//! like vm alias changes. As events are read from the kernel cfwlogd looks for an existing logging
//! thread or creates one if its the first event it has seen for a specific zone. Each logging
//! thread serialzes the internal data structure to json and writes the log to a `BufWriter` which
//! has its own internall buffer that will flush to disk once full, this is to cut down on the
//! number of write syscalls cfwlogd has to make.

use crossbeam::channel;
use crossbeam::sync::ShardedLock;
use failure::Error;
use libc::c_int;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::sync::Arc;

#[macro_use]
extern crate nom;
#[macro_use]
extern crate log;

mod events;
mod fileutils;
mod ipf;
mod logger;
mod parser;
mod signal;
mod zones;
use events::Loggers;
use ipf::IpfevDevice;

// Method successfully but purposefully leaves no processes remaining in the
// contract; it should be treated as if it had a transient service model.
const SMF_EXIT_NODAEMON: i32 = 94;

/// Process incoming unix signals. Returns `true` if the signal indicates that
/// we should shutdown the process.
fn handle_signal(s: c_int, loggers: &Loggers) -> bool {
    let mut shutdown = false;
    match s {
        // XXX might be interesting to have USR1 export some statistics
        libc::SIGUSR1 => info!("SIGUSR1: caught sigusr1"),
        libc::SIGUSR2 => {
            info!("SIGUSR2: flushing logs");
            let loggers = loggers.lock().unwrap();
            for logger in loggers.values() {
                if logger.flush().is_err() {
                    error!(
                        "Failed to flush logs for {} because the logger is no \
                         longer listening on its signal handler",
                        &logger.uuid
                    );
                }
            }
        }
        libc::SIGHUP => {
            info!(
                "SIGHUP: log rotation -- flushing currently opened files and \
                 reopening current.log"
            );
            let loggers = loggers.lock().unwrap();
            for logger in loggers.values() {
                if logger.rotate().is_err() {
                    error!(
                        "Failed to rotate logs for {} because the logger is no \
                         longer listening on its signal handler",
                        &logger.uuid
                    );
                }
            }
        }
        libc::SIGINT => {
            info!("SIGINT: shutting down");
            shutdown = true;
        }
        libc::SIGTERM => {
            info!("SIGTERM: shutting down");
            shutdown = true;
        }
        val => debug!("ignoring signal: {}", val),
    }
    shutdown
}

fn main() -> Result<(), Error> {
    // We may want bunyan here or some other log crate that implements "log"
    pretty_env_logger::init();

    let vmobjs = Arc::new(ShardedLock::new(HashMap::new()));
    let _vminfod_handle = zones::start_vminfod(Arc::clone(&vmobjs));

    // Now that we have a list of zones, we iterate through them looking for any existing log files
    // that may have incomplete data from a previous run of cfwlogd, such as a crash or a SIGKILL.
    // If we find an existing log file we attempt to scan the file backwards looking for a "\n" to
    // ensure that the log file does not end with incomplete json logs. If we find a "\n" we
    // truncate the file to that position, and if we dont find one then we truncate the log all
    // together. Note that this currently doesn't account for a zone that was deleted between now
    // and the time where cfwlogd was torn down without a chance to clean up.
    let zones = vmobjs.read().unwrap();
    for zone in zones.values() {
        let path: PathBuf = [
            "/var/log/firewall",
            &zone.owner_uuid,
            &zone.uuid,
            "current.log",
        ]
        .iter()
        .collect();

        // If the file doesn't exist on disk we can skip over it
        if !path.is_file() {
            continue;
        };

        match OpenOptions::new().read(true).write(true).open(&path) {
            Ok(mut file) => match fileutils::rseek_and_scan(&mut file, 512, b'\n') {
                Ok(idx) => {
                    // If we find the "\n" we add 1 to the index so that when we truncate the file
                    // we keep the newline.
                    let idx = idx.and_then(|i| Some(i + 1)).unwrap_or(0);
                    if let Err(e) = file.set_len(idx) {
                        error!("failed to truncate file ({}): {}", &path.display(), e);
                    } else {
                        debug!("tuncated {} to {}", &path.display(), idx);
                    }
                }
                Err(e) => {
                    error!(
                        "failed to scan file ({}) for a newline: {}",
                        &path.display(),
                        e
                    );
                }
            },
            Err(e) => error!(
                "failed to open file ({}) for cleanup: {}",
                path.display(),
                e
            ),
        }
    }
    drop(zones);

    // This is unbounded so that we don't block in the signal handler
    let (sig_tx, sig_rx) = channel::unbounded();
    let (shutdown_tx, shutdown_rx) = channel::bounded(1);

    let device = IpfevDevice::new("/dev/ipfev").unwrap_or_else(|e| match e.kind() {
        // The device was not found but ipfilter is online because the smf dependency requires it
        // to be up before starting, therefore we are on a platform that doesn't support ipfev. So
        // we exit with SMF_EXIT_NODAEMON to indicate success leaving no process running.
        std::io::ErrorKind::NotFound => {
            info!(
                "/dev/ipfev not present on this system -- \
                 treating the daemon as a transient service "
            );
            std::process::exit(SMF_EXIT_NODAEMON);
        }
        // Anything other than NotFound should be treated as a hard error.
        _ => {
            error!("failed to open /dev/ipfev: {}", e);
            std::process::exit(e.raw_os_error().unwrap_or(-1));
        }
    });

    // Setup our processing pipeline
    let (ipf_events, _ipf_handle) = events::start_event_reader(device);
    let (loggers, fanout_handle) =
        events::start_event_fanout(ipf_events, shutdown_rx, Arc::clone(&vmobjs));
    let _signal_handle = signal::start_signalhandler(sig_tx);

    // Handle signals until we are told to exit
    for sig in sig_rx.iter() {
        if handle_signal(sig, &loggers) {
            break;
        };
    }

    // Wait for the event processor to drain all queued events into its loggers
    shutdown_tx.send(()).unwrap();
    fanout_handle.join().unwrap();

    // Wait for loggers to finish flushing to disk
    let mut loggers = loggers.lock().unwrap();
    for (zonedid, logger) in loggers.drain() {
        info!(
            "shutting down logging thread for {} ({})",
            logger.uuid, zonedid
        );
        logger.shutdown().unwrap();
    }

    Ok(())
}
