// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Copyright 2019 Joyent, Inc.

//! cfwlogd is a userland daemon that is responsible for translating firewall events into newline
//! separated json logs.  It does so by attaching to the kernel device found at `/dev/ipfev` and
//! reading in a buffer of bytes.  Cfwlogd is then responsible for parsing the buffer into cloud
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
//! appropriate zone information that contains the customer uuid, the vm uuid, and the vm alias.
//! It does this by spawning a `vminfod` watcher thread that is responsible for tracking vminfod
//! events as they arrive. Each binary payload from the kernel device contains a `zonedid` which is
//! a unique id per vm until the box is rebooted; this allows cfwlogd to keep track of what event
//! is for what vm (zone). Also, because cfwlogd gets vminfod events in real time it is able to
//! track things like vm alias changes. As events are read from the kernel cfwlogd looks for an
//! existing logging thread or creates one if it's the first event it has seen for a specific zone.
//! Each logging thread serializes the internal data structure to json and writes the log to a
//! `BufWriter` which has its own internal buffer that will flush to disk once full, this is to
//! cut down on the number of write syscalls cfwlogd has to make.

use crossbeam::channel;
use crossbeam::sync::ShardedLock;
use daemonize::Daemonize;
use illumos_priv::{PrivOp, PrivPtype, PrivSet, Privilege};
use libc::c_int;

use std::collections::HashMap;
use std::ffi::CString;
use std::fs::OpenOptions;
use std::io;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;
use std::sync::Arc;

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
use zones::Vmobjs;

const LOG_DIR: &str = "/var/log/firewall";

/// As defined in smf_method(5): method successfully but purposefully leaves no processes remaining
/// in the contract; it should be treated as if it had a transient service model.
const SMF_EXIT_NODAEMON: i32 = 94;

/// Set's the daemon's privileges to the basic set plus a few extras that allow us to open the
/// /dev/ipfev device and chroot ourselves into LOG_DIR
fn cfwlogd_set_privs() -> io::Result<()> {
    let set = PrivSet::new_basic()?;
    // Remove
    set.delset(Privilege::ProcInfo)?;
    set.delset(Privilege::ProcSession)?;
    set.delset(Privilege::FileLinkAny)?;
    set.delset(Privilege::ProcExec)?;
    // Add
    set.addset(Privilege::ProcChroot)?;
    set.addset(Privilege::ProcSetid)?;
    set.addset(Privilege::SysNetConfig)?;

    illumos_priv::setppriv(PrivOp::Set, PrivPtype::Permitted, &set)?;
    Ok(())
}

/// Drop all the privileges that we no longer need once we are running as a child aka daemon.
fn cfwlogd_drop_privs() -> io::Result<()> {
    let set = illumos_priv::getppriv(PrivPtype::Permitted)?;
    set.delset(Privilege::ProcFork)?;
    set.delset(Privilege::ProcChroot)?;
    set.delset(Privilege::ProcSetid)?;
    set.delset(Privilege::SysNetConfig)?;

    illumos_priv::setppriv(PrivOp::Set, PrivPtype::Permitted, &set)?;
    Ok(())
}

/// Fork cfwlogd as a daemon.
fn cfwlogd_daemonize() {
    // The "daemonize" crate unfortunately sets stdout/stderr to devnull if you don't specify a
    // path, so for now we reopen them manually via their respective devices.
    let stdout = OpenOptions::new()
        .write(true)
        .open("/dev/stdout")
        .expect("failed to open stdout");
    let stderr = OpenOptions::new()
        .write(true)
        .open("/dev/stderr")
        .expect("failed to open stderr");

    // Drop all groups
    if unsafe { libc::setgroups(0, std::ptr::null()) } != 0 {
        let e = io::Error::last_os_error();
        error!("failed to drop all groups: {}", e);
        std::process::exit(e.raw_os_error().unwrap_or(1));
    }

    if let Err(e) = Daemonize::new()
        .stdout(stdout)
        .stderr(stderr)
        .group("daemon")
        .working_directory(LOG_DIR)
        .umask(0o022)
        .start()
    {
        error!("failed to daemonize: {}", e);
        std::process::exit(1);
    };
}

/// Process incoming unix signals. Returns `true` if the signal indicates that
/// we should shutdown the process.
fn cfwlogd_handle_signals(s: c_int, loggers: &Loggers) -> bool {
    let mut shutdown = false;
    match s {
        // CMON TRITON-1755 -- dump some cmon counters somewhere?
        libc::SIGUSR1 => info!("SIGUSR1: caught sigusr1"),
        // Tell the logger threads to flush to disk
        libc::SIGUSR2 => {
            info!("SIGUSR2: flushing logs");
            let loggers = loggers.lock().unwrap();
            loggers.values().for_each(|logger| {
                if logger.flush().is_err() {
                    error!(
                        "Failed to flush logs for {} because the logger is no \
                         longer listening on its signal handler",
                        &logger.uuid
                    );
                }
            });
        }
        // Tell logger threads to flush and reopen current.log
        libc::SIGHUP => {
            info!(
                "SIGHUP: log rotation -- flushing currently opened files and \
                 reopening current.log"
            );
            let loggers = loggers.lock().unwrap();
            loggers.values().for_each(|logger| {
                if logger.rotate().is_err() {
                    error!(
                        "Failed to rotate logs for {} because the logger is no \
                         longer listening on its signal handler",
                        &logger.uuid
                    );
                }
            });
        }
        // Shutdown
        libc::SIGINT => {
            info!("SIGINT: shutting down");
            shutdown = true;
        }
        // Shutdown
        libc::SIGTERM => {
            info!("SIGTERM: shutting down");
            shutdown = true;
        }
        // Ignore all other signals in our set
        val => debug!("ignoring signal: {}", val),
    }
    shutdown
}

/// Chroot into the provided path.
fn cfwlogd_chroot<P: Into<PathBuf>>(p: P) -> io::Result<()> {
    let path = p.into();
    std::fs::create_dir_all(&path)?;
    let cstring = CString::new(path.into_os_string().into_vec())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "path contained nuls"))?;
    unsafe {
        match libc::chroot(cstring.as_ptr()) {
            -1 => Err(io::Error::last_os_error()),
            _ => Ok(()),
        }
    }
}

/// Given a list of zones, iterate through them looking for log files that have incomplete newline
/// separated json logs. Truncate logs to the first "\n" found from the end of the file seeking
/// backwards.
fn validate_log_files(vmobjs: &Vmobjs) {
    let zones = vmobjs.read().unwrap();
    for zone in zones.values() {
        let path: PathBuf = ["/", &zone.owner_uuid, &zone.uuid, "current.log"]
            .iter()
            .collect();

        // If the file doesn't yet exist on disk we can skip over it
        if !path.is_file() {
            continue;
        };

        match OpenOptions::new().read(true).write(true).open(&path) {
            Ok(mut file) => match fileutils::rseek_and_scan(&mut file, 512, b'\n') {
                Ok(info) => {
                    // If we find the "\n" we add 1 to the index so that when we truncate the file
                    // we keep the newline.
                    let idx = info.index.and_then(|i| Some(i + 1)).unwrap_or(0);
                    // If idx matches the length of the file we can skip the
                    // truncation.
                    if idx == info.length {
                        continue;
                    }
                    if let Err(e) = file.set_len(idx) {
                        error!("failed to truncate file ({}): {}", &path.display(), e);
                    } else {
                        info!(
                            "truncated {} by {} bytes",
                            &path.display(),
                            info.length - idx
                        );
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
}

fn main() {
    pretty_env_logger::init();

    // Since we are running as root limit our privileges as early as possible.
    if let Err(e) = cfwlogd_set_privs() {
        error!("failed to add extra privileges: {}", e);
        std::process::exit(e.raw_os_error().unwrap_or(1));
    }
    debug!("successfully set new privileges");

    let device = IpfevDevice::new("/dev/ipfev").unwrap_or_else(|e| match e.kind() {
        // The device was not found but ipfilter is online because the smf dependency
        // requires it to be up before starting, therefore we are on a platform that
        // doesn't support ipfev. So we exit with SMF_EXIT_NODAEMON to indicate success
        // leaving no process running.
        io::ErrorKind::NotFound => {
            info!(
                "/dev/ipfev not present on this system -- \
                 treating the daemon as a transient service"
            );
            std::process::exit(SMF_EXIT_NODAEMON);
        }
        // Anything other than NotFound should be treated as a hard error.
        _ => {
            error!("failed to open /dev/ipfev: {}", e);
            std::process::exit(e.raw_os_error().unwrap_or(1));
        }
    });

    cfwlogd_daemonize();

    // The vminfod client and signal handler need access to /dev/{u}random so we handle these
    // things before we chroot into "/var/log/firewall"
    // TODO make sure the vminfod client is able to be restarted later once we drop privs
    let vmobjs = Arc::new(ShardedLock::new(HashMap::new()));
    let _vminfod_handle = zones::start_vminfod(Arc::clone(&vmobjs));

    // This is unbounded so that we don't block in the signal handler
    let (sig_tx, sig_rx) = channel::unbounded();
    let _signal_handle = signal::start_signalhandler(sig_tx);

    // Since we are running as root lock ourselves into the LOG_DIR, and then further limit our
    // privileges.
    if let Err(e) = cfwlogd_chroot(LOG_DIR) {
        error!("failed to chroot into {}: {}", LOG_DIR, e);
        std::process::exit(e.raw_os_error().unwrap_or(1));
    }
    if let Err(e) = cfwlogd_drop_privs() {
        error!("failed to drop privileges: {}", e);
        std::process::exit(e.raw_os_error().unwrap_or(1));
    }
    debug!("successfully dropped privileges");

    validate_log_files(&vmobjs);

    // Setup our processing pipeline
    let (shutdown_tx, shutdown_rx) = channel::bounded(1);
    let (ipf_events, _ipf_handle) = events::start_event_reader(device);
    let (loggers, fanout_handle) =
        events::start_event_fanout(ipf_events, shutdown_rx, Arc::clone(&vmobjs));

    // Handle signals until we are told to exit
    for sig in sig_rx.iter() {
        if cfwlogd_handle_signals(sig, &loggers) {
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
}
