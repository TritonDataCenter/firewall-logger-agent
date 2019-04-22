use crate::ipf::Loggers;
use libc::c_int;
use std::collections::HashMap;
use std::sync::Arc;

#[macro_use]
extern crate nom;
#[macro_use]
extern crate log;

extern crate pretty_env_logger;
use crossbeam::channel;
use crossbeam::sync::ShardedLock;
use failure::Error;

mod ipf;
mod logger;
mod parser;
mod signal;
mod zones;
use vminfod::Zone;
use zones::Zonedid;

/// Process incoming unix signals. Returns `true` if the signal indicates that we should shutdown
/// the process.
fn handle_signal(s: c_int, loggers: &Loggers) -> bool {
    let mut shutdown = false;
    match s {
        libc::SIGUSR1 => debug!("caught sigusr1"),
        libc::SIGHUP => {
            info!("rotating logs");
            let loggers = loggers.lock().unwrap();
            for (_, logger) in loggers.iter() {
                let _ = logger.rotate();
            }
        }
        libc::SIGINT => {
            info!("shutting down");
            shutdown = true;
        }
        val => debug!("ignoring signal: {}", val),
    }
    shutdown
}

fn main() -> Result<(), Error> {
    pretty_env_logger::init();

    let mapping: HashMap<Zonedid, Zone> = HashMap::new();
    let vmobjs = Arc::new(ShardedLock::new(mapping));
    let _vminfod_handle = zones::start_vminfod(vmobjs.clone());
    let (sig_tx, sig_rx) = channel::unbounded();
    let (shutdown_tx, shutdown_rx) = channel::bounded(1);

    // Setup our pipeline
    let (ipf_events, _ipf_handle) = ipf::start_ipfreader();
    let (loggers, eventprocessor_handle) =
        ipf::start_eventprocessor(ipf_events, shutdown_rx, vmobjs.clone());
    let _signal_handle = signal::start_signalhandler(sig_tx);

    // Handle signals until we are told to exit
    for sig in sig_rx.iter() {
        if handle_signal(sig, &loggers) {
            break;
        };
    }

    // Wait for the event processor to drain all queued events into its loggers
    shutdown_tx.send(()).unwrap();
    eventprocessor_handle.join().unwrap();

    // Wait for loggers to finish flushing to disk
    let mut loggers = loggers.lock().unwrap();
    for (zonedid, logger) in loggers.drain() {
        logger.shutdown().unwrap();
        info!("shutdown logging thread for zonedid {}", zonedid);
    }

    Ok(())
}
