use std::collections::HashMap;
use std::sync::Arc;

#[macro_use]
extern crate nom;
#[macro_use]
extern crate log;

extern crate pretty_env_logger;
use crossbeam::sync::ShardedLock;
use failure::Error;

//mod ipf;
mod ipf;
mod logger;
mod parser;
mod zones;
use vminfod::Zone;
use zones::Zonedid;

fn main() -> Result<(), Error> {
    pretty_env_logger::init();

    let mapping: HashMap<Zonedid, Zone> = HashMap::new();
    let vmobjs = Arc::new(ShardedLock::new(mapping));

    let _vminfod_handle = zones::start_vminfod(vmobjs.clone());

    // Setup our pipeline
    let (ipf_events, ipf_handle) = ipf::start_ipfreader();
    let (loggers, event_handle) = ipf::start_eventprocessor(ipf_events, vmobjs.clone());

    // we have a copy of loggers that we can use to flush/rotate logs with
    // for logger in loggers { .... }

    // for now block on something so the pipeline doesn't return
    ipf_handle.join().unwrap();
    Ok(())
}
