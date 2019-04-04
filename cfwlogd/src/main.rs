use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::thread;

#[macro_use]
extern crate nom;
#[macro_use]
extern crate log;

extern crate pretty_env_logger;
use crossbeam::channel;
use crossbeam::channel::Sender;
use crossbeam::sync::ShardedLock;
use failure::{Error, ResultExt};

//mod ipf;
mod ipf;
mod logger;
mod parser;
mod zones;
use ipf::IpfevDevice;
use parser::CfwEvent;
use serde::Serialize;
use vminfod::Zone;
use zones::Zonedid;

#[derive(Debug, Serialize)]
struct LogEvent {
    #[serde(flatten)]
    event: CfwEvent,
    vm: String,
    alias: String,
}

type Loggers = Arc<Mutex<HashMap<Zonedid, (Sender<LogEvent>, Sender<bool>)>>>;

fn main() -> Result<(), Error> {
    pretty_env_logger::init();

    /// This is hardcoded until `/dev/ipfev` provides an ioctl interface that can tell us a few
    /// things like size of the largest event type, and size of the internal ring buffer
    let mapping: HashMap<Zonedid, Zone> = HashMap::new();
    let vmobjs = Arc::new(ShardedLock::new(mapping));
    let channels: HashMap<Zonedid, (Sender<LogEvent>, Sender<bool>)> = HashMap::new();
    let loggers = Arc::new(Mutex::new(channels));

    let _vminfod_handle = zones::start_vminfod(vmobjs.clone());

    let (log_tx, log_rx) = channel::unbounded::<CfwEvent>();
    let _fan_out = thread::Builder::new()
        .name("event-fan-out".to_string())
        .spawn(move || {
            for event in log_rx.iter() {
                let r = vmobjs.read().unwrap();
                let zonedid = event.zone();
                let vmobj = match r.get(&zonedid) {
                    Some(v) => v,
                    None => {
                        warn!("cfwlogd doesn't yet know about zone {}", &zonedid);
                        continue;
                    }
                };
                let log = LogEvent {
                    vm: vmobj.uuid.clone(),
                    alias: vmobj.alias.clone(),
                    event,
                };

                // this may get too hot
                let r = loggers.lock().unwrap();
                match r.get(&log.event.zone()) {
                    Some((events, _)) => {
                        events.send(log).unwrap();
                    }
                    None => warn!("log event seen for zone with no loggers"),
                }
            }
        })
        .expect("fan_out thread spawn failed.");

    // open the cfw device
    let mut device = IpfevDevice::new("/dev/ipfev")?;
    info!("now reading cfw events...");

    let mut buf = [0; BUFSIZE];

    loop {
        let mut offset = 0;

        let size = device
            .read_events(&mut buf)
            .context("failed to read from ipfev device")?;

        while offset < size {
            // XXX: Support other/unknown event types
            let event = parser::traffic_event(&buf).unwrap().1;
            offset += event.len();
            log_tx.send(event).unwrap();
        }
    }

    // main returns a result so we can use "?" even though the loop above stops us from ever
    // reaching this return value
    #[allow(unreachable_code)]
    Ok(())
}
