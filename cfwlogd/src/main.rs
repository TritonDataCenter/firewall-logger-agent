use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex};
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
use ipf::IpfevDevice;
use parser::CfwEvent;
use serde::Serialize;
use vminfod::Zone;

#[derive(Debug, Serialize)]
struct LogEvent {
    #[serde(flatten)]
    event: CfwEvent,
    vm: String,
    alias: String,
}

type Zonedid = u32;
type Vmobjs = Arc<ShardedLock<HashMap<Zonedid, Zone>>>;
type Loggers = Arc<Mutex<HashMap<Zonedid, (Sender<LogEvent>, Sender<bool>)>>>;

/// Start a vminfod watcher thread that will keep a `Vmobjs` object up-to-date.
/// This function will block until the spawned thread has processed the `Ready` event from vminfod
fn start_vminfod(vmobjs: Vmobjs, loggers: Loggers) -> thread::JoinHandle<()> {
    #[allow(clippy::mutex_atomic)] // this lint doesn't realize we are using it with a CondVar
    let waiter = Arc::new((Mutex::new(false), Condvar::new()));
    let waiter2 = waiter.clone();
    let handle = thread::Builder::new()
        .name("vminfod_event_processor".to_string())
        .spawn(move || {
            info!("starting vminfod thread");
            let &(ref lock, ref cvar) = &*waiter2;
            let (r, _) = vminfod::start_vminfod_stream();
            for event in r.iter() {
                // We got a ready event that has the initial zones on the CN
                if let Some(raw_vms) = event.vms {
                    let mut ready = lock.lock().unwrap();
                    // make sure we don't see another ready event in the future
                    assert_eq!(*ready, false);
                    let vms: Vec<Zone> = serde_json::from_str(&raw_vms).unwrap();
                    let mut w = vmobjs.write().unwrap();
                    let mut loggers = loggers.lock().unwrap();
                    for vm in vms {
                        if vm.firewall_enabled {
                            let channels =
                                logger::start_logger(vm.owner_uuid.clone(), vm.uuid.clone());
                            loggers.insert(vm.zonedid, channels);
                            info!("started loggger for zone {}", &vm.uuid);
                        }
                        w.insert(vm.zonedid, vm);
                    }
                    *ready = true;
                    debug!("ready event processed");
                    cvar.notify_one();
                }
                // Standard vminfod event
                if let Some(vmobj) = event.vm {
                    debug!("processing event for zone: {:?}", &vmobj);
                    let mut w = vmobjs.write().unwrap();
                    let mut loggers = loggers.lock().unwrap();
                    if vmobj.firewall_enabled && !loggers.contains_key(&vmobj.zonedid) {
                        let channels =
                            logger::start_logger(vmobj.owner_uuid.clone(), vmobj.uuid.clone());
                        loggers.insert(vmobj.zonedid, channels);
                        info!("started loggger for zone {}", &vmobj.uuid);
                    }
                    w.insert(vmobj.zonedid, vmobj);
                }
            }
            // TODO: implement retry logic here, until then just panic
            panic!("vminfod event stream closed");
        })
        .expect("vminfod client thread spawn failed.");

    let &(ref lock, ref cvar) = &*waiter;
    let mut ready = lock.lock().unwrap();
    while !*ready {
        ready = cvar.wait(ready).unwrap();
    }

    handle
}

fn main() -> Result<(), Error> {
    // setup our logger
    pretty_env_logger::init();

    /// This is hardcoded until `/dev/ipfev` provides an ioctl interface that can tell us a few
    /// things like size of the largest event type, and size of the internal ring buffer
    const BUFSIZE: usize = 81920;
    let mapping: HashMap<Zonedid, Zone> = HashMap::new();
    let vmobjs = Arc::new(ShardedLock::new(mapping));
    let channels: HashMap<Zonedid, (Sender<LogEvent>, Sender<bool>)> = HashMap::new();
    let loggers = Arc::new(Mutex::new(channels));

    let _vminfod_handle = start_vminfod(vmobjs.clone(), loggers.clone());

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
