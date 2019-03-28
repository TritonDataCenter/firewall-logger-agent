use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

#[macro_use]
extern crate nom;
#[macro_use]
extern crate log;

extern crate pretty_env_logger;
use bytes::Bytes;
use crossbeam::channel;
use crossbeam::sync::ShardedLock;
use failure::{Error, ResultExt};

mod parser;
use parser::{CfwEvent, EventInfo};
use serde::Serialize;
use vminfod::Zone;

#[derive(Debug, Serialize)]
struct LogEvent<'a> {
    #[serde(flatten)]
    event: CfwEvent,
    vm: &'a str,
    alias: &'a str,
}

type Zonedid = u32;
type Vmobjs = Arc<ShardedLock<HashMap<Zonedid, Zone>>>;
type Waiter = Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>;

fn start_vminfod(waiter: Waiter, vmobjs: Vmobjs) -> thread::JoinHandle<()> {
    thread::Builder::new()
        .name("vminfod_event_processor".to_string())
        .spawn(move || {
            info!("starting vminfod thread");
            let &(ref lock, ref cvar) = &*waiter;
            let (r, _) = vminfod::start_vminfod_stream();
            for event in r.iter() {
                // We got a ready event that has the initial zones on the CN
                if let Some(raw_vms) = event.vms {
                    let mut ready = lock.lock().unwrap();
                    // make sure we don't see another ready event in the future
                    assert_eq!(*ready, false);
                    let vms: Vec<Zone> = serde_json::from_str(&raw_vms).unwrap();
                    let mut w = vmobjs.write().unwrap();
                    for vm in vms {
                        w.insert(vm.zonedid, vm);
                    }
                    *ready = true;
                    cvar.notify_one();
                }
                // Standard vminfod event
                if let Some(vmobj) = event.vm {
                    // XXX: for now all vminfod events result in an update to the backing store.
                    // In the future we need to look for an array of changes and only update under
                    // certain conditions.
                    //
                    // We also don't want to delete a vmobj for zone that has been deleted because
                    // there may still be logs queued up in processing threads that need the info
                    let mut w = vmobjs.write().unwrap();
                    w.insert(vmobj.zonedid, vmobj);
                }
            }
            // TODO: implement retry logic here, until then just panic
            panic!("vminfod event stream closed");
        })
        .expect("vminfod client thread spawn failed.")
}

fn main() -> Result<(), Error> {
    // Current size of the ring buffer at the time of writing this code
    const BUFSIZE: usize = 81920;

    // setup our logger
    pretty_env_logger::init();

    let mapping: HashMap<Zonedid, Zone> = HashMap::new();
    let vmobjs = Arc::new(ShardedLock::new(mapping));

    #[allow(clippy::mutex_atomic)] // this lint doesn't realize we are using it with a CondVar
    let waiter = Arc::new((Mutex::new(false), Condvar::new()));
    let _vminfod_handle = start_vminfod(waiter.clone(), vmobjs.clone());
    let &(ref lock, ref cvar) = &*waiter;
    let mut ready = lock.lock().unwrap();
    while !*ready {
        ready = cvar.wait(ready).unwrap();
    }

    // open the cfw device
    let mut fd = File::open("/dev/ipfev").context("failed to open ipfev device")?;
    info!("connected to /dev/ipfev");

    //let (log_tx, log_rx) = channel::bounded::<(EventInfo, Vec<u8>)>(1_000_000);
    let (log_tx, log_rx) = channel::unbounded::<(EventInfo, Bytes)>();

    let _logger_handle = thread::Builder::new()
        .name("logger test".to_string())
        .spawn(move || {
            // create or truncate file for testing
            let tmp = File::create("/var/tmp/cfw.log").unwrap();
            let mut logger = BufWriter::new(tmp);

            for (info, chunk) in log_rx.iter() {
                let iresult = match info.event_type {
                    parser::CfwEvType::Unknown => {
                        warn!("unknown cfw event found: {:?}", &info);
                        continue;
                    }
                    _ => parser::traffic_event(&chunk),
                };

                match iresult {
                    Err(e) => println!("failed to parse event: {}", e),
                    Ok((_leftover_bytes, event)) => match event {
                        CfwEvent::Traffic(ref ev) => {
                            let r = vmobjs.read().unwrap();
                            let log = LogEvent {
                                vm: &r[&ev.zonedid].uuid,
                                alias: &r[&ev.zonedid].alias,
                                event,
                            };
                            writeln!(&mut logger, "{}", serde_json::to_string(&log).unwrap())
                                .unwrap();
                        }
                    },
                }
            }
        })
        .expect("vminfod client thread spawn failed.");

    info!("now reading cfw events...");
    let mut drops = 0;

    loop {
        let mut buf = vec![0; BUFSIZE];
        let mut offset = 0;

        let size = fd
            .read(&mut buf)
            .context("failed to read from ipfev device")?;
        if size == 0 {
            warn!("read 0 bytes...exiting!");
            break;
        }

        // first chop off the wasted bytes
        buf.truncate(size);
        // then convert it to `Bytes` so that we can slice it up without copying the data a second
        // time
        let bytes = Bytes::from(buf);

        while offset < size as usize {
            // we should just panic if the first few bytes dont look like a cfw event
            let info = parser::peek_event(&bytes[offset..])
                .expect("peek at cfw event failed")
                .1;
            let size = info.length as usize;

            let chunk = bytes.slice(offset, offset + size);
            offset += size;

            // XXX: fan these events out to various per zone queues?
            // for now lets just send them to a thread that  prints something that resembles a log
            // line
            if log_tx.try_send((info, chunk)).is_err() {
                drops += 1;
            }
        }

        if drops > 0 {
            warn!("processing thread is full, dropped {} events", drops);
            drops = 0;
        }
    }
    Ok(())
}
