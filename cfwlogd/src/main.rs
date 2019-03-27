use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::sync::Arc;
use std::thread;

#[macro_use]
extern crate nom;
#[macro_use]
extern crate log;

extern crate pretty_env_logger;
use crossbeam::sync::ShardedLock;
use failure::{Error, ResultExt};

mod parser;
use parser::CfwEvent;
use serde::Serialize;
use vminfod::{EventType, Zone};

#[derive(Debug, Serialize)]
struct LogEvent {
    #[serde(flatten)]
    event: CfwEvent,
    vm: String,
    alias: String,
}

type Zonedid = u32;
type Vmobjs = Arc<ShardedLock<HashMap<Zonedid, Zone>>>;

fn start_vminfod(vmobjs: Vmobjs) -> thread::JoinHandle<()> {
    thread::Builder::new()
        .name("vminfod_event_processor".to_string())
        .spawn(move || {
            info!("starting vminfod thread");
            let (r, _) = vminfod::start_vminfod_stream();
            for event in r.iter() {
                // We got a ready event that has the initial zones on the CN
                if let Some(raw_vms) = event.vms {
                    let vms: Vec<Zone> = serde_json::from_str(&raw_vms).unwrap();
                    let mut w = vmobjs.write().unwrap();
                    for vm in vms {
                        w.insert(vm.zonedid, vm);
                    }
                }
                // Standard vminfod event
                if let Some(vmobj) = event.vm {
                    match event.event_type {
                        EventType::Delete => {
                            let mut w = vmobjs.write().unwrap();
                            let _ = w.remove(&vmobj.zonedid);
                        }
                        // TODO: Look at modify events and only update if the alias changed
                        _ => {
                            let mut w = vmobjs.write().unwrap();
                            w.insert(vmobj.zonedid, vmobj);
                        }
                    }
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

    let _vminfod_handle = start_vminfod(vmobjs.clone());

    // open the cfw device
    let mut fd = File::open("/dev/ipfev").context("failed to open ipfev device")?;
    let mut buf = vec![0; BUFSIZE];

    loop {
        let mut offset = 0;

        let size = fd
            .read(&mut buf)
            .context("failed to read from ipfev device")?;
        if size == 0 {
            println!("read 0 bytes...exiting!");
            break;
        }

        while offset < size as usize {
            // we should just panic if the first few bytes dont look like a cfw event
            let info = parser::peek_event(&buf[offset..])
                .expect("peek at cfw event failed")
                .1;

            let iresult = match info.event_type {
                parser::CfwEvType::Unknown => {
                    warn!("unknown cfw event found: {:?}", &info);
                    offset += info.length as usize;
                    continue;
                }
                _ => parser::traffic_event(&buf),
            };

            // XXX: fan these events out to various per zone queues?

            // for now lets just print something that resembles a log line
            match iresult {
                Err(e) => println!("failed to parse event: {}", e),
                Ok((_leftover_bytes, event)) => match event {
                    CfwEvent::Traffic(ref ev) => {
                        let r = vmobjs.read().unwrap();
                        let log = LogEvent {
                            vm: r[&ev.zonedid].uuid.clone(),
                            alias: r[&ev.zonedid].alias.clone(),
                            event: event,
                        };
                        println!("{}", serde_json::to_string(&log).unwrap());
                    }
                },
            }

            offset += info.length as usize;
        }
    }
    Ok(())
}
