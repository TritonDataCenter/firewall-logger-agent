use crate::parser::{self, CfwEvent};
use crate::zones::{Vmobjs, Zonedid};
use bytes::Bytes;
use crossbeam::channel::{self, Receiver, SendError, Sender};
use serde::Serialize;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

#[derive(Debug, Serialize)]
struct LogEvent<'a> {
    #[serde(flatten)]
    event: CfwEvent,
    vm: &'a str,
    alias: &'a str,
}

pub struct Logger {
    handle: thread::JoinHandle<()>,
    sender: channel::Sender<Bytes>,
    flush: channel::Sender<bool>,
}

impl Logger {
    pub fn send(&self, b: Bytes) -> Result<(), SendError<Bytes>> {
        self.sender.send(b)
    }

    pub fn flush(&self) -> Result<(), SendError<bool>> {
        self.flush.send(true)
    }
}

fn open_file(vm: String, customer: String) -> std::io::Result<File> {
    let path: PathBuf = ["/var/log/firewall", &customer, &vm, "current.log"]
        .iter()
        .collect();

    // we know the unwrap is safe because we just created the path above
    std::fs::create_dir_all(path.parent().unwrap())?;

    // TODO instead of truncating the existing file we should try to stat it first and open it or
    // rotate it before creating the new file
    Ok(File::create(path)?)
}

fn _start_logger(
    vm: String,
    customer: String,
    vmobjs: Vmobjs,
    events: channel::Receiver<Bytes>,
    signal: channel::Receiver<bool>,
) -> thread::JoinHandle<()> {
    thread::Builder::new()
        .name("logger".to_string())
        .spawn(move || {
            let mut file = match open_file(vm, customer) {
                Ok(file) => file,
                Err(e) => {
                    // XXX CMON?
                    error!("failed to open log file: {}", e);
                    return;
                }
            };

            let mut writer = BufWriter::new(file);

            for bytes in events.iter() {
                // force the event type for now
                let event = parser::traffic_event(&bytes).unwrap().1;
                let vmobjs = vmobjs.read().unwrap();
                let vmobj = vmobjs
                    .get(&event.zone())
                    .expect("we should have the zonedid:uuid mapping already");
                let event = LogEvent {
                    event,
                    vm: &vmobj.uuid,
                    alias: &vmobj.alias,
                };
                writeln!(&mut writer, "{}", serde_json::to_string(&event).unwrap()).unwrap();
            }
        })
        .expect("failed to spawn IpfReader thread")
}

/// Return a Logger if we have information for the zone already otherwise return None
pub fn start_logger(zonedid: Zonedid, vmobjs: Vmobjs) -> Option<Logger> {
    let (event_tx, event_rx) = channel::unbounded();
    let (signal_tx, signal_rx) = channel::bounded(1);
    let vms = vmobjs.read().unwrap();
    if let Some(vm) = vms.get(&zonedid) {
        let handle = _start_logger(
            vm.uuid.clone(),
            vm.owner_uuid.clone(),
            vmobjs.clone(),
            event_rx,
            signal_rx,
        );
        return Some(Logger {
            handle,
            sender: event_tx,
            flush: signal_tx,
        });
    }
    None
}
