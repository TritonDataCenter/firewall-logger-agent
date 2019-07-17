// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Copyright 2019 Joyent, Inc.

use std::collections::HashMap;
use std::sync::{Arc, Barrier};
use std::thread;

use crossbeam::sync::ShardedLock;
use vminfod_client::{Changes, VminfodEvent, Zone};

pub type Vmobjs = Arc<ShardedLock<HashMap<Zonedid, Zone>>>;
pub type Zonedid = u32;

/// Inserts or updates an existing vmobj into a given `Vmobjs`
fn insert_vmobj(zone: Zone, vmobjs: &Vmobjs) {
    let mut w = vmobjs.write().unwrap();
    w.insert(zone.zonedid, zone);
}

/// Search through a vminfod changes payload and see if the alias was a part of the update
fn alias_changed(changes: &[Changes]) -> bool {
    changes.iter().any(|change| {
        change
            .path
            .first()
            // double map_or because path is a `Vec<Option<String>>`
            .map_or(false, |v| v.as_ref().map_or(false, |a| a == "alias"))
    })
}

/// Start a vminfod watcher thread that will keep a `Vmobjs` object up-to-date.
/// This function will block until the spawned thread has processed the `Ready` event from vminfod
pub fn start_vminfod(vmobjs: Vmobjs) -> thread::JoinHandle<()> {
    let version = env!("CARGO_PKG_VERSION");
    let b = Arc::new(Barrier::new(2));
    let b2 = Arc::clone(&b);
    let handle = thread::Builder::new()
        .name("vminfod_event_processor".to_owned())
        .spawn(move || {
            info!("starting vminfod thread");
            let mut init = true;
            let (r, _) = vminfod_client::start_vminfod_stream(version);
            for event in r.iter() {
                match event {
                    VminfodEvent::Ready(event) => {
                        let raw_vms = event.vms;
                        let vms: Vec<Zone> = serde_json::from_str(&raw_vms)
                            .expect("failed to parse vms payload from vminfod");
                        let mut w = vmobjs.write().unwrap();
                        for vm in vms {
                            w.insert(vm.zonedid, vm);
                        }
                        debug!("vminfod ready event processed");
                        // Barriers reset after wait is called n times. Since this thread won't be
                        // spawned multiple times we should only call wait on the barrier during
                        // initialization.
                        if init {
                            b2.wait();
                            init = false;
                        }
                    }
                    VminfodEvent::Create(event) => insert_vmobj(event.vm, &vmobjs),
                    VminfodEvent::Modify(event) => {
                        if alias_changed(&event.changes) {
                            debug!(
                                "alias changed for {} ({}), updating vmobj mapping",
                                &event.vm.uuid, &event.vm.zonedid
                            );
                            insert_vmobj(event.vm, &vmobjs);
                        }
                    }
                    // Nothing to be done with deletes currently. We don't modify `Vmobjs` since
                    // cfw event logs in various processing queues may not have made it to disk
                    // yet. We may eventually want to signal a logger that it's okay to shutdown.
                    VminfodEvent::Delete(_) => (),
                }
            }
            // TODO TRITON-1754: implement retry logic here, until then just panic
            panic!("vminfod event stream closed");
        })
        .expect("vminfod client thread spawn failed.");

    // Block until we process the very first "Ready" event from vminfod
    b.wait();
    handle
}
