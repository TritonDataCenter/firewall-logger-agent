// This Source Code Form is subject to the terms of the Mozilla Public
// // License, v. 2.0. If a copy of the MPL was not distributed with this
// // file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// // Copyright 2019 Joyent, Inc.

fn main() {
    // starts a new thread that sends events back over a channel
    let version = env!("CARGO_PKG_VERSION");
    let (rx, _vminfod_handle) = vminfod_client::start_vminfod_stream(version);

    // do something with each event
    for event in rx.iter() {
        println!("{:#?}", event);
    }
}
