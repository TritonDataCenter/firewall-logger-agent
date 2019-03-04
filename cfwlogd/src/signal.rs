// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Copyright 2019 Joyent, Inc.

use crossbeam::channel::Sender;
use libc::c_int;
use std::sync::{Arc, Barrier};
use std::thread;

fn signal_handler(tx: Sender<c_int>, b: Arc<Barrier>) {
    let signals = signal_hook::iterator::Signals::new(&[
        libc::SIGHUP,
        libc::SIGINT,
        libc::SIGTERM,
        libc::SIGUSR1,
        libc::SIGUSR2,
    ])
    .expect("unable to create signal handler");

    // signal handler has started
    b.wait();

    for signal in signals.forever() {
        if tx.send(signal).is_err() {
            trace!("receive half of signal handler channel is disconnected");
            break;
        }
    }
}

pub fn start_signalhandler(tx: Sender<c_int>) -> thread::JoinHandle<()> {
    let b = Arc::new(Barrier::new(2));
    let b2 = Arc::clone(&b);
    let handle = thread::Builder::new()
        .name("signal_handler".to_owned())
        .spawn(move || signal_handler(tx, b2))
        .expect("failed to spawn signal watcher thread");

    // Block until the signal handler is setup
    b.wait();
    handle
}
