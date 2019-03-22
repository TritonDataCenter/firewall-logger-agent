pub mod client;
pub mod linefeed;

use std::thread;

use client::{Client, VminfodEvent};
use crossbeam_channel::Sender;

pub fn start_vminfod_stream(sender: Sender<VminfodEvent>) -> thread::JoinHandle<()> {
    thread::Builder::new()
        .name("vminfod_client".to_string())
        .spawn(move || {
            let c = Client::new(sender);
            c.run();
        })
        .expect("vminfod client thread spawn failed.")
}
