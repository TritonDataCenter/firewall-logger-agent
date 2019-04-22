use crossbeam::channel::Sender;
use libc::c_int;
use std::thread;

fn signal_handler(tx: Sender<c_int>) {
    let signals = signal_hook::iterator::Signals::new(&[
        libc::SIGHUP,
        libc::SIGINT,
        libc::SIGTERM,
        libc::SIGUSR1,
        libc::SIGUSR2,
    ])
    .expect("unable to create signal handler");

    for signal in signals.forever() {
        if tx.send(signal).is_err() {
            trace!("receive half of signal handler channel is disconnected");
            break;
        }
    }
}

pub fn start_signalhandler(tx: Sender<c_int>) -> thread::JoinHandle<()> {
    thread::Builder::new()
        .name("signal_handler".to_owned())
        .spawn(move || signal_handler(tx))
        .expect("failed to spawn signal watcher thread")
}
