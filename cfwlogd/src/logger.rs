use crossbeam::channel;
use serde::Serialize;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::thread;
use std::time::Duration;

// TODO:
// create firewall log dir if it doesn't exist

fn _start_logger<T>(
    customer: String,
    vm: String,
    events: channel::Receiver<T>,
    signal: channel::Receiver<bool>,
) -> thread::JoinHandle<()>
where
    T: Serialize + Send + 'static,
{
    thread::Builder::new()
        .name(format!("logger-{}", &vm))
        .spawn(move || {
            // XXX currently truncating the log file at startup
            // and currently crashing if the file cant be created
            let dir = format!("/var/log/firewall/{}/{}", &customer, &vm);
            std::fs::create_dir_all(dir).unwrap();
            let mut fd = File::create(format!(
                "/var/log/firewall/{}/{}/current.log",
                &customer, &vm
            ))
            .unwrap();
            let mut logger = BufWriter::new(fd);

            loop {
                // check if we need to rotate the log
                if signal.try_recv().is_ok() {
                    logger.flush().unwrap();
                    // XXX actually rotate the log
                    fd = File::create(format!(
                        "/var/log/firewall/{}/{}/current.log",
                        &customer, &vm
                    ))
                    .unwrap();
                    logger = BufWriter::new(fd);
                }
                //check if we have an event to process
                match events.recv_timeout(Duration::from_millis(200)) {
                    Ok(e) => {
                        // XXX figure out how to signal to the main thread that we failed to write
                        // so that everyone else can close flush their files?
                        writeln!(&mut logger, "{}", serde_json::to_string(&e).unwrap()).unwrap()
                    }
                    // hit a timeout looking for events so loop again
                    Err(e) if e.is_timeout() => (),
                    // Other side disconnected so we shutdown
                    _ => {
                        logger.flush().unwrap();
                        info!("{} logger shutting down", &customer);
                        break;
                    }
                }
            }
        })
        .expect("failed to spawn IpfReader thread")
}

pub fn start_logger<T>(customer: String, vm: String) -> (channel::Sender<T>, channel::Sender<bool>)
where
    T: Serialize + Send + 'static,
{
    let (event_tx, event_rx) = channel::unbounded();
    let (signal_tx, signal_rx) = channel::bounded(1);
    let _handle = _start_logger(customer, vm, event_rx, signal_rx);
    (event_tx, signal_tx)
}
