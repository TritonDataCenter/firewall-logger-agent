use std::sync::mpsc;

pub struct Client<T> {
    send: mpsc::Sender<T>,
}

impl<T> Client<T> {
    pub fn new(send: mpsc::Sender<T>) -> Self {
        Client { send }
    }

    pub fn run(&self) {
        // use hyper + linefeed to parse the vminfod event stream and send back the events across
        // the mpsc channel
        unimplemented!();
    }
}
