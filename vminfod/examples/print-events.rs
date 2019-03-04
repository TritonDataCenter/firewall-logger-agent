fn main() {
    // starts a new thread that sends events back over a channel
    let (rx, _vminfod_handle) = vminfod::start_vminfod_stream();

    // do something with each event
    for event in rx.iter() {
        println!("{:#?}", event);
    }
}
