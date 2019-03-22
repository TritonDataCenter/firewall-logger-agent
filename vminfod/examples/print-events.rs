use crossbeam_channel::bounded;

fn main() {
    // We allow up to 10 events to be buffered
    let (s, r) = bounded(10);

    // starts a new thread that sends events back over a channel
    let _vminfod_handle = vminfod::start_vminfod_stream(s);

    // do something with each event
    for event in r.iter() {
        println!("{:#?}", event);
    }
}
