use chrono::prelude::*;
use flate2::Compression;
use flate2::write::GzEncoder;
use rand::prelude::*;
use serde::{Deserialize, Serialize};
use std::io::prelude::*;
use std::io;

#[derive(Serialize, Deserialize)]
struct Entry {
    event: String,
    time: String,
    source_ip: String,
    source_port: u16,
    destination_ip: String,
    destination_port: u16,
    protocol: String,
    rule: String,
    vm: String,
    alias: String,
}

fn main() -> io::Result<()> {
    let out = std::fs::File::create("cfwlog.gz")?;
    let mut encoder = GzEncoder::new(out, Compression::default());
    let mut i = 1_000_000;
    let mut entry = Entry {
        event: String::from("allow"),
        time: String::from(""),
        source_ip: String::from(""),
        source_port: 0,
        destination_ip: rand_ipv4(),
        destination_port: rand_port(),
        protocol: String::from("tcp"),
        rule: String::from("7f789617-84c9-c7f6-8914-c0568cdbbbd5"),
        vm: String::from("260cd903-8692-47d3-93fa-eca8ec93c3b1"),
        alias: String::from("some-friendly-name-here"),
    };

    while i != 0 {
        let utc: DateTime<Utc> = Utc::now();

        entry.time = utc.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        entry.source_ip = rand_ipv4();
        entry.source_port = rand_port();
        encoder.write_all(serde_json::to_string(&entry).unwrap().as_bytes())?;
        encoder.write_all(b"\n")?;
        i -= 1;
    }

    encoder.finish()?;
    Ok(())
}

fn rand_port() -> u16 {
    let mut rng = rand::thread_rng();

    rng.gen_range(1025, 65535)
}

fn rand_ipv4() -> String {
    let mut rng = rand::thread_rng();
    let ip: [u8; 4] = rng.gen();

    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}
