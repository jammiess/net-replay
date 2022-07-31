use std::env::args;
use std::thread::sleep;
use std::time::Duration;

use std::fs::File;
use std::io::BufWriter;

use net_replay::capture::{Capture, NoFilter};
use net_replay::ip::write_pcap_file;

fn main() {
    let iface = args().nth(1);
    let iface = match iface {
        Some(i) => i,
        None => {
            println!("Pass interface name as first parameter");
            return;
        }
    };

    let cap = Capture::new(Box::new(NoFilter), Some(iface)).start().unwrap();
    sleep(Duration::from_secs(5));
    let data = cap.end().unwrap();

    let file = File::create("capture.pcap").unwrap();
    let mut writer = BufWriter::new(file);
    write_pcap_file(&data, &mut writer).unwrap();
}
