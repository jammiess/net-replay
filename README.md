# Network Replay
Capture and replay a TCP connection.

This library is intended to make a network replay attack or just replaying some captured network traffic as easy as
possible. Currently, only TCP/IP traffic is supported.

Using this library may require root privileges or specific network capabilities when running the final compiled binary
depending on what features are used.

## Installation
Just add
```
net-replay = "0.1"
```
to your `Cargo.toml`.

## Usage

### Capture Network Traffic
**Note**: This module of the library is only supported on Linux.

Example of capturing all traffic destined for IP address 8.8.8.8

```rs
use std::net::Ipv4Addr;
use std::thread::sleep;
use std::time::Duration;
use std::fs::File;
use std::io::BufWriter;

use net_replay::capture::{Filter, Capture};
use net_replay::ip::{IpPacket, write_pcap_file};

const TARGET_IP: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);

struct CustomFilter;

impl Filter for CustomFilter {
  fn filter(&mut self, packet: &IpPacket) -> bool {
    if packet.dest == TARGET_IP {
      true
    } else {
      false
    }
  }
}

fn main() {
  // Initialize a new capture on interface 'eno1' with our custom filter that will only keep packets destined for
  // ip address 8.8.8.8
  let cap = Capture::new(Box::new(CustomFilter), Some("eno1".into()));
  let cap_handle = cap.start().unwrap();
  // Let capture run for 5 seconds
  sleep(Duration::from_secs(5));
  let packets = cap_handle.end().unwrap();
  // Write the packets to a pcap file
  let pcap_file = File::create("capture.pcap").unwrap();
  let mut writer = BufWriter::new(pcap_file);
  write_pcap_file(&packets, &mut writer).unwrap();
}
```

Example of replaying some captured packets

```rs
use std::net::Ipv4Addr;
use std::fs::File;
use std::io::BufReader;
use std::net::TcpStream;

use net_replay::replay::{Arbiter, Action, Replayer};
use net_replay::ip::{IpPacket, read_pcap_file, TcpFlags};

// Will be used to decide what to do for each packet in the replay
// Can cause the replayer to send or read
//
// This arbiter will replay a connection between a host ip address of 8.8.8.8
// and a client address of 192.168.0.1
struct CustomArbiter;

impl Arbiter for CustomArbiter {
  fn decide(&mut self, packet: &IpPacket) -> Action {
    const CLIENT: Ipv4Addr = Ipv4Addr::new(192, 168, 0, 1);
    const HOST: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);

    if packet.source == CLIENT && packet.dest == HOST && packet.payload.flags.contains(TcpFlags::PSH) {
      return Action::Send(None);
    }

    if packet.source == HOST && packet.dest == CLIENT && packet.payload.flags.contains(TcpFlags::PSH) {
      return Action::Recv(None);
    }
    // If packet is not from the replay we want just pass
    Action::Pass
  }

  // No internal state so don't need to udpate
  fn update(&mut self, _data: &[u8], _original: &[u8]) {}
}

fn main() {
  let capture = File::open("capture.pcap").unwrap();
  let mut reader = BufReader::new(capture);
  let packets = read_pcap_file(&mut reader).unwrap();
  // Replay capture to a different address
  let socket = TcpStream::connect("9.9.9.9:80").unwrap();
  let replayer = Replayer::new(socket, packets, Box::new(CustomArbiter));
  let _orignal_socket = replayer.replay().unwrap();
}
```
