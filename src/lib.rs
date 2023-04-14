//! Capture and replay TCP connections
//!
//! Use the [`capture`] module to capture the traffic you are interested in. **This module uses promiscuous network
//! devices and therefore requires elevated privileges to run properly**.
//!
//! The [`ip`] module can be used to save and load captured packets using pcap files.
//!
//! Lastly, [`replay`] can be used to replay a captured TCP stream to any host.

pub use pcap::Device;
#[cfg(target_os = "linux")]
pub mod capture;
pub mod ip;
pub mod replay;
