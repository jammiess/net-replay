//! Capture and replay TCP connections
//!
//! Parts of this library only work on Linux. Specifically, the raw socket implementation uses Linux specific apis
//! that aren't supported on other OSes. The other parts of this library, the replay and ip packet modules, solely
//! depend on the rust standard library and can be used in any normal environment.
//!
//! This library implements a [`Raw`] socket that can be used to snoop IP packets on an interface and capture all of
//! the network traffic. That socket implementation only supports reading via [`std::io::Read`]. **This module will
//! require root privileges or raw network capabilities to work**.
//!
//! Use the [`capture`] module to capture the traffic you are interested in. **This module uses the raw socket and
//! therefore requires the same kind of privileges**.
//!
//! The [`ip`] module can be used to save and load captured packets using pcap files.
//!
//! Lastly, [`replay`] can be used to replay a captured TCP stream to any host.

pub mod ip;
#[cfg(target_os="linux")]
pub mod capture;
pub mod replay;
#[cfg(target_os="linux")]
pub mod sock;
