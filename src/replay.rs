//! Replay a TCP connection
//!
//! Create a [`Replayer`] struct with a vector of ip packets, a tcp socket, and an arbiter to replay a connection.
//! The replayer assumes the tcp socket is in a state ready for the previous connection to be replayed and will only
//! send packets that come from the capture. Upon the end of the replay, it will yield back the tcp socket so that
//! it can continue to be used after the replay.
//!
//! A struct implementing the [`Arbiter`] trait is needed to customize the packets sent during a replay. An arbiter
//! can be used to decide which packets will be sent and change the exact contents of the packet. For each packet in
//! the capture, the replayer will call [`Arbiter::decide`] with the packet as a parameter to know what to do with the
//! packet. That method returns a variant of the [`Action`] enum which will specify what will happen. You can take a
//! look at the docs for that enum to figure out what all of the possible actions are.
//!
//! Additionally, the arbiter trait requires the [`Arbiter::update`] method which will be passed response data from the
//! connection. That method allows the arbiter to potentially update any internal state with response data.
//!
//! See the [`AddressArbiter`] struct for an example implementation of the trait.

use crate::ip::{DataType, IpPacket, TcpFlags};

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, TcpStream};
use std::num::NonZeroUsize;

/// Enum for what to do with a packet from a capture
#[derive(Debug)]
pub enum Action {
    /// Ignore packet and move on to looking at the next packet in the capture
    Pass,
    /// Send the payload of the packet on the connection
    ///
    /// If the payload should be modified, include the modified version with this enum variant.
    Send(Option<Vec<u8>>),
    /// Receive data from the connection
    ///
    /// If there is a specific amount of data expected from the service, include how much as part of this enum variant.
    /// Otherwise, the [`Replayer`] will attempt to read up to 65536 bytes in a single read call before moving on to
    /// the next packet.
    Recv(Option<NonZeroUsize>),
    /// Stop the replay
    ///
    /// This variant is for stopping a replay early before all of the packets in a capture have been looked at.
    Break,
}

/// Trait for managing a replay
///
/// [`Replayer`] requires having a struct that implements this trait to know what to do with each packet.
///
/// See [`AddressArbiter`] for an example implementation of this trait.
pub trait Arbiter {
    /// Decide what to do with a packet
    ///
    /// Given a packet from a capture, decide to send the packet, receive data from the connection, or move on to
    /// looking to the next packet in the capture. See [`Action`] for the possible actions.
    ///
    /// The [`Action::Break`] variant does not necessarily need to every be returned. Once all packets from the capture
    /// have been iterated through, the replay will automatically stop.
    fn decide(&mut self, packet: &IpPacket) -> Action;

    /// Update state based on received data
    ///
    /// If a packet was marked as receive, then the data received on the connection will get passed to this method
    /// along with what the original data was.
    fn update(&mut self, data: &[u8], original: &[u8]);
}

/// Arbiter that solely replays a connection based on the IP addresses in a packet
///
/// This arbiter will send a packet anytime it sees an IP packet where the host is the destination and the client is
/// the source and recv when the IP addresses are the opposite way around.
///
/// If the TCP connection ended in someway - a packet with the reset or fin flag set was seen - then this arbiter will
/// break from the replay and the socket will be returned to the user.
pub struct AddressArbiter {
    client: Ipv4Addr,
    host: Ipv4Addr,
}

impl AddressArbiter {
    /// Create a new Address Arbiter with the given host and client addresses
    #[must_use]
    pub fn new(client: Ipv4Addr, host: Ipv4Addr) -> Self {
        Self { client, host }
    }
}

impl Arbiter for AddressArbiter {
    fn decide(&mut self, packet: &IpPacket) -> Action {
        const CONN_END: TcpFlags = TcpFlags::RST.union(TcpFlags::FIN);

        // If the packet is not a TCP packet just skip it
        if let DataType::TCP(ref payload) = packet.payload {
            // Check if this is a packet that should be sent in the replay
            if self.host == packet.dest && self.client == packet.source {
                // Has the right destination and source, now check that actually data was sent
                if payload.flags.contains(TcpFlags::PSH) {
                    return Action::Send(None);
                }
                // Check if connection got reset and break if it did
                if payload.flags.intersects(CONN_END) {
                    return Action::Break;
                }
            }

            // Check if the client should receive some data from the host
            if self.host == packet.source && self.client == packet.dest {
                // Check if any data was actually sent in this packet
                if payload.flags.contains(TcpFlags::PSH) {
                    return Action::Recv(None);
                }
                // Check if the connection got reset and break if it did
                if payload.flags.intersects(CONN_END) {
                    return Action::Break;
                }
            }
        }

        // Default action is to pass
        Action::Pass
    }

    // AddressArbiter has no internal state that needs to be updated so this method is just a no op
    fn update(&mut self, _data: &[u8], _original: &[u8]) {}
}

/// Replay a TCP connection with optionally modified data
///
/// Create a new replay by capturing data using [`crate::capture::Capture`] or by making a raw IP capture in wireshark.
/// That capture can then be replayed.
///
/// This struct requires an already connected tcp socket to work. The socket should be already connected to the service
/// you wish to replay the connection to. The socket and connection state should be in some form of initialized state
/// that is ready for the replay. That initialization might just be connecting to the service.
pub struct Replayer {
    socket: TcpStream,
    packets: Vec<IpPacket>,
    arbiter: Box<dyn Arbiter>,
}

impl Replayer {
    /// Create a new replayer struct
    ///
    /// The socket should already be connected and initialized to some extent.
    #[must_use]
    pub fn new(socket: TcpStream, packets: Vec<IpPacket>, arbiter: Box<dyn Arbiter>) -> Self {
        Self {
            socket,
            packets,
            arbiter,
        }
    }

    /// Replay a TCP connection
    ///
    /// Replay a TCP connection based on captured packets. This function will return the TCP socket in a still
    /// connected state.
    ///
    /// # Errors
    /// This method may return any IO error that occurs during the replay.
    pub fn replay(mut self) -> io::Result<TcpStream> {
        let mut recv_buf = Box::new([0u8; 65536]);
        for packet in &self.packets {
            match self.arbiter.decide(packet) {
                Action::Pass => {}
                Action::Send(payload) => {
                    if let Some(data) = payload {
                        self.socket.write_all(&data)?;
                    } else {
                        self.socket.write_all(packet.payload.get_payload())?;
                    }
                }
                Action::Recv(read_size) => {
                    let read_bytes: usize;
                    if let Some(size) = read_size {
                        read_bytes = size.into();
                        self.socket.read_exact(&mut recv_buf[..read_bytes])?;
                    } else {
                        read_bytes = self.socket.read(&mut recv_buf[..])?;
                    }
                    self.arbiter
                        .update(&recv_buf[..read_bytes], packet.payload.get_payload());
                }
                Action::Break => break,
            }
        }
        Ok(self.socket)
    }

    /// Get the socket out of the struct
    #[must_use]
    pub fn into_socket(self) -> TcpStream {
        self.socket
    }
}
