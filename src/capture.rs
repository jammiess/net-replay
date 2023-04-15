//! Capture TCP packets
//!
//! [`Capture`] can be used to capture TCP traffic on an interface. Capturing traffic will start two new threads: one
//! for snooping traffic using a raw socket and another one for filtering and storing those packets.
//!
//! Each capture requires a [`Filter`] that will decide which packets will be included in the capture. That trait has a
//! single method that needs to be implemented: [`Filter::filter`].
//!
//! Once a capture is completed, a vector of all the captured packets will be returned. You can use
//! [`crate::ip::write_pcap_file`] to write the capture to a pcap file or use the [`crate::replay`] module to replay
//! that data over a TCP connection.

use crate::ip::IpPacket;

use pcap::{Capture as Pcapture, Device, Inactive};

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::thread::{spawn, JoinHandle};
use std::time::Duration;

use thiserror::Error;

/// Errors that can occur when starting a capture session
#[derive(Debug, Error)]
pub enum CaptureError {
    /// Failed to join one of the threads
    #[error("Failed to join one of the threads")]
    JoinError,
    /// Failed to find a reasonable default device
    #[error("Could not find a default device")]
    NoDevice,
    /// Failed to do a socket operation
    #[error("Failed to do a socket operation")]
    DeviceError(#[from] pcap::Error),
}

/// Trait for filtering out the kind of packet(s) you want to store
///
/// Any struct that implements this trait can be used to filter out packets during a capture.
///
/// # NOTE
/// If you want to end a capture after some packet or packet sequence has been seen, you would implement that
/// functionality in this struct. You would put some shareable condition in this struct and set it when that condition
/// is seen. The controlling thread would then know to stop the capture.
pub trait Filter: Send {
    /// Method to determine whether or not a packet will be kept or discarded
    ///
    /// Return true to keep the packet or false to discard the packet.
    fn filter(&mut self, packet: &IpPacket) -> bool;
}

/// Pre-made filter that will keep all seen packets
pub struct NoFilter;

impl Filter for NoFilter {
    fn filter(&mut self, _packet: &IpPacket) -> bool {
        true
    }
}

/// Session state struct for before the capture has started
///
/// Has all of the data needed to start a capture: the filter to use and an optional interface to bind to.
pub struct Ready {
    filter: Box<dyn Filter>,
    interface: Option<Device>,
}

/// Session state struct for an active capture
///
/// Has all of the data needed to maintain a capture: the thread handle for the snooper, the thread handle for the
/// packet store, and the signal bool to stop.
pub struct Capturing {
    snooper: JoinHandle<()>,
    store: JoinHandle<Vec<IpPacket>>,
    cond: Arc<AtomicBool>,
}

/// Capture TCP packets on an interface
pub struct Capture<T> {
    state: T,
}

impl Capture<Ready> {
    /// Create a new Capture struct with a filter and interface to capture on
    ///
    /// This simply sets up a struct without actually starting to capture.
    #[must_use]
    pub fn new(filter: Box<dyn Filter>, interface: Option<Device>) -> Self {
        Self {
            state: Ready { filter, interface },
        }
    }

    /// Start capturing packets
    ///
    /// This method will consume the object and return a new one.
    ///
    /// # Errors
    /// Will return an error if something goes wrong with creating the socket or joining a thread after a socket error
    /// has occurred.
    pub fn start(self) -> Result<Capture<Capturing>, CaptureError> {
        let (send, recv) = channel::<IpPacket>();
        let signal = Arc::new(AtomicBool::new(false));
        let cap_signal = Arc::clone(&signal);
        let capture = spawn(move || {
            let capture = Store {
                chan: recv,
                cond: cap_signal,
                store: Vec::with_capacity(1000),
                filter: self.state.filter,
            };
            capture.start()
        });

        let interface = match self.state.interface {
            Some(d) => {
                Pcapture::<Inactive>::from_device(d).map_err(|e| CaptureError::DeviceError(e))
            }
            None => match Device::lookup() {
                Ok(od) => match od {
                    Some(d) => Pcapture::<Inactive>::from_device(d)
                        .map_err(|e| CaptureError::DeviceError(e)),
                    None => Err(CaptureError::NoDevice),
                },
                Err(e) => Err(CaptureError::DeviceError(e)),
            },
        };
        let dev = match interface {
            Ok(s) => s,
            Err(e) => {
                // I believe the relaxed ordering is fine because the exact timing of the threads stopping is not
                // super important. As long as they get the message shortly after the bool is set. That should happen
                // with relaxed ordering.
                signal.store(true, Ordering::Relaxed);
                capture.join().map_err(|_| CaptureError::JoinError)?;
                return Err(e);
            }
        };

        let snoop_signal = Arc::clone(&signal);
        let snoop = spawn(move || {
            let snooper = Snooper {
                chan: send,
                cond: snoop_signal,
                dev,
            };
            snooper.start();
        });

        let cap_state = Capturing {
            snooper: snoop,
            store: capture,
            cond: signal,
        };
        Ok(Capture { state: cap_state })
    }
}

impl Capture<Capturing> {
    /// Stop capturing packets and get captured packets
    ///
    /// This will signal each thread to stop and get the captured packets.
    ///
    /// # Errors
    /// If there is an error in joining the thread that stores the packets, an error will be returned. No error in
    /// joining the snooping thread will be returned as long as the store thread returns properly.
    pub fn end(self) -> Result<Vec<IpPacket>, CaptureError> {
        // The atomic bool could most likley be changed to just a pointer and some volatile reads and writes and
        // everything would still just work.
        self.state.cond.store(true, Ordering::Relaxed);
        let _cap_res = self.state.snooper.join();
        let store_res = self.state.store.join();
        store_res.map_err(|_| CaptureError::JoinError)
    }
}

struct Snooper {
    chan: Sender<IpPacket>,
    cond: Arc<AtomicBool>,
    dev: Pcapture<Inactive>,
}

impl Snooper {
    fn start(mut self) {
        self.dev = self.dev.timeout(50);
        let mut capture = match self.dev.open() {
            Ok(started) => started,
            Err(_) => return,
        };
        'recv_loop: loop {
            if self.cond.load(Ordering::Relaxed) {
                break 'recv_loop;
            }
            let packet = capture.next_packet();
            if let Ok(p) = packet {
                let eth_type = u16::from_be_bytes(p.data[12..14].try_into().unwrap());
                if eth_type != 0x0800 {
                    continue 'recv_loop;
                }
                let packet = IpPacket::parse_from_bytes(&&p.data[14..], None);
                if let Ok(p) = packet {
                    self.chan.send(p).unwrap();
                }
            }
        }
    }
}

struct Store {
    chan: Receiver<IpPacket>,
    cond: Arc<AtomicBool>,
    store: Vec<IpPacket>,
    filter: Box<dyn Filter>,
}

impl Store {
    fn start(mut self) -> Vec<IpPacket> {
        const RECV_WAIT: Duration = Duration::new(0, 50_000_000);
        'recv_loop: loop {
            if self.cond.load(Ordering::Relaxed) {
                break 'recv_loop;
            }
            let packet = self.chan.recv_timeout(RECV_WAIT);
            match packet {
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break 'recv_loop,
                Ok(ip_packet) => {
                    if self.filter.filter(&ip_packet) {
                        self.store.push(ip_packet);
                    }
                }
            }
        }
        self.store
    }
}
