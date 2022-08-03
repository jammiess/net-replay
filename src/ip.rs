//! Parse and export IP packets
//!
//! This module has functionality and limitations very specific to its use case. Do not use this as a general
//! purpose packet parsing module.
//!
//! This module provides functionality for parsing TCP/IP and UDP/IP packets from a raw socket and reading and writing
//! those packets from a pcap file. The functionality in this module is mainly meant as utility for the rest of the
//! library. As a user of the library, you should really only need to use [`read_pcap_file`] and [`write_pcap_file`] as
//! well as the public types.

use std::convert::From;
use std::fmt;
use std::io::{Read, Write};
use std::mem::transmute;
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime};

use bitflags::bitflags;
use thiserror::Error;

/// Magic value for a pcap file
const PCAP_MAGIC: u32 = 0xA1B2_3C4D;

/// PCAP magic of the opposite endianness
const PCAP_BAD_ENDIANNESS: u32 = 0x4D3C_B2A1;

/// Errors that can occur when parsing an ip header
#[derive(Debug, Error)]
pub enum IpParseErr {
    /// IP packet was not version 4. Contains the parsed version.
    #[error("Found version {0}, expected 4")]
    Version(u8),
    /// IP packet encapsulated an unsupported protocol
    #[error("Found protocol {0}")]
    Proto(u8),
    /// Not enough bytes to be an IP header. Minimum of 20. Contains size of passed buffer.
    #[error("IPv4 header is 20 bytes, only passed a buffer of size {0}")]
    Size(usize),
    /// Error occured when parsing the TCP portion of the payload.
    #[error("Failed to parse the TCP payload")]
    Tcp(#[from] TcpParseErr),
    /// Failed to parse the underlying udp packet
    #[error("Error occurred while parsing UDP payload")]
    Udp(#[from] UdpParseErr),
    /// IP header contained options. This struct doesn't support those.
    #[error("This library doesn't support ip options")]
    Options,
    /// Size field in ip header is larger than passed in slice or smaller than the IP header
    #[error("Size field in packet is larger than data passed in ({0})")]
    InvalidSize(usize),
    /// IHL field was not in a valid range
    #[error("IHL field was outside valid range of [6, 15] ({0})")]
    InvalidIHL(usize),
    /// Error reading from IO
    #[error("Encountered IO error")]
    IOError(#[from] std::io::Error),
    /// Endianness of pcap file does not match native endianness
    #[error("PCAP file endianness does not match")]
    EndianError,
    /// Found a bad magic value in the pcap file
    #[error("Pcap file had bad magic: {0:0X}")]
    BadMagic(u32),
    /// PCAP file is invalid in some way
    #[error("Pcap file is invalid")]
    PcapInvalid,
    /// PCAP file does not have enough data or a size field was corrupted
    #[error("Pcap file too small")]
    PcapFileSize,
}

/// Data that the IP packet encapsulates
///
/// An IP packet can encapsulate many different types of data. Each possible encapsulated type that this library
/// supports is represented by this enum.
///
/// This enum is marked as non-exhaustive as more underlying types may be added in future versions of the library.
#[non_exhaustive]
#[derive(Debug)]
pub enum DataType {
    TCP(TcpPacket),
    UDP(UdpDatagram),
}

impl DataType {
    /// Write the underlying protocol data to the pcap file
    ///
    /// # Errors
    /// Will return any io errors that occur
    pub fn pcap_write<W: Write>(&self, f: &mut W) -> std::io::Result<()> {
        match self {
            Self::TCP(p) => p.pcap_write(f),
            Self::UDP(p) => p.pcap_write(f),
        }
    }

    pub fn get_proto_num(&self) -> u8 {
        match self {
            Self::TCP(_) => 6,
            Self::UDP(_) => 17,
        }
    }

    pub fn get_payload(&self) -> &Vec<u8> {
        match self {
            Self::TCP(p) => &p.data,
            Self::UDP(p) => &p.payload,
        }
    }
}

impl From<TcpPacket> for DataType {
    fn from(packet: TcpPacket) -> Self {
        Self::TCP(packet)
    }
}

impl From<UdpDatagram> for DataType {
    fn from(packet: UdpDatagram) -> Self {
        Self::UDP(packet)
    }
}

/// IP header and its associated TCP data
#[derive(Debug)]
pub struct IpPacket {
    /// Differentiated Services Code Point
    ///
    /// This field is mainly used for real time protocols to determine what kind of data is in
    /// the packet. Should be left alone.
    pub dscp: u8,
    /// Explicit Congestion Notification
    ///
    /// Used to indicate network congestion without having to drop packets.
    pub ecn: u8,
    /// Total Length
    ///
    /// Length of the IP packet and associated data. Minimum size of 20 bytes for the header.
    /// This field is encoded as a u16 so it has a maximum value of 65535.
    pub len: usize,
    /// Identification
    ///
    /// Primarily used for identifying a group of fragments.
    pub id: u16,
    /// Flags
    ///
    /// A bit field used for controllig and identifying a fragmented IP packet.
    pub flags: u8,
    /// Fragment Offset
    ///
    /// Specifies the offset of a fragment with respect to the beginning of the fragment. Units
    /// are 64 bits.
    pub frag_off: u16,
    /// Time to Live
    ///
    /// Originally specified the time to live for a packet in seconds. It is now generally used
    /// as a hop count.
    pub ttl: u8,
    // Only support TCP so don't worry about that field
    // pub protocol: u8,
    /// Header Checksum
    ///
    /// Checksum over the header of the IP packet.
    pub checksum: u16,
    /// Source Address
    ///
    /// The IP address from which this packet was sent.
    pub source: Ipv4Addr,
    /// Destination Address
    ///
    /// The IP address where this packet is being sent to.
    pub dest: Ipv4Addr,
    /// IP options
    ///
    /// Any options the IP header may have. This field will only contain a vector if the IHL field is in the range
    /// [6, 15].
    pub options: Option<Vec<u8>>,
    /// Encapsulated data
    ///
    /// The payload can be any of the supported types in the [`DataType`] enum
    pub payload: DataType,
    /// Time packet received at
    ///
    /// This field is populated at the time the packet was parsed at and may not perfectly reflect the time at which
    /// the packet was actually received on the interface.
    pub recv_time: SystemTime,
}

impl IpPacket {
    /// Parse an ip header and TCP packet out of a stream of bytes
    ///
    /// This method is meant to be called with data read from the raw socket. It will read out any IPv4 TCP packet
    /// and parse the containing data.
    ///
    /// # Errors
    /// Returns an error if an unsupported packet type is passed in. Those cases are an IPv6 packet, non-TCP packet,
    /// or a slice smaller than 20 bytes.
    ///
    /// # Panics
    /// This method may panic. If the system time is before the [`SystemTime::UNIX_EPOCH`] time, then a panic will
    /// occur.
    pub fn parse_from_bytes(
        data: &dyn AsRef<[u8]>,
        time: Option<SystemTime>,
    ) -> Result<Self, IpParseErr> {
        // This should never fail. The only times that this would fail is if the current system time is from before the
        // unix epoch. I feel safe in assuming that the system time will never drift that far.
        let recv_time = match time {
            None => SystemTime::now(),
            Some(t) => t,
        };
        let data = data.as_ref();
        if data.len() < 20 {
            return Err(IpParseErr::Size(data.len()));
        }
        let version = data[0] >> 4;
        if version != 4 {
            return Err(IpParseErr::Version(version));
        }
        let ihl = data[0] & 0xf;
        if !(5..=15).contains(&ihl) {
            return Err(IpParseErr::InvalidIHL(ihl as usize));
        }
        if ihl as usize * 4 > data.len() {
            return Err(IpParseErr::InvalidIHL(ihl as usize));
        }
        let dscp = (data[1] & 0xfc) >> 2;
        let ecn = data[1] & 0x3;
        let len = u16::from_be_bytes(data[2..4].try_into().unwrap()) as usize;
        if len > data.len() {
            return Err(IpParseErr::InvalidSize(len));
        }
        let id = u16::from_be_bytes(data[4..6].try_into().unwrap());
        let flags = data[6] >> 5;
        let frag_off: u16 = (u16::from(data[6] & 0x1f) << 8) + u16::from(data[7]);
        let ttl = data[8];
        let proto = data[9];
        let checksum = u16::from_be_bytes(data[10..12].try_into().unwrap());
        let source = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
        let dest = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
        let end: usize;
        let options = if ihl == 5 {
            end = 20;
            None
        } else {
            end = ihl as usize * 4;
            Some(data[20..end].to_vec())
        };
        if len < end {
            return Err(IpParseErr::Size(len));
        }
        let payload: DataType = match proto {
            6 => TcpPacket::parse_from_bytes(&&data[end..len])?.into(),
            17 => UdpDatagram::parse_from_bytes(&&data[end..len])?.into(),
            p => return Err(IpParseErr::Proto(p)),
        };
        Ok(IpPacket {
            dscp,
            ecn,
            len,
            id,
            flags,
            frag_off,
            ttl,
            checksum,
            source,
            dest,
            options,
            payload,
            recv_time,
        })
    }

    /// Write an IP packet to a pcap file
    ///
    /// # Errors
    /// Returns an error if any of the writes fail.
    pub fn pcap_write<W: Write>(&self, file: &mut W) -> std::io::Result<()> {
        let diff = self
            .recv_time
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        let secs = diff.as_secs() as u32;
        let nanos = diff.as_nanos() as u32;
        file.write_all(&secs.to_ne_bytes())?;
        file.write_all(&nanos.to_ne_bytes())?;
        let size = self.len as u32;
        file.write_all(&size.to_ne_bytes())?;
        file.write_all(&size.to_ne_bytes())?;
        let ihl = self.options.clone().map_or(0, |v| v.len() >> 2) as u8;
        let version_ihl = 0x40 | (ihl + 5);
        file.write_all(&version_ihl.to_be_bytes())?;
        let dscp_ecn = (self.dscp << 2) | self.ecn;
        file.write_all(&dscp_ecn.to_be_bytes())?;
        let total_len = self.len as u16;
        file.write_all(&total_len.to_be_bytes())?;
        file.write_all(&self.id.to_be_bytes())?;
        let frag_off = ((self.flags as u16) << 13) | self.frag_off;
        file.write_all(&frag_off.to_be_bytes())?;
        file.write_all(&self.ttl.to_be_bytes())?;
        file.write_all(&self.payload.get_proto_num().to_be_bytes())?;
        file.write_all(&self.checksum.to_be_bytes())?;
        file.write_all(&self.source.octets())?;
        file.write_all(&self.dest.octets())?;
        if let Some(ref o) = self.options {
            file.write_all(o)?;
        }
        self.payload.pcap_write(file)?;
        Ok(())
    }
}

impl fmt::Display for IpPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IPv4 Header")
            .field("Total length", &self.len)
            .field("Source addr", &self.source)
            .field("Dest addr", &self.dest)
            .field("Payload", &self.payload)
            .finish_non_exhaustive()
    }
}

bitflags! {
    /// TCP flag bits
    ///
    /// Represent the control bits in a TCP packet that help manage connection state
    #[repr(transparent)]
    pub struct TcpFlags: u16 {
        /// ECN-nonce - concealment protection
        const NS = 0b1_0000_0000;
        /// Congestion window reduced
        const CWR = 0b1000_0000;
        /// ECN-Echo
        ///
        /// If the SYN flag is set, it means the TCP peer is ECN capable.
        ///
        /// If the SYN flag is clear, indicates that there is network congestion.
        const ECE = 0b100_0000;
        /// Indicates that the urget pointer field is set
        const URG = 0b10_0000;
        /// Indicates that the acknowledgement field of the header is significant
        const ACK = 0b10000;
        /// Indicates that there is data that needs to be forwarded to the application
        const PSH = 0b1000;
        /// Reset the connection
        const RST = 0b100;
        /// Synchronize sequence numbers
        const SYN = 0b10;
        /// Indicates that the packet is the last one from the sender
        const FIN = 0b1;
    }
}

/// TCP header and its associated data
#[derive(Clone)]
pub struct TcpPacket {
    /// Source port
    pub source: u16,
    /// Destination port
    pub dest: u16,
    /// Sequence number
    pub seq: u32,
    /// Acknowledge number
    pub ack: u32,
    /// TCP flags such as reset, ack, push, etc.
    pub flags: TcpFlags,
    /// Window size
    pub window: u16,
    /// Checksum value
    pub checksum: u16,
    /// Urgent pointer
    pub urg: u16,
    /// Option data if there was any
    pub option_data: Option<Vec<u8>>,
    /// TCP data
    pub data: Vec<u8>,
}

impl fmt::Debug for TcpPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TCP Packet")
            .field("Source Addr", &self.source)
            .field("Dest Addr", &self.source)
            .field("Data Len", &self.data)
            .finish_non_exhaustive()
    }
}

/// Errors that can occur when parsing a TCP packet
#[derive(Error, Debug)]
pub enum TcpParseErr {
    /// Not enough bytes to be a TCP packet. Minimum of 20 bytes.
    #[error("Data is too small to be a TCP packet {0}")]
    Size(usize),
    /// The value of the data offset field is too large for passed in data
    #[error("Header has invalid size field {0}")]
    InvalidSize(usize),
}

impl TcpPacket {
    /// Parse a TCP packet and data out of a stream of bytes
    ///
    /// This method is meant to be called from the [`IpPacket::parse_from_bytes`] method.
    ///
    /// # Errors
    /// Returns an error if there are not enough bytes for a valid TCP packet.
    pub fn parse_from_bytes(data: &dyn AsRef<[u8]>) -> Result<Self, TcpParseErr> {
        let data = data.as_ref();
        if data.len() < 20 {
            return Err(TcpParseErr::Size(data.len()));
        }
        let source = u16::from_be_bytes(data[0..2].try_into().unwrap());
        let dest = u16::from_be_bytes(data[2..4].try_into().unwrap());
        let seq = u32::from_be_bytes(data[4..8].try_into().unwrap());
        let ack = u32::from_be_bytes(data[8..12].try_into().unwrap());
        let data_off = data[12] >> 4;
        if data_off as usize * 4 > data.len() {
            return Err(TcpParseErr::InvalidSize(data_off as usize));
        }
        let mut flag_bits: u16 = u16::from(data[12] & 1) << 8;
        flag_bits += u16::from(data[13]);
        // SAFETY: These should have the same exact structure in memory.
        // The high order bits from the packet that don't match up to flags are masked out
        // so this should be completely fine.
        let flags: TcpFlags = unsafe { transmute(flag_bits) };
        let window = u16::from_be_bytes(data[14..16].try_into().unwrap());
        let checksum = u16::from_be_bytes(data[16..18].try_into().unwrap());
        let urg = u16::from_be_bytes(data[18..20].try_into().unwrap());
        let option_data: Option<Vec<u8>> = if data_off > 5 {
            Some(data[20..(data_off as usize) * 4].to_vec())
        } else {
            None
        };
        let data = data[(data_off as usize) * 4..].to_vec();
        Ok(TcpPacket {
            source,
            dest,
            seq,
            ack,
            flags,
            window,
            checksum,
            urg,
            option_data,
            data,
        })
    }

    /// Write packet to a pcap file
    ///
    /// Writes a tcp packet to a pcap file. This is for use by the [`write_pcap_file`] function.
    ///
    /// # Errors
    /// Will return an error if any of the writes fail.
    pub fn pcap_write<W: Write>(&self, file: &mut W) -> std::io::Result<()> {
        file.write_all(&self.source.to_be_bytes())?;
        file.write_all(&self.dest.to_be_bytes())?;
        file.write_all(&self.seq.to_be_bytes())?;
        file.write_all(&self.ack.to_be_bytes())?;
        let mut data_off = self.option_data.clone().map_or(0_usize, |v| v.len() >> 2);
        data_off += 5;
        data_off <<= 4;
        data_off |= (self.flags.bits >> 8) as usize;
        let data_off_ns = data_off as u8;
        file.write_all(&data_off_ns.to_be_bytes())?;
        let options = (self.flags.bits & 0xFF) as u8;
        file.write_all(&options.to_be_bytes())?;
        file.write_all(&self.window.to_be_bytes())?;
        file.write_all(&self.checksum.to_be_bytes())?;
        file.write_all(&self.urg.to_be_bytes())?;
        if let Some(ref v) = self.option_data {
            file.write_all(v)?;
        }
        file.write_all(&self.data)?;
        Ok(())
    }
}

/// Errors that can happen while parsing a UDP packet
#[derive(Debug, Error)]
pub enum UdpParseErr {
    /// Size in header is too large for passed in slice
    #[error("Size in header did not match size of data")]
    SizeMismatch,
    /// The slice is less than 8 bytes, the minimum UDP packet size
    #[error("Passed in data is not large enough for UDP header")]
    MissingHeader,
}

/// UDP header and associated data
pub struct UdpDatagram {
    /// Source port
    pub source: u16,
    /// Destination port
    pub dest: u16,
    /// Packet checksum
    pub checksum: u16,
    /// UDP data
    pub payload: Vec<u8>,
}

impl fmt::Debug for UdpDatagram {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UDP Packet")
            .field("Source Port", &self.source)
            .field("Dest Port", &self.dest)
            .field("Data len", &self.payload.len())
            .finish_non_exhaustive()
    }
}

impl UdpDatagram {
    /// Parse a udp packet from a slice of bytes
    ///
    /// This method will not check the checksum.
    ///
    /// # Errors
    /// This method will return an error if the slice is less than 8 bytes or if the size of the length field is larger
    /// than the length of the slice.
    pub fn parse_from_bytes(data: &dyn AsRef<[u8]>) -> Result<Self, UdpParseErr> {
        let data = data.as_ref();
        if data.len() < 8 {
            return Err(UdpParseErr::MissingHeader);
        }
        let source = u16::from_be_bytes(data[0..2].try_into().unwrap());
        let dest = u16::from_be_bytes(data[2..4].try_into().unwrap());
        let length = u16::from_be_bytes(data[4..6].try_into().unwrap()) as usize;
        let checksum = u16::from_be_bytes(data[6..8].try_into().unwrap());
        if !(8..data.len()).contains(&length) {
            return Err(UdpParseErr::SizeMismatch);
        }
        let payload = data[8..length].to_vec();
        Ok(Self {
            source,
            dest,
            checksum,
            payload,
        })
    }

    /// Write packet to a pcap file
    ///
    /// # Errors
    /// Will return any io errors that occur.
    pub fn pcap_write<W: Write>(&self, f: &mut W) -> std::io::Result<()> {
        f.write_all(&self.source.to_be_bytes())?;
        f.write_all(&self.dest.to_be_bytes())?;
        f.write_all(&self.payload.len().to_be_bytes())?;
        f.write_all(&self.checksum.to_be_bytes())?;
        f.write_all(&self.payload)?;
        Ok(())
    }
}

/// Write a packet capture out to a pcap file
///
/// It is recommended to pass a buf writer to this function as many small writes will be made while writing the file.
///
/// # Errors
/// If any IO errors occur while writing the file, they will be returned.
pub fn write_pcap_file<W: Write>(
    packets: &Vec<IpPacket>,
    pcap_file: &mut W,
) -> std::io::Result<()> {
    pcap_file.write_all(&PCAP_MAGIC.to_ne_bytes())?;
    pcap_file.write_all(&2_u16.to_ne_bytes())?;
    pcap_file.write_all(&4_u16.to_ne_bytes())?;
    pcap_file.write_all(&0_u32.to_ne_bytes())?;
    pcap_file.write_all(&0_u32.to_ne_bytes())?;
    pcap_file.write_all(&0xFFFF_u32.to_ne_bytes())?;
    pcap_file.write_all(&101_u32.to_ne_bytes())?;

    for packet in packets {
        packet.pcap_write(pcap_file)?;
    }

    pcap_file.flush()?;
    Ok(())
}

/// Parse packets from a pcap file
///
/// Parses all of the IP/TCP packets from a pcap file. Any packet that isn't able to be parsed properly will just be
/// skipped. This function assumes that the pcap file uses the same endianness as the system.
///
/// # Errors
/// If the pcap file is not in the expected format, then an error will be returned.
///
/// # Panics
/// This function calls unwrap on some slices to turn them into an array of a specific size. This should never fail
/// because the slicing is for that specific size.
pub fn read_pcap_file<R: Read>(pcap_file: &mut R) -> Result<Vec<IpPacket>, IpParseErr> {
    let mut pcap_data = Vec::new();
    let data_size = pcap_file.read_to_end(&mut pcap_data)?;
    if data_size < 24 {
        return Err(IpParseErr::PcapFileSize);
    }
    let magic = u32::from_ne_bytes(pcap_data[0..4].try_into().unwrap());
    if magic == PCAP_BAD_ENDIANNESS {
        return Err(IpParseErr::EndianError);
    }
    if magic != PCAP_MAGIC {
        return Err(IpParseErr::BadMagic(magic));
    }
    // Check the major version field
    if u16::from_ne_bytes(pcap_data[4..6].try_into().unwrap()) != 2 {
        return Err(IpParseErr::PcapInvalid);
    }
    // Check the minor version field
    if u16::from_ne_bytes(pcap_data[6..8].try_into().unwrap()) != 4 {
        return Err(IpParseErr::PcapInvalid);
    }
    // Skip some fields that we don't care about
    // Check to see if the pcap file is for raw IP packets
    if u32::from_ne_bytes(pcap_data[20..24].try_into().unwrap()) != 101 {
        return Err(IpParseErr::PcapInvalid);
    }
    let mut packets = Vec::new();
    let mut index: usize = 24;
    while index + 16 < data_size {
        let seconds = u32::from_ne_bytes(pcap_data[index..index + 4].try_into().unwrap()) as u64;
        let nanos = u32::from_ne_bytes(pcap_data[index + 4..index + 8].try_into().unwrap());
        let time = Some(
            SystemTime::UNIX_EPOCH
                .checked_add(Duration::new(seconds, nanos))
                .unwrap(),
        );
        let packet_size =
            u32::from_ne_bytes(pcap_data[index + 8..index + 12].try_into().unwrap()) as usize;
        if index + 16 + packet_size > data_size {
            break;
        }
        let packet = IpPacket::parse_from_bytes(&&pcap_data[index + 16..][..packet_size], time);
        if let Ok(p) = packet {
            packets.push(p);
        }
        index += 16;
        index += packet_size;
    }
    Ok(packets)
}

#[cfg(test)]
mod ip_testing {
    use super::*;
    use std::io::Cursor;

    const EMPTY_PACKET_BYTES: &[u8] = &[
        0x45, 0x00, 0x00, 0x28, 0xde, 0xad, 0x00, 0x00, 0x00, 0x06, 0xbe, 0xef, 0x12, 0x34, 0x56,
        0x78, 0xab, 0xcd, 0xef, 0x12, 0x43, 0x21, 0xfe, 0xdc, 0xde, 0xad, 0xbe, 0xef, 0x69, 0x69,
        0x69, 0x69, 0x50, 0x00, 0x10, 0x00, 0x99, 0x99, 0x00, 0x00,
    ];

    #[test]
    fn empty_packet() {
        let packet = IpPacket::parse_from_bytes(&EMPTY_PACKET_BYTES, None).unwrap();
        assert_eq!(packet.id, 0xdead);
        assert_eq!(packet.checksum, 0xbeef);
        assert_eq!(packet.len, 40);
    }

    #[test]
    fn test_pcap_write() {
        let packet = IpPacket::parse_from_bytes(&EMPTY_PACKET_BYTES, None).unwrap();
        let mut file = Cursor::new(Vec::new());
        packet.pcap_write(&mut file).unwrap();
        let buffer = file.into_inner();
        assert_eq!(buffer[8], 40);
        assert_eq!(buffer[9], 0);
        assert_eq!(buffer[10], 0);
        assert_eq!(buffer[11], 0);
        assert_eq!(buffer[12], 40);
        assert_eq!(buffer[13], 0);
        assert_eq!(buffer[14], 0);
        assert_eq!(buffer[15], 0);
        assert_eq!(&buffer[16..], EMPTY_PACKET_BYTES);
    }

    #[test]
    fn test_read_pcap() {
        use std::fs::File;
        let mut file = File::open("./test/test.pcap").unwrap();
        let packets = read_pcap_file(&mut file).unwrap();
        assert!(packets.len() > 0);
    }

    #[test]
    fn test_fuzz_crash_pcap_read() {
        use std::fs::File;
        let mut file =
            File::open("test/test.pcap")
                .unwrap();
        let _data = read_pcap_file(&mut file);
    }
}
