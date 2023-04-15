use std::io::Write;
use std::net::IpAddr;
use pcap::Device;

const APPLICATION_NAME: &str = "net-replay";

pub trait PcapngEncode {
    fn encode(&self, file: &mut impl Write) -> std::io::Result<()>;
    fn length(&self) -> usize;
}

struct PcapngOption {
    pub typ: u16,
    pub len: u16,
    pub dat: Vec<u8>,
}

impl PcapngOption {
    pub const SHB_USERAPPL: u16 = 4;
    pub const IF_NAME: u16 = 2;
    pub const IF_IP4ADDR: u16 = 4;
    pub const IF_IP6ADDR: u16 = 5;
}

impl PcapngEncode for PcapngOption {
    #[inline]
    fn length(&self) -> usize {
        4 + self.dat.len()
    }

    fn encode(&self, file: &mut impl Write) -> std::io::Result<()> {
        file.write_all(&self.typ.to_ne_bytes())?;
        file.write_all(&self.len.to_ne_bytes())?;
        file.write_all(&self.dat)
    }
}

struct SHB {
    options: Vec<PcapngOption>,
}

impl SHB {
    const SHB_MAGIC: u32 = 0x0A0D0D0A;
    const ORDER_MAGIC: u32 = 0x1A2B3C4D;
    const MAJOR_VER: u16 = 1;
    const MINOR_VER: u16 = 0;

    pub fn new() -> Self {
        let mut app_string = String::from(APPLICATION_NAME).into_bytes();
        while app_string.len() % 4 != 0 {
            app_string.push(0);
        }
        let appname = PcapngOption {
            typ: PcapngOption::SHB_USERAPPL,
            len: (app_string.len() + 4) as u16,
            dat: app_string,
        };
        Self {
            options: vec![appname],
        }
    }
}

impl PcapngEncode for SHB {
    fn length(&self) -> usize {
        self.options.iter().map(|o| o.length()).sum::<usize>() + 28
    }

    fn encode(&self, file: &mut impl Write) -> std::io::Result<()> {
        let length = self.length() as u32;
        let section_len = self.options.iter().map(|o| o.length()).sum::<usize>() as u64;
        file.write_all(&Self::SHB_MAGIC.to_ne_bytes())?;
        file.write_all(&length.to_ne_bytes())?;
        file.write_all(&Self::ORDER_MAGIC.to_ne_bytes())?;
        file.write_all(&Self::MAJOR_VER.to_ne_bytes())?;
        file.write_all(&Self::MINOR_VER.to_ne_bytes())?;
        file.write_all(&section_len.to_ne_bytes())?;
        for option in &self.options {
            option.encode(file)?;
        }
        file.write_all(&length.to_ne_bytes())
    }
}

struct InterfaceBlock {
    options: Vec<PcapngOption>,
}

impl InterfaceBlock {
    fn from_device(dev: &Device) -> Self {
        let mut options = Vec::<PcapngOption>::new();
        options.push(PcapngOption { typ: PcapngOption::IF_NAME, len: dev.name.len() as u16, dat: dev.name.clone().into_bytes() });
        for address in &dev.addresses {
            // Need netmask to make a valid option
            let netmask = match address.netmask {
                Some(a) => {
                    match a {
                        IpAddr::V4(net) => net,
                        _ => continue,
                    }
                },
                None => continue,
            };
            if address.netmask.is_none() {
                continue;
            }
            if let IpAddr::V4(addr) = address.addr {
                let mut addr_bytes = Vec::<u8>::new();
                addr_bytes.extend(addr.octets());
                addr_bytes.extend(netmask.octets());
                options.push(PcapngOption {
                    typ: PcapngOption::IF_IP4ADDR,
                    len: 8,
                    dat: addr_bytes,
                });
            }
        }
        Self {
            options
        }
    }
}
