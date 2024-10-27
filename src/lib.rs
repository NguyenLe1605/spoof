use libc::{c_char, c_int, c_ulong, sockaddr, IF_NAMESIZE, SIOCGIFHWADDR};
use std::{
    io::{self, Error, ErrorKind},
    os::fd::RawFd,
};

const IFREQUNIONSIZE: usize = 24;

#[repr(C)]
struct IfReqUnion {
    data: [u8; IFREQUNIONSIZE],
}

impl IfReqUnion {
    fn as_sockaddr(&self) -> sockaddr {
        let mut s = sockaddr {
            sa_family: u16::from_be((self.data[0] as u16) << 8 | (self.data[1] as u16)),
            sa_data: [0; 14],
        };

        // basically a memcpy
        for (i, b) in self.data[2..16].iter().enumerate() {
            s.sa_data[i] = *b as i8;
        }

        s
    }

    fn as_int(&self) -> c_int {
        c_int::from_be(
            (self.data[0] as c_int) << 24
                | (self.data[1] as c_int) << 16
                | (self.data[2] as c_int) << 8
                | (self.data[3] as c_int),
        )
    }
}

impl Default for IfReqUnion {
    fn default() -> IfReqUnion {
        IfReqUnion {
            data: [0; IFREQUNIONSIZE],
        }
    }
}

#[repr(C)]
pub struct IfReq {
    ifr_name: [c_char; IF_NAMESIZE],
    union: IfReqUnion,
}

impl IfReq {
    ///
    /// Create an interface request struct with the interface name set
    ///
    pub fn with_if_name(if_name: &str) -> io::Result<IfReq> {
        let mut if_req = IfReq::default();

        if if_name.len() >= if_req.ifr_name.len() {
            return Err(Error::new(ErrorKind::Other, "Interface name too long"));
        }

        // basically a memcpy
        for (a, c) in if_req.ifr_name.iter_mut().zip(if_name.bytes()) {
            *a = c as i8;
        }

        Ok(if_req)
    }

    pub fn ifr_hwaddr(&self) -> sockaddr {
        self.union.as_sockaddr()
    }

    pub fn ifr_ifindex(&self) -> c_int {
        self.union.as_int()
    }
}

impl Default for IfReq {
    fn default() -> IfReq {
        IfReq {
            ifr_name: [0; IF_NAMESIZE],
            union: IfReqUnion::default(),
        }
    }
}

extern "C" {
    fn ioctl(fd: c_int, request: c_ulong, ifreq: *mut IfReq) -> c_int;
}

#[derive(Debug, Default)]
pub struct HwAddr {
    a: u8,
    b: u8,
    c: u8,
    d: u8,
    e: u8,
    f: u8,
}

/// Representation of a MAC address
impl HwAddr {
    pub fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> HwAddr {
        HwAddr { a, b, c, d, e, f }
    }

    /// Returns the six eight-bit integers that make up this address.
    pub fn octets(&self) -> [u8; 6] {
        [self.a, self.b, self.c, self.d, self.e, self.f]
    }
}

impl std::fmt::Display for HwAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mac = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.a, self.b, self.c, self.d, self.e, self.f,
        );

        write!(f, "{}", mac)
    }
}

/// ioctl operations on a hardware interface
pub struct Iface {
    pub name: String,
    pub hwaddr: HwAddr,
}

impl Iface {
    pub fn new<S: Into<String>>(fd: RawFd, if_name: S) -> io::Result<Self> {
        let name: String = if_name.into();
        let if_req = IfReq::with_if_name(&name)?;
        let mut req: Box<IfReq> = Box::new(if_req);
        if unsafe { ioctl(fd, SIOCGIFHWADDR, &mut *req) } == -1 {
            return Err(Error::last_os_error());
        }
        let ifr_hwaddr = req.ifr_hwaddr();
        let hwaddr = HwAddr {
            a: ifr_hwaddr.sa_data[0] as u8,
            b: ifr_hwaddr.sa_data[1] as u8,
            c: ifr_hwaddr.sa_data[2] as u8,
            d: ifr_hwaddr.sa_data[3] as u8,
            e: ifr_hwaddr.sa_data[4] as u8,
            f: ifr_hwaddr.sa_data[5] as u8,
        };

        Ok(Iface { name, hwaddr })
    }
}
