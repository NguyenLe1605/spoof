use etherparse::{err::ReadError, PacketBuilder};
use etherparse::{Ethernet2Header, Icmpv6Header, Ipv6Header};
use futures::StreamExt;
use libc::{
    c_int, c_void, sendto, setsockopt, sockaddr, sockaddr_in6, socket, socklen_t, AF_INET6,
    IPPROTO_IPV6, IPPROTO_UDP, IPV6_HDRINCL, SOCK_RAW,
};
use pcap::{Active, Capture, Device, Packet, PacketCodec, PacketStream};
use spoof::Iface;
use std::os::fd::AsRawFd;
use std::{error::Error, mem::size_of_val, net::Ipv6Addr, str::FromStr};

struct BoxCodec;
impl PacketCodec for BoxCodec {
    type Item = Box<[u8]>;

    fn decode(&mut self, packet: Packet) -> Self::Item {
        packet.data.into()
    }
}

unsafe fn send_raw_ip_pkt(dest: Ipv6Addr, buffer: &[u8]) {
    let mut dest_info: sockaddr_in6 = std::mem::zeroed();
    let enable: c_int = 1;

    // create a raw socket
    let sock: c_int = socket(AF_INET6, SOCK_RAW, IPPROTO_UDP);
    assert!(sock >= 0);
    let set = setsockopt(
        sock,
        IPPROTO_IPV6,
        IPV6_HDRINCL,
        (&enable) as *const c_int as *const c_void,
        size_of_val(&enable) as socklen_t,
    );
    assert!(set >= 0);

    dest_info.sin6_family = AF_INET6 as u16;
    dest_info.sin6_port = 0;
    dest_info.sin6_addr.s6_addr.copy_from_slice(&dest.octets());

    let result = sendto(
        sock,
        buffer.as_ptr() as *const c_void,
        buffer.len() as libc::size_t,
        0,
        &dest_info as *const sockaddr_in6 as *const sockaddr,
        std::mem::size_of::<sockaddr_in6>() as u32,
    );
    assert!(result >= 0);
}

fn new_stream<D: Into<Device>>(
    device: D,
) -> Result<(PacketStream<Active, BoxCodec>, Iface), pcap::Error> {
    // get the default Device
    let device: Device = device.into();
    let name = device.name.clone();
    println!("Using device {}", name);

    let mut cap = Capture::from_device(device)?
        .immediate_mode(true)
        .open()?
        .setnonblock()?;
    if name.as_str() == "tap0" {
        cap.filter("dst host 2001:db8:100::1", false)?;
    } else if name.as_str() == "veth0" {
        cap.filter("dst host 2001:db8:100::2", false)?;
    }
    let iface = Iface::new(cap.as_raw_fd(), name)?;
    cap.filter("udp or icmp6[0] = 135 or icmp6[0] = 136", false)?;
    let stream = cap.stream(BoxCodec)?;
    Ok((stream, iface))
}

// fn craft_ra(iface: &Iface, payload: &[u8]) -> Result<Vec<u8>, ReadError> {
//     // parse the packet => ipv6 packet
//     let (ether_hdr, payload) = Ethernet2Header::from_slice(payload)?;
//     let (ip_hdr, payload) = Ipv6Header::from_slice(payload)?;
//     let (icmp_hdr, _payload) = Icmpv6Header::from_slice(payload)?;
//
//     // craft the router advertisement packet to send back
//     Ok(vec![])
// }

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let src: Ipv6Addr = Ipv6Addr::from_str("fd00::1").unwrap();
    let dest: Ipv6Addr = Ipv6Addr::from_str("fd00::2").unwrap();
    let builder = PacketBuilder::ipv6(src.octets(), dest.octets(), 47).udp(12345, 51280);
    let payload = b"hello\n";
    let mut result = Vec::<u8>::with_capacity(builder.size(payload.len()));
    builder.write(&mut result, payload).unwrap();

    // unsafe {
    //     send_raw_ip_pkt(dest, &result);
    // }

    println!("start capturing");
    let (mut stream, iface) = new_stream("tap0")?;
    let (mut veth, _) = new_stream("veth0")?;
    println!("{}", iface.hwaddr);

    // let mut cap = Capture::from_device("veth0")?
    //     .immediate_mode(true)
    //     .open()?
    //     .setnonblock()?;
    // cap.filter("icmp6[0] = 135", false)?;
    // let veth_stream = cap.stream(BoxCodec)?;

    loop {
        tokio::select! {
            data = stream.next() => {
                let data = data.unwrap()?;
                let cap = veth.capture_mut();
                cap.sendpacket(data)?;
            }
            data = veth.next() => {
                let data = data.unwrap()?;
                let cap = stream.capture_mut();
                cap.sendpacket(data)?;
            }
        }
    }
}
