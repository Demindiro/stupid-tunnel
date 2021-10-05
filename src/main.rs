mod icmp;
mod ip;
mod udp;
mod tun;
mod ifreq;

use std::io::{Read, Write};

fn main() {
	let mut tun = tun::Tun::new(b"stupid_tunnel").unwrap();
	let mut buf = [0; 0x10000];

	loop {
		let len = tun.read(&mut buf).unwrap();

		let mut buf = &buf[..len];
		while !buf.is_empty() {
			match ip::IPv6Header::from_raw(&buf[..len]) {
				Ok((header, extra)) => {
					dbg!(header);
					if header.next_header == 17 {

						let (uh, extra) = udp::UDPHeader::from_raw_ipv6(extra, header.source_address(), header.destination_address()).unwrap();
						let data = &extra[..usize::from(uh.data_length())];
						let _ = dbg!(header, uh, core::str::from_utf8(data));

						let mut ip_h = *header;
						ip_h.set_source_address(header.destination_address());
						ip_h.set_destination_address(header.source_address());
						//let ip_h = *header;

						let (src_p, dst_p) = (uh.destination_port(), uh.source_port());
						let udp_h = udp::UDPHeader::new_ipv6(ip_h.source_address(), src_p, ip_h.destination_address(), dst_p, &data).unwrap();

						let mut buf = [0; 0x10000];
						let mut w = &mut buf[..];
						w[..ip_h.as_ref().len()].copy_from_slice(ip_h.as_ref());
						w = &mut w[ip_h.as_ref().len()..];
						w[..udp_h.as_ref().len()].copy_from_slice(udp_h.as_ref());
						w = &mut w[udp_h.as_ref().len()..];
						w[..data.len()].copy_from_slice(data);
						let len = ip_h.as_ref().len() + udp_h.as_ref().len() + data.len();

						{
							let (ip, e) = ip::IPv6Header::from_raw(&buf[..len]).unwrap();
							let (udp, e) = udp::UDPHeader::from_raw_ipv6(e, ip.source_address(), ip.destination_address()).unwrap();
							let _ = dbg!(ip, udp, core::str::from_utf8(e));
						}

						tun.write(&buf[..len]).unwrap();
					} else if header.next_header == 58 {
						let (icmp, extra) = icmp::ICMPv6Header::from_raw(extra).unwrap();
						dbg!(icmp);
					}
					buf = &extra[usize::from(header.payload_length())..];
				}
				Err(e) => { dbg!(e); break },
			}
		}
	}
}
