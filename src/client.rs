use crate::*;
use std::io::{Read, Write};
use std::net;

pub struct Client {
	pub ipv6_prefix: [u8; 12],
	pub server_address: net::SocketAddr,
	pub name: [u8; 16],
}

impl Client {
	pub fn new() -> Self {
		Self {
			ipv6_prefix: [0; 12],
			server_address: net::SocketAddr::new(net::IpAddr::V4(net::Ipv4Addr::LOCALHOST), 5434),
			name: *b"stupid_tunnel\0\0\0",
		}
	}

	pub fn run(self) -> Result<!, RunError> {

		let mut buf = [0; 0x10000];

		debug!("Connecting to server");
		let mut server = net::TcpStream::connect(self.server_address)
			.map_err(RunError::ConnectError)?;

		debug!("Creating interface");
		let mut tun = tun::Tun::new(&self.name[..15]).unwrap();

		debug!("Adding IP address");
		tun.add_ipv6_address(net::Ipv6Addr::new(0xabcd, 0xef00, 0, 0, 0, 0, 0, 0x1001));

		'lol: loop {
			let len = tun.read(&mut buf).unwrap();

			let mut buf = &buf[..len];
			while !buf.is_empty() {
				match ip::IPv6Header::from_raw(&buf[..len]) {
					Ok((header, extra)) => {
						dbg!(header);
						if header.next_header == 6 {
							// TCP
							let (pkt, opt, data) = tcp::TcpHeader::from_raw_ipv6(extra, header.source_address(), header.destination_address()).unwrap();

							let mut out = [0; 0x10000];
							if pkt.flags.synchronize() {
								let (conn, out) = tcp::Tcp6Connection::new(header, pkt, opt, 2380923, &mut out);
								tun.write(out).unwrap();
							}
						} else if header.next_header == 17 {
							// UDP

							let (uh, extra) = udp::UDPHeader::from_raw_ipv6(extra, header.source_address(), header.destination_address()).unwrap();
							let data = &extra[..usize::from(uh.data_length())];
							let _ = dbg!(header, uh, core::str::from_utf8(data));

							let addr = &header.destination_address().octets()[12..];
							let dh = stupid::StupidDataHeader::new(
								<[u8; 4]>::try_from(addr).unwrap().try_into().unwrap(),
								uh.destination_port(),
								uh.data_length()
							);

							let mut buf = [0; 0x10000];
							let mut w = &mut buf[..];
							w[..dh.as_ref().len()].copy_from_slice(dh.as_ref());
							w = &mut w[dh.as_ref().len()..];
							w[..data.len()].copy_from_slice(data);
							let len = dh.as_ref().len() + data.len();

							server.write_all(&buf[..len]).unwrap();
						}
						buf = &extra[usize::from(header.payload_length())..];
					}
					Err(e) => { dbg!(e); break },
				}
			}
		}
	}
}

#[derive(Debug)]
pub enum RunError {
	ConnectError(std::io::Error),
}
