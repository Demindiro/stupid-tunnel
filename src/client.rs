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
							let (pkt, opt, extra) = tcp::TcpHeader::from_raw_ipv6(extra, header.source_address(), header.destination_address()).unwrap();

							// Just ignore other types for now
							if !pkt.flags.synchronize() {
								continue 'lol;
							}

							let mut echo = None;
							for o in opt.iter() {
								if let tcp::OptionData::Timestamp { time, .. } = o {
									echo = Some(time);
									break;
								}
							}

							debug!("accept TCP");
							let mut buf = [0; 32];
							let opt = [
								tcp::OptionData::MaximumSegmentSize(1440),
								tcp::OptionData::NoOperation,
								tcp::OptionData::NoOperation,
								tcp::OptionData::Timestamp {
									time: 0,
									echo: echo.unwrap(),
								},
								tcp::OptionData::WindowScale(7),
								tcp::OptionData::NoOperation,
							];
							let opt = tcp::Options::new(opt.iter().copied(), &mut buf).unwrap();
							let seq_n = 23940324;
							let pkt = tcp::listen::accept_ipv6(pkt, header.source_address(), header.destination_address(), seq_n, 64800, opt);

							let ip = ip::IPv6Header::new(pkt.length(&[]).unwrap(), 6, header.hop_limit, header.destination_address(), header.source_address());

							let mut buf = [0; 0x10000];
							let mut w = &mut buf[..];

							// IP
							w[..ip.as_ref().len()].copy_from_slice(ip.as_ref());
							w = &mut w[ip.as_ref().len()..];
							// TCP
							w[..pkt.as_ref().len()].copy_from_slice(pkt.as_ref());
							w = &mut w[pkt.as_ref().len()..];
							// Options
							w[..opt.as_ref().len()].copy_from_slice(opt.as_ref());

							let len = ip.as_ref().len() + pkt.as_ref().len() + opt.byte_len();

							debug!("sending");
							tun.write(&buf[..len]).unwrap();
							debug!("done");
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
