use crate::*;
use std::collections::hash_map::{HashMap, Entry};
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

		let mut tcp_connections = HashMap::<_, tcp::Tcp6Connection>::new();
		let mut init_seq_n = 2930232;
		let init_seq_n_offt = 239020923;

		let mut buf = [0; 0x10000];

		debug!("Connecting to server");
		let mut stupid = stupid::StupidClient::new(self.server_address)
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
						let d_ip = header.destination_address();
						let d_ip = net::Ipv4Addr::from(<[u8; 4]>::try_from(&d_ip.octets()[12..]).unwrap());

						if header.next_header == 6 {
							// TCP
							let (tcp, opt, data) = tcp::TcpHeader::from_raw_ipv6(extra, header.source_address(), header.destination_address()).unwrap();

							let d_port = tcp.destination();

							let k = (
								header.source_address(),
								tcp.source(),
								header.destination_address(),
								tcp.destination(),
							);

							let mut out = [0; 0x10000];

							match tcp_connections.entry(k) {
								Entry::Occupied(mut e) => {
									match e.get_mut().receive(tcp, data, &mut out).unwrap() {
										tcp::Response::Acknowledge(r) => {
											debug!("acknowledge");
											tun.write(r).unwrap();
										},
										tcp::Response::Finish(r) => {
											debug!("finish");
											tun.write(r).unwrap();
											e.remove();
										},
										tcp::Response::None => (),
									}
									if !data.is_empty() {
										stupid.send(stupid::StupidType::TCP, d_ip, d_port, data).unwrap();
									}
								}
								Entry::Vacant(e) => {
									let out = if tcp.flags.synchronize() {
										let (conn, out) = tcp::Tcp6Connection::new(header, tcp, opt, init_seq_n, &mut out);
										init_seq_n = init_seq_n.wrapping_add(init_seq_n_offt);
										e.insert(conn);
										out
									} else {
										let tcp = tcp::TcpHeader::new(
											(header.destination_address(), tcp.destination()),
											(header.source_address(), tcp.source()),
											0,
											0,
											tcp::Flags::new().set_reset(true),
											0,
											tcp::Options::NONE,
											&[],
										);
										let ip = ip::IPv6Header::new(tcp.length(&[]).unwrap(), 6, 255, header.destination_address(), header.source_address());
										out[..ip.byte_len()].copy_from_slice(ip.as_ref());
										out[ip.byte_len()..][..tcp.byte_len()].copy_from_slice(tcp.as_ref());
										&out[..ip.byte_len() + tcp.byte_len()]
									};
									tun.write(out).unwrap();
								}
							}
						} else if header.next_header == 17 {
							// UDP

							let (uh, extra) = udp::UDPHeader::from_raw_ipv6(extra, header.source_address(), header.destination_address()).unwrap();
							let data = &extra[..usize::from(uh.data_length())];

							let d_port = uh.destination_port();

							stupid.send(stupid::StupidType::UDP, d_ip, d_port, data).unwrap();
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
