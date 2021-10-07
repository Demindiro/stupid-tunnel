use crate::*;
use stupid::StupidType;
use std::collections::hash_map::{HashMap, Entry};
use std::io::{Read, Write};
use std::net::{SocketAddr, SocketAddrV4, Ipv4Addr, SocketAddrV6, Ipv6Addr};

pub struct Client {
	pub ipv6_prefix: [u8; 12],
	pub server_address: net::SocketAddr,
	pub name: [u8; 16],
}

impl Client {
	pub fn new() -> Self {
		Self {
			ipv6_prefix: [0; 12],
			server_address: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 5434),
			name: *b"stupid_tunnel\0\0\0",
		}
	}

	pub fn run(self) -> Result<!, RunError> {
		let tcp_connections = HashMap::new();
		let init_seq_n = 2930232;
		let init_seq_n_offt = 239020923;

		const TUN_TOKEN: usize = 0x00_0000;
		const STUPID_TOKEN: usize = 0x10_0000;

		let mut poll = mio::Poll::new().unwrap();

		debug!("Connecting to server");
		let mut stupid = stupid::StupidClient::new(self.server_address)
			.map_err(RunError::ConnectError)?;
		poll.registry()
			.register(&mut stupid, mio::Token(STUPID_TOKEN), mio::Interest::READABLE)
			.unwrap();

		debug!("Creating interface");
		let mut tun = tun::Tun::new(&self.name[..15]).unwrap();
		debug!("Adding IP address");
		let local_address = Ipv6Addr::new(0xabcd, 0xef00, 0, 0, 0, 0, 0, 0x1001);
		tun.add_ipv6_address(local_address);
		poll.registry()
			.register(&mut tun, mio::Token(TUN_TOKEN), mio::Interest::READABLE)
			.unwrap();

		let mut events = mio::Events::with_capacity(1024);

		let mut state = State {
			local_address,
			init_seq_n,
			init_seq_n_offt,
			tun,
			stupid,
			tcp_connections,
		};

		loop {
			debug!("TCP sockets: {}", state.tcp_connections.len());
			poll.poll(&mut events, None).unwrap();
			for e in &events {
				match e.token() {
					mio::Token(TUN_TOKEN) => {
						state.handle_tun();
					}
					mio::Token(STUPID_TOKEN) => {
						state.handle_stupid();
					}
					_ => unreachable!(),
				}
			}
		}

	}
}

struct State {
	local_address: Ipv6Addr,
	init_seq_n: u32,
	init_seq_n_offt: u32,
	tun: tun::Tun,
	stupid: stupid::StupidClient,
	tcp_connections: HashMap<u16, tcp::Tcp6Connection>,
}

impl State {
	fn handle_tun(&mut self) {
		let mut buf = [0; 0x10000];
		let len = self.tun.read(&mut buf).unwrap();
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
						let s_port = tcp.source();
						let addr = SocketAddrV4::new(d_ip, d_port);

						let (src6, dst6) = (header.source_address(), header.destination_address());
						let src4: [u8; 4] = src6.octets()[12..].try_into().unwrap();
						let dst4: [u8; 4] = dst6.octets()[12..].try_into().unwrap();

						let k = (
							SocketAddrV4::new(src4.into(), tcp.source()),
							SocketAddrV4::new(dst4.into(), tcp.destination()),
						);

						let mut out = [0; 0x10000];

						match self.tcp_connections.entry(tcp.source()) {
							Entry::Occupied(mut e) => {
								let mut remove = false;
								match e.get_mut().receive(tcp, data, &mut out).unwrap() {
									tcp::Response::Acknowledge(r) => {
										debug!("acknowledge");
										self.tun.write(r).unwrap();
									},
									tcp::Response::Finish(r) => {
										debug!("closing TCP {} -> {}", s_port, addr);
										self.tun.write(r).unwrap();
										remove = true;
									},
									tcp::Response::Finished(r) => {
										debug!("closed TCP {} -> {}", s_port, addr);
										self.tun.write(r).unwrap();
										remove = true;
									},
									tcp::Response::None => (),
								}
								if !data.is_empty() {
									self.stupid.send(stupid::StupidType::TCP, addr, s_port, data).unwrap();
								}
								if remove {
									self.stupid.send(StupidType::TcpFinish, addr, s_port, &[]).unwrap();
									e.remove();
								}
							}
							Entry::Vacant(e) => {
								let ip: [u8; 4] = header.destination_address().octets()[12..].try_into().unwrap();
								let addr = SocketAddrV4::new(ip.into(), d_port);
								let out = if tcp.flags.synchronize() {
									self.stupid.send(StupidType::TcpConnect, addr, s_port, &[]).unwrap();
									let (conn, out) = tcp::Tcp6Connection::new(header, tcp, opt, self.init_seq_n, &mut out);
									self.init_seq_n = self.init_seq_n.wrapping_add(self.init_seq_n_offt);
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
								self.tun.write(out).unwrap();
							}
						}
					} else if header.next_header == 17 {
						// UDP

						let (uh, extra) = udp::UDPHeader::from_raw_ipv6(extra, header.source_address(), header.destination_address()).unwrap();
						let data = &extra[..usize::from(uh.data_length())];

						let d_port = uh.destination_port();
						let s_port = uh.source_port();
						let addr = SocketAddrV4::new(d_ip, d_port);

						self.stupid.send(stupid::StupidType::UDP, addr, s_port, data).unwrap();
					}
					buf = &extra[usize::from(header.payload_length())..];
				}
				Err(e) => { dbg!(e); break },
			}
		}
	}

	fn handle_stupid(&mut self) {
		let mut buf = [0; 0x10000];
		let mut out = [0; 0x10000];
		let (h, data, _) = self.stupid.receive(&mut buf).unwrap();

		match h.ty() {
			Ok(StupidType::UDP) => {
				let mut addr = [0; 16];
				addr[..12].copy_from_slice(&self.local_address.octets()[..12]);
				addr[12..].copy_from_slice(&h.remote().ip().octets());
				let addr6 = SocketAddrV6::new(addr.into(), h.remote().port(), 0, 0);
				let local6 = SocketAddrV6::new(self.local_address, h.local(), 0, 0);

				let udp = udp::UDPHeader::new_ipv6(addr6, local6, data).unwrap();
				let ip = ip::IPv6Header::new(udp.length(data).unwrap(), 17, 255, *addr6.ip(), self.local_address);

				out[..ip.byte_len()].copy_from_slice(ip.as_ref());
				out[ip.byte_len()..][..udp.byte_len()].copy_from_slice(udp.as_ref());
				out[ip.byte_len()..][udp.byte_len()..][..data.len()].copy_from_slice(data);

				self.tun.write(&out).unwrap();
			}
			Ok(StupidType::TcpConnect) => (), // TODO only send SYN,ACK on receiving this
			Ok(StupidType::TCP) => {
				let mut addr = [0; 16];
				addr[..12].copy_from_slice(&self.local_address.octets()[..12]);
				addr[12..].copy_from_slice(&h.remote().ip().octets());

				let conn = self.tcp_connections.get_mut(&h.local()).unwrap();
				let out = conn.send(data, &mut out).unwrap();
				self.tun.write(&out).unwrap();
			}
			Ok(StupidType::TcpFinish) => {
				debug!("closing TCP {} -> {}", h.local(), h.remote());
				let conn = self.tcp_connections.get_mut(&h.local()).unwrap();
				let out = conn.close(data, &mut out).unwrap();
				self.tun.write(&out).unwrap();
			}
			Err(_) => todo!(),
		}
	}
}

#[derive(Debug)]
pub enum RunError {
	ConnectError(std::io::Error),
}
