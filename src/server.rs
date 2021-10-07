use crate::*;
use crate::stupid::{StupidDataHeader, StupidType};
use std::collections::hash_map::{HashMap, Entry};
use std::io::{Error, Read, Write};
use std::net::{SocketAddr, SocketAddrV4, Ipv4Addr};
use std::time::Instant;
use mio::net::{UdpSocket, TcpListener, TcpStream};

pub struct Server {
	pub address: net::SocketAddr,
}

impl Server {
	pub fn run(self) -> Result<!, RunError> {

		debug!("Starting server");
		let mut server = TcpListener::bind(self.address).map_err(RunError::Bind)?;

		let mut poll = mio::Poll::new().unwrap();
		let reg = poll.registry();
		reg.register(&mut server, mio::Token(0), mio::Interest::READABLE).unwrap();
		let mut events = mio::Events::with_capacity(1);
		
		loop {
			debug!("Waiting for client");
			poll.poll(&mut events, None).unwrap();

			for e in &events {
				if e.token() == mio::Token(0) {
					let (stream, _) = server.accept().map_err(RunError::Accept)?;
					debug!("Accepted client");
					let _ = self.handle_client(stream);
				}
			}
		}
	}

	fn handle_client(&self, mut client: TcpStream) -> Result<!, Error> {

		const CLIENT_EVENT: usize = 0x00_0000;
		const UDP_EVENT: usize = 0x10_0000;
		const TCP_EVENT: usize = 0x20_0000;
		const EVENT_MASK: usize = !0xffff;

		let mut poll = mio::Poll::new().unwrap();
		let reg = poll.registry();
		reg.register(&mut client, mio::Token(CLIENT_EVENT), mio::Interest::READABLE).unwrap();

		let mut events = mio::Events::with_capacity(1024);

		let mut buf = [0; 0x10000];
		let mut out = [0; 0x10000];

		let mut udp_socks = HashMap::<u16, (UdpSocket, Instant)>::new();
		let mut tcp_socks = HashMap::<u16, (TcpStream, Instant)>::new();

		loop {

			debug!("TCP sockets: {}", tcp_socks.len());
			debug!("UDP sockets: {}", udp_socks.len());
			poll.poll(&mut events, None).unwrap();
			let now = Instant::now(); // Inie tinie bit more efficient;

			for e in &events {
				let (ty, local_port) = (e.token().0 & EVENT_MASK, e.token().0 & !EVENT_MASK);
				match ty {
					CLIENT_EVENT => {
						let len = client.read(&mut buf)?;
						if len == 0 {
							return Err(Error::new(std::io::ErrorKind::NotConnected, ""));
						}

						let (sh, data, _) = stupid::StupidDataHeader::from_raw(&buf[..len]).unwrap();

						match sh.ty() {
							Ok(stupid::StupidType::UDP) => {
								match udp_socks.entry(sh.local()) {
									Entry::Occupied(mut e) => {
										let (udp, last_used) = e.get_mut();
										udp.send(data).unwrap();
										*last_used = now;
									}
									Entry::Vacant(e) => {
										let addr = SocketAddrV4::new([0; 4].into(), 0);
										let mut udp = UdpSocket::bind(addr.into()).unwrap();
										udp.connect(sh.remote().into()).unwrap();
										udp.send(data).unwrap();
										let token = mio::Token(UDP_EVENT | usize::from(sh.local()));
										poll.registry()
											.register(&mut udp, token, mio::Interest::READABLE)
											.unwrap();
										e.insert((udp, now));
									}
								}
							}
							Ok(stupid::StupidType::TcpConnect) => {
								debug!("connecting TCP {} -> {}", sh.local(), sh.remote());
								let mut tcp = TcpStream::connect(sh.remote().into()).unwrap();
								tcp.write(data).unwrap();
								let token = mio::Token(TCP_EVENT | usize::from(sh.local()));
								poll.registry()
									.register(&mut tcp, token, mio::Interest::READABLE)
									.unwrap();
								tcp_socks.insert(sh.local(), (tcp, now));
							}
							Ok(stupid::StupidType::TCP) => {
								debug!("closing TCP {} -> {}", sh.local(), sh.remote());
								let (tcp, last_used) = tcp_socks.get_mut(&sh.local()).unwrap();
								tcp.write(data).unwrap();
								*last_used = now;
							}
							Ok(stupid::StupidType::TcpFinish) => {
								debug!("closed TCP {} -> {}", sh.local(), sh.remote());
								tcp_socks.remove(&sh.local());
							}
							Err(_) => todo!(),
						}
					}
					UDP_EVENT => {
						let (udp, last_used) = udp_socks.get_mut(&local_port.try_into().unwrap()).unwrap();
						let (len, addr) = udp.recv_from(&mut buf).unwrap();
						let addr = match addr {
							SocketAddr::V4(a) => a,
							_ => unreachable!(),
						};

						let data = &buf[..len];
						let h = StupidDataHeader::new(StupidType::UDP, addr, local_port.try_into().unwrap(), len.try_into().unwrap());

						out[..h.byte_len()].copy_from_slice(h.as_ref());
						out[h.byte_len()..][..data.len()].copy_from_slice(data);
						let out = &out[..h.byte_len() + data.len()];
						client.write_all(out).unwrap();

						*last_used = now;
					}
					TCP_EVENT => {
						let (tcp, last_used) = tcp_socks.get_mut(&local_port.try_into().unwrap()).unwrap();
						let addr = tcp.peer_addr().unwrap();
						let addr = match addr {
							SocketAddr::V4(a) => a,
							_ => unreachable!(),
						};

						let len = tcp.read(&mut buf).unwrap();
						if len > 0 {
							let data = &buf[..len];
							let h = StupidDataHeader::new(StupidType::TCP, addr, local_port.try_into().unwrap(), len.try_into().unwrap());

							out[..h.byte_len()].copy_from_slice(h.as_ref());
							out[h.byte_len()..][..data.len()].copy_from_slice(data);
							let out = &out[..h.byte_len() + data.len()];
							client.write_all(out).unwrap();

							*last_used = now;
						} else {
							debug!("closing TCP connection {} -> {}", local_port, addr);
							let h = StupidDataHeader::new(StupidType::TcpFinish, addr, local_port.try_into().unwrap(), len.try_into().unwrap());
							client.write_all(h.as_ref()).unwrap();
						}
					}
					_ => unreachable!(),
				}
			}
		}
	}
}

#[derive(Debug)]
pub enum RunError {
	Bind(Error),
	Accept(Error),
}
