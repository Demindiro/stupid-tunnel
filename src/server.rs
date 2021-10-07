use crate::*;
use crate::stupid::{StupidDataHeader, StupidType};
use std::collections::HashMap;
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
		let mut buf = [0; 0x10000];

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

		let mut udp_socks: [Option<(UdpSocket, Instant)>; 0x10000] = unsafe {
			use core::mem::MaybeUninit;
			let mut a = MaybeUninit::uninit_array::<0x10000>();
			a.fill_with(|| MaybeUninit::new(None));
			MaybeUninit::array_assume_init(a)
		};
		let mut tcp_socks = unsafe {
			use core::mem::MaybeUninit;
			let mut a = MaybeUninit::uninit_array::<0x10000>();
			a.fill_with(|| MaybeUninit::new(None));
			MaybeUninit::array_assume_init(a)
		};

		loop {

			poll.poll(&mut events, None).unwrap();

			for e in &events {
				let (ty, local_port) = (e.token().0 & EVENT_MASK, e.token().0 & !EVENT_MASK);
				match ty {
					CLIENT_EVENT => {
						let len = client.read(&mut buf)?;
						if len == 0 {
							return Err(Error::new(std::io::ErrorKind::NotConnected, ""));
						}

						let (sh, data, _) = stupid::StupidDataHeader::from_raw(&buf[..len]).unwrap();
						let _ = dbg!(sh, core::str::from_utf8(&data));

						match sh.ty() {
							Ok(stupid::StupidType::UDP) => {
								let u = &mut udp_socks[usize::from(sh.local())];
								if let Some((udp, last_used)) = u {
									udp.send(data).unwrap();
									*last_used = Instant::now();
								} else {
									let addr = SocketAddrV4::new([0; 4].into(), 0);
									let udp = UdpSocket::bind(addr.into()).unwrap();
									udp.connect(sh.remote().into()).unwrap();
									udp.send(data).unwrap();
									*u = Some((udp, Instant::now()));
									let token = mio::Token(UDP_EVENT | usize::from(sh.local()));
									poll.registry()
										.register(&mut u.as_mut().unwrap().0, token, mio::Interest::READABLE)
										.unwrap();
								}
							}
							Ok(stupid::StupidType::TcpConnect) => {
								let mut tcp = TcpStream::connect(sh.remote().into()).unwrap();
								tcp.write(data).unwrap();
								let t = &mut tcp_socks[usize::from(sh.local())];
								*t = Some((tcp, Instant::now()));
								let token = mio::Token(TCP_EVENT | usize::from(sh.local()));
								poll.registry()
									.register(&mut t.as_mut().unwrap().0, token, mio::Interest::READABLE)
									.unwrap();
							}
							Ok(stupid::StupidType::TCP) => {
								let (tcp, last_used) = tcp_socks[usize::from(sh.local())]
									.as_mut()
									.unwrap();
								tcp.write(data).unwrap();
								*last_used = Instant::now();
							},
							Ok(stupid::StupidType::TcpFinish) => todo!(),
							Err(_) => todo!(),
						}
					}
					UDP_EVENT => {
						if let Some((udp, last_used)) = udp_socks[local_port].as_mut() {
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

							*last_used = Instant::now();
						} else {
							panic!("oh no {}", local_port);
						}
					}
					TCP_EVENT => {
						if let Some((tcp, last_used)) = tcp_socks[local_port].as_mut() {
							let addr = tcp.peer_addr().unwrap();
							let addr = match addr {
								SocketAddr::V4(a) => a,
								_ => unreachable!(),
							};

							let len = tcp.read(&mut buf).unwrap();
							let data = &buf[..len];
							let h = StupidDataHeader::new(StupidType::TCP, addr, local_port.try_into().unwrap(), len.try_into().unwrap());

							out[..h.byte_len()].copy_from_slice(h.as_ref());
							out[h.byte_len()..][..data.len()].copy_from_slice(data);
							let out = &out[..h.byte_len() + data.len()];
							client.write_all(out).unwrap();

							*last_used = Instant::now();
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
