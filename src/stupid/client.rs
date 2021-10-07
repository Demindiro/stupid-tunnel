use super::*;
use std::io::{Error, Read, Write};
use std::net::{SocketAddr, SocketAddrV4};
use mio::net::TcpStream;
use mio::{Registry, Token, Interest};

pub struct StupidClient {
	server: TcpStream,
}

impl StupidClient {
	pub fn new(address: SocketAddr) -> Result<Self, Error> {
		let server = TcpStream::connect(address)?;
		Ok(Self { server })
	}

	pub fn send(&mut self, ty: StupidType, remote: SocketAddrV4, local: u16, data: &[u8]) -> Result<(), Error> {
		let len = data.len().try_into().unwrap();
		let dh = StupidDataHeader::new(ty, remote, local, len);

		let mut out = [0; 0x10000];
		out[..dh.byte_len()].copy_from_slice(dh.as_ref());
		out[dh.byte_len()..][..data.len()].copy_from_slice(data);
		let out = &out[..dh.byte_len() + data.len()];

		self.server.write_all(out)
	}

	pub fn receive<'a>(&mut self, buf: &'a mut [u8]) -> Result<(StupidDataHeader, &'a [u8], &'a [u8]), Error> {
		let len = self.server.read(buf)?;
		assert_ne!(len, 0);
		let buf = &buf[..len];
		Ok(StupidDataHeader::from_raw(&buf).unwrap())
	}
}

impl mio::event::Source for StupidClient {
	fn register(&mut self, registry: &Registry, token: Token, interest: Interest) -> Result<(), Error> {
		self.server.register(registry, token, interest)
	}

	fn reregister(&mut self, registry: &Registry, token: Token, interest: Interest) -> Result<(), Error> {
		self.server.reregister(registry, token, interest)
	}

	fn deregister(&mut self, registry: &Registry) -> Result<(), Error> {
		self.server.deregister(registry)
	}
}
