use super::*;
use std::io::{Error, Read, Write};
use std::net::{TcpStream, SocketAddr, Ipv4Addr};

pub struct StupidClient {
	server: TcpStream,
}

impl StupidClient {
	pub fn new(address: SocketAddr) -> Result<Self, Error> {
		let server = TcpStream::connect(address)?;
		Ok(Self { server })
	}

	pub fn send(&mut self, ty: StupidType, ip: Ipv4Addr, port: u16, data: &[u8]) -> Result<(), Error> {
		let len = data.len().try_into().unwrap();
		let dh = StupidDataHeader::new(ty, ip, port, len);

		let mut out = [0; 0x10000];
		out[..dh.byte_len()].copy_from_slice(dh.as_ref());
		out[dh.byte_len()..][..data.len()].copy_from_slice(data);
		let out = &out[..dh.byte_len() + data.len()];

		self.server.write_all(out)
	}
}
