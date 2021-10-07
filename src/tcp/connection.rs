use super::*;
use crate::ip::IPv6Header;
use std::net::Ipv6Addr;

pub struct Tcp6Connection {
	local_ip: Ipv6Addr,
	local_port: u16,
	remote_ip: Ipv6Addr,
	remote_port: u16,
	sequence_num: u32,
	acknowledge_num: u32,
	closed: bool,
}

impl Tcp6Connection {
	/// Create a new TCP connection from a received SYN packet.
	pub fn new<'a>(ip: &IPv6Header, tcp: &TcpHeader, _options: Options<'_>, sequence_num: u32, out: &'a mut [u8]) -> (Self, &'a [u8]) {
		let mut slf = Self {
			local_ip: ip.destination_address(),
			local_port: tcp.destination(),
			remote_ip: ip.source_address(),
			remote_port: tcp.source(),
			sequence_num,
			// SYN increases the ACK by 1
			acknowledge_num: tcp.sequence_num().wrapping_add(1),
			closed: false,
		};

		let tcp = TcpHeader::new(
			(slf.local_ip, slf.local_port),
			(slf.remote_ip, slf.remote_port),
			slf.sequence_num,
			slf.acknowledge_num,
			Flags::new().set_acknowledge(true).set_synchronize(true),
			0xffff,
			Options::NONE,
			&[],
		);

		// We're sending SYN, so increment by 1
		slf.sequence_num = slf.sequence_num.wrapping_add(1);

		let ip = IPv6Header::new(tcp.length(&[]).unwrap(), 6, 255, slf.local_ip, slf.remote_ip);

		let ip_o = 0;
		let tcp_o = ip_o + ip.byte_len();
		let len = tcp_o + tcp.byte_len();

		assert!(out.len() >= len);

		out[ip_o..tcp_o].copy_from_slice(ip.as_ref());
		out[tcp_o..len].copy_from_slice(tcp.as_ref());

		(slf, &out[..len])
	}

	pub fn receive<'a>(&mut self, tcp: &TcpHeader, data: &[u8], out: &'a mut [u8]) -> Result<Response<'a>, ()> {

		self.acknowledge_num = self.acknowledge_num.wrapping_add(data.len() as u32);

		if tcp.flags.finish() {
			self.acknowledge_num = self.acknowledge_num.wrapping_add(1);
		} else if data.is_empty() {
			return Ok(Response::None);
		}

		let tcp = TcpHeader::new(
			(self.local_ip, self.local_port),
			(self.remote_ip, self.remote_port),
			self.sequence_num,
			self.acknowledge_num,
			Flags::new().set_acknowledge(true).set_finish(tcp.flags.finish()),
			0xffff,
			Options::NONE,
			&[],
		);

		tcp.flags.finish().then(|| self.sequence_num = self.sequence_num.wrapping_add(1));

		let ip = IPv6Header::new(tcp.length(&[]).unwrap(), 6, 255, self.local_ip, self.remote_ip);

		let ip_o = 0;
		let tcp_o = ip_o + ip.byte_len();
		let len = tcp_o + tcp.byte_len();

		assert!(out.len() >= len);

		out[ip_o..tcp_o].copy_from_slice(ip.as_ref());
		out[tcp_o..len].copy_from_slice(tcp.as_ref());

		if tcp.flags.finish() {
			if self.closed {
				Ok(Response::Finished(&out[..len]))
			} else {
				Ok(Response::Finish(&out[..len]))
			}
		} else {
			Ok(Response::Acknowledge(&out[..len]))
		}
	}

	pub fn send<'a>(&mut self, data: &[u8], out: &'a mut [u8]) -> Result<&'a [u8], ()> {

		let tcp = TcpHeader::new(
			(self.local_ip, self.local_port),
			(self.remote_ip, self.remote_port),
			self.sequence_num,
			self.acknowledge_num,
			Flags::new().set_acknowledge(true),
			0xffff,
			Options::NONE,
			data,
		);

		let ip = *IPv6Header::default()
			.set_hop_limit(64)
			.set_next_header(6)
			.set_source_address(self.local_ip)
			.set_destination_address(self.remote_ip)
			.set_payload_length(tcp.length(data).unwrap());

		out[..ip.byte_len()].copy_from_slice(ip.as_ref());
		out[ip.byte_len()..][..tcp.byte_len()].copy_from_slice(tcp.as_ref());
		out[ip.byte_len()..][tcp.byte_len()..][..data.len()].copy_from_slice(data);

		self.sequence_num = self.sequence_num.wrapping_add(data.len() as u32);
		
		Ok(&out[..ip.byte_len() + tcp.byte_len() + data.len()])
	}

	pub fn close<'a>(&mut self, data: &[u8], out: &'a mut [u8]) -> Result<&'a [u8], ()> {

		let tcp = TcpHeader::new(
			(self.local_ip, self.local_port),
			(self.remote_ip, self.remote_port),
			self.sequence_num,
			self.acknowledge_num,
			Flags::new().set_acknowledge(true).set_finish(true),
			0xffff,
			Options::NONE,
			data,
		);

		let ip = *IPv6Header::default()
			.set_hop_limit(64)
			.set_next_header(6)
			.set_source_address(self.local_ip)
			.set_destination_address(self.remote_ip)
			.set_payload_length(tcp.length(data).unwrap());

		out[..ip.byte_len()].copy_from_slice(ip.as_ref());
		out[ip.byte_len()..][..tcp.byte_len()].copy_from_slice(tcp.as_ref());
		out[ip.byte_len()..][tcp.byte_len()..][..data.len()].copy_from_slice(data);

		self.sequence_num = self.sequence_num.wrapping_add(data.len() as u32);
		self.closed = true;
		
		Ok(&out[..ip.byte_len() + tcp.byte_len() + data.len()])
	}
}

pub enum Response<'a> {
	Acknowledge(&'a [u8]),
	Finish(&'a [u8]),
	Finished(&'a [u8]),
	None,
}
