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
		};

		let tcp = TcpHeader::new(
			(slf.local_ip, slf.local_port),
			(slf.remote_ip, slf.remote_port),
			slf.sequence_num,
			slf.acknowledge_num,
			Flags::new().set_acknowledge(true).set_synchronize(true),
			tcp.window(),
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

	pub fn receive<'a>(&mut self, tcp: &TcpHeader, data: &[u8], out: &'a mut [u8]) -> Result<Option<&'a [u8]>, ()> {

		self.acknowledge_num = self.acknowledge_num.wrapping_add(data.len() as u32);

		let tcp = TcpHeader::new(
			(self.local_ip, self.local_port),
			(self.remote_ip, self.remote_port),
			self.sequence_num,
			self.acknowledge_num,
			Flags::new().set_acknowledge(true),
			tcp.window(),
			Options::NONE,
			&[],
		);

		let ip = IPv6Header::new(tcp.length(&[]).unwrap(), 6, 255, self.local_ip, self.remote_ip);

		let ip_o = 0;
		let tcp_o = ip_o + ip.byte_len();
		let len = tcp_o + tcp.byte_len();

		assert!(out.len() >= len);

		out[ip_o..tcp_o].copy_from_slice(ip.as_ref());
		out[tcp_o..len].copy_from_slice(tcp.as_ref());

		Ok(Some(&out[..len]))
	}

	pub fn send(&mut self, data: &[u8], out: &mut [u8]) -> Result<(), ()> {
		todo!();
		let tcp = TcpHeader::default();
		//	.set
		let ip = IPv6Header::default()
			.set_hop_limit(64)
			.set_next_header(6)
			.set_source_address(self.local_ip)
			.set_destination_address(self.remote_ip);
	}
}
