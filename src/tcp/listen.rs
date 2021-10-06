use super::*;
use std::net::Ipv6Addr;

/// Create a response for the three way handshake.
pub fn accept_ipv6(packet: &TcpHeader, source: Ipv6Addr, destination: Ipv6Addr, sequence_num: u32, window: u16, options: Options<'_>) -> TcpHeader {
	TcpHeader::new(
		(destination, packet.destination()),
		(source, packet.source()),
		sequence_num,
		packet.sequence_num().wrapping_add(1),
		Flags::new().set_acknowledge(true).set_synchronize(true),
		window,
		options,
		&[],
	)
}
