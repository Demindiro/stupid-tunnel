use crate::Checksum;
use core::fmt;
use core::mem;
use std::net::{Ipv6Addr, SocketAddrV6};

#[derive(Clone, Copy)]
#[repr(C)]
pub struct UDPHeader {
	source_port: [u8; 2],
	destination_port: [u8; 2],
	length: [u8; 2],
	checksum: [u8; 2],
}

impl UDPHeader {
	pub fn from_raw_ipv6(data: &[u8], source: Ipv6Addr, destination: Ipv6Addr) -> Result<(Self, &[u8]), FromRawError> {
		// TODO checksum
		if data.len() < mem::size_of::<Self>() {
			return Err(FromRawError::Truncated);
		}

		let (h, e) = data.split_at(mem::size_of::<Self>());
		// SAFETY: the data fits and is properly aligned.
		unsafe { Ok((*h.as_ptr().cast::<Self>(), e)) }
	}

	pub fn new_ipv6(source: SocketAddrV6, destination: SocketAddrV6, data: &[u8]) -> Result<Self, ChecksumError> {
		let length = u16::try_from(mem::size_of::<Self>() + data.len()).map_err(|_| ChecksumError::DataTooLarge)?.to_be_bytes();
		let mut slf = Self {
			source_port: source.port().to_be_bytes(), 
			destination_port: destination.port().to_be_bytes(),
			length,
			checksum: [0, 0],
		};
		slf.checksum = slf.checksum_ipv6(*source.ip(), *destination.ip(), data)?.to_be_bytes();
		Ok(slf)
	}

	pub fn source_port(&self) -> u16 {
		u16::from_be_bytes(self.source_port)
	}

	pub fn destination_port(&self) -> u16 {
		u16::from_be_bytes(self.destination_port)
	}

	pub fn data_length(&self) -> u16 {
		u16::from_be_bytes(self.length) - u16::try_from(mem::size_of_val(self)).unwrap()
	}

	from_be_fn!(checksum, u16);

	/// Total length of the UDP packet (header + data)
	pub fn length(&self, data: &[u8]) -> Result<u16, ()> {
		let l = mem::size_of_val(self) * 4 + data.len();
		l.try_into().map_err(|_| ())
	}

	/// Return the size of the header
	pub fn byte_len(&self) -> usize {
		mem::size_of_val(self)
	}

	fn checksum_ipv6(&self, source: Ipv6Addr, destination: Ipv6Addr, data: &[u8]) -> Result<u16, ChecksumError> {
		let mut sum = 0usize;
		let (src, dest) = (source.octets(), destination.octets());
		let udp_length = u16::try_from(mem::size_of_val(self) + data.len()).map_err(|_| ChecksumError::DataTooLarge)?.to_be_bytes();
		let sum = Checksum::new()
			.feed_ref(&src)
			.feed_ref(&dest)
			.feed_ref(&[0, 17]) // zero, protocol
			.feed_ref(&udp_length)
			.feed_ref(&self.source_port)
			.feed_ref(&self.destination_port)
			.feed_ref(&self.length)
			.feed_ref(data)
			.finish();
		Ok(sum)
	}
}

impl fmt::Debug for UDPHeader {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct(stringify!(IPv6Header))
			.field("source_port", &self.source_port())
			.field("destination_port", &self.destination_port())
			.field("length", &u16::from_be_bytes(self.length))
			.field("checksum", &u16::from_be_bytes(self.checksum))
			.finish()
	}
}

impl AsRef<[u8; mem::size_of::<Self>()]> for UDPHeader {
	fn as_ref(&self) -> &[u8; mem::size_of::<Self>()] {
		unsafe { &*(self as *const _ as *const _) }
	}
}

#[derive(Debug)]
pub enum FromRawError {
	BadChecksum,
	Truncated,
}

#[derive(Debug)]
pub enum ChecksumError {
	DataTooLarge,
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn checksum() {
		let src = Ipv6Addr::LOCALHOST;
		let dst = Ipv6Addr::UNSPECIFIED;
		let udp = UDPHeader::new_ipv6(src, 232, dst, 244, b"gutentag").unwrap();
		assert_eq!(udp.checksum(), 21051);
	}
}
