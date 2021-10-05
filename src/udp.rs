use core::fmt;
use core::mem;
use std::net::Ipv6Addr;

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

	pub fn new_ipv6(source: Ipv6Addr, source_port: u16, destination: Ipv6Addr, destination_port: u16, data: &[u8]) -> Result<Self, ChecksumError> {
		let length = u16::try_from(mem::size_of::<Self>() + data.len()).map_err(|_| ChecksumError::DataTooLarge)?.to_be_bytes();
		let mut slf = Self {
			source_port: source_port.to_be_bytes(), 
			destination_port: destination_port.to_be_bytes(),
			length,
			checksum: [0, 0],
		};
		slf.checksum = slf.checksum_ipv6(source, destination, data)?.to_be_bytes();
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

	fn checksum_ipv6(&self, source: Ipv6Addr, destination: Ipv6Addr, data: &[u8]) -> Result<u16, ChecksumError> {
		let mut sum = 0usize;
		let (src, dest) = (source.octets(), destination.octets());
		let udp_length = u16::try_from(mem::size_of_val(self) + data.len()).map_err(|_| ChecksumError::DataTooLarge)?.to_be_bytes();
		let mut chain = src.iter()
			.chain(&dest)
			.chain(&[0, 17]) // zero, protocol
			.chain(&udp_length)
			.chain(&self.source_port)
			.chain(&self.destination_port)
			.chain(&self.length)
			.chain(data)
			.copied();
		while let Some(a) = chain.next() {
			let n = [a, chain.next().unwrap_or(0)];
			sum = sum.wrapping_add(u16::from_be_bytes(n).into());
		}
		Ok((sum as u16 + (sum >> 16) as u16) ^ 0xffff)
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
