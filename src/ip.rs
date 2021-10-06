use core::mem;
use core::fmt;
use std::net::Ipv6Addr;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct IPv6Header {
	head: [u8; 4], // 4 bit version, 8 bit traffic class, 20 bit flow label
	payload_length: [u8; 2], // 16 bit BE integer
	pub next_header: u8,
	pub hop_limit: u8,
	source_address: [u8; 16],
	destination_address: [u8; 16],
}

impl IPv6Header {
	const VERSION: u8 = 6;

	pub fn new(payload_length: u16, next_header: u8, hop_limit: u8, source_address: Ipv6Addr, destination_address: Ipv6Addr) -> Self {
		Self {
			head: [Self::VERSION << 4, 0, 0, 0],
			payload_length: payload_length.to_be_bytes(),
			next_header,
			hop_limit,
			source_address: source_address.octets(),
			destination_address: destination_address.octets(),
		}
	}

	pub fn from_raw(raw: &[u8]) -> Result<(&Self, &[u8]), FromRawError> {
		if raw.len() < mem::size_of::<Self>() {
			return Err(FromRawError::BadSize);
		}

		let (header, payload) = raw.split_at(mem::size_of::<Self>());
		// SAFETY: it fits and it's properly aligned.
		let header = unsafe { &*header.as_ptr().cast::<Self>() };

		if header.version() != Self::VERSION {
			return Err(FromRawError::BadVersion(header.version()));
		}

		Ok((header, payload))
	}

	pub fn version(&self) -> u8 {
		self.head[0] >> 4
	}

	pub fn payload_length(&self) -> u16 {
		u16::from_be_bytes(self.payload_length)
	}

	pub fn source_address(&self) -> Ipv6Addr {
		Ipv6Addr::from(self.source_address)
	}

	pub fn set_source_address(&mut self, address: Ipv6Addr) -> &mut Self {
		self.source_address = address.octets();
		self
	}

	pub fn destination_address(&self) -> Ipv6Addr {
		Ipv6Addr::from(self.destination_address)
	}

	pub fn set_destination_address(&mut self, address: Ipv6Addr) -> &mut Self {
		self.destination_address = address.octets();
		self
	}

	pub fn set_next_header(&mut self, header: u8) -> &mut Self {
		self.next_header = header;
		self
	}

	pub fn set_hop_limit(&mut self, limit: u8) -> &mut Self {
		self.hop_limit = limit;
		self
	}

	pub fn set_payload_length(&mut self, length: u16) -> &mut Self {
		self.payload_length = length.to_be_bytes();
		self
	}

	pub fn byte_len(&self) -> usize {
		mem::size_of_val(self)
	}
}

impl fmt::Debug for IPv6Header {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct(stringify!(IPv6Header))
			.field("version", &self.version())
			.field("payload_length", &self.payload_length())
			.field("next_header", &self.next_header)
			.field("hop_limit", &self.hop_limit)
			.field("source_address", &self.source_address())
			.field("destination_address", &self.destination_address())
			.finish()
	}
}

impl AsRef<[u8; mem::size_of::<Self>()]> for IPv6Header {
	fn as_ref(&self) -> &[u8; mem::size_of::<Self>()] {
		unsafe { &*(self as *const _ as *const _) }
	}
}

impl Default for IPv6Header {
	fn default() -> Self {
		Self::new(0, 0, 0, Ipv6Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED)
	}
}

#[derive(Debug)]
pub enum FromRawError {
	BadSize,
	BadVersion(u8),
}
