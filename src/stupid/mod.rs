mod client;

use core::mem;
use core::fmt;
use std::net::Ipv4Addr;

pub use client::StupidClient;

#[derive(Clone, Copy)]
#[repr(u8)]
pub enum StupidType {
	TCP = 0,
	UDP = 1,
}

impl From<StupidType> for u8 {
	fn from(t: StupidType) -> Self {
		t as u8
	}
}

impl TryFrom<u8> for StupidType {
	type Error = InvalidType;

	fn try_from(n: u8) -> Result<Self, Self::Error> {
		[
			Self::TCP,
			Self::UDP,
		].get(usize::from(n)).copied().ok_or(InvalidType)
	}
}

#[derive(Debug)]
pub struct InvalidType;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct StupidDataHeader {
	ty: u8,
	address: [u8; 4],
	port: [u8; 2],
	data_length: [u8; 2],
}

impl StupidDataHeader {
	pub fn from_raw(data: &[u8]) -> Result<(Self, &[u8]), FromRawError> {
		if data.len() < mem::size_of::<Self>() {
			return Err(FromRawError::Truncated);
		}

		let (h, d) = data.split_at(mem::size_of::<Self>());

		unsafe { Ok((*h.as_ptr().cast(), d)) }
	}

	pub fn new(ty: StupidType, address: Ipv4Addr, port: u16, data_length: u16) -> Self {
		Self {
			ty: ty.into(),
			address: address.octets(),
			port: port.to_le_bytes(),
			data_length: data_length.to_le_bytes(),
		}
	}

	pub fn address(&self) -> Ipv4Addr {
		Ipv4Addr::from(self.address)
	}

	pub fn ty(&self) -> Result<StupidType, InvalidType> {
		self.ty.try_into()
	}

	pub fn port(&self) -> u16 {
		u16::from_le_bytes(self.port)
	}

	pub fn data_length(&self) -> u16 {
		u16::from_le_bytes(self.data_length)
	}

	pub fn byte_len(&self) -> usize {
		mem::size_of_val(self)
	}
}

impl AsRef<[u8; mem::size_of::<Self>()]> for StupidDataHeader {
	fn as_ref(&self) -> &[u8; mem::size_of::<Self>()] {
		unsafe { &*(self as *const _ as *const _) }
	}
}

impl fmt::Debug for StupidDataHeader {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct(stringify!(StupidDataHeader))
			.field("address", &self.address())
			.field("port", &self.port())
			.field("data_length", &self.data_length())
			.finish()
	}
}

#[derive(Debug)]
pub enum FromRawError {
	Truncated,
}
