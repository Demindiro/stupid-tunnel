//! (RFC 4443)[https://datatracker.ietf.org/doc/html/rfc4443]

use core::fmt;
use core::mem;

#[derive(Clone, Copy)]
#[repr(C)]
pub struct ICMPv6Header {
	ty: u8,
	code: u8,
	checksum: [u8; 2],
}

impl ICMPv6Header {
	pub fn from_raw(data: &[u8]) -> Result<(Self, &[u8]), RawHeaderError> {
		if data.len() < mem::size_of::<Self>() {
			return Err(RawHeaderError::Truncated);
		}
		// SAFETY: the data fits & is aligned
		let (h, e) = data.split_at(mem::size_of::<Self>());
		unsafe { Ok((*h.as_ptr().cast(), e)) }
	}
}

impl fmt::Debug for ICMPv6Header {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct(stringify!(ICMPv6Header))
			.field("type", &self.ty)
			.field("code", &self.code)
			.field("checksum", &u16::from_be_bytes(self.checksum))
			.finish()
	}
}

#[derive(Debug)]
pub enum RawHeaderError {
	Truncated,
}
