//! https://datatracker.ietf.org/doc/html/rfc793

use crate::Checksum;
use core::fmt;
use core::mem;
use std::net::Ipv6Addr;

#[derive(Clone, Copy, PartialEq)]
#[repr(C)]
pub struct TcpHeader {
	source: [u8; 2],
	destination: [u8; 2],
	sequence_num: [u8; 4],
	acknowledge_num: [u8; 4],
	data_offset: u8,
	pub flags: Flags,
	window: [u8; 2],
	checksum: [u8; 2],
	urgent_pointer: [u8; 2],
}

impl TcpHeader {
	pub fn from_raw_ipv6(data: &[u8], source: Ipv6Addr, destination: Ipv6Addr) -> Result<(&Self, Options, &[u8]), FromRawError> {
		// TODO checksum
		if data.len() < mem::size_of::<Self>() {
			return Err(FromRawError::Truncated);
		}

		let (h, e) = data.split_at(mem::size_of::<Self>());

		// SAFETY: the data fits and is properly aligned.
		let h = unsafe { &*h.as_ptr().cast::<Self>() };

		let (o, e) = e.split_at(usize::from(h.data_offset()) * 4 - mem::size_of_val(h));
		let o = Options(o);

		Ok((h, o, e))
	}

	pub fn new(source: (Ipv6Addr, u16), destination: (Ipv6Addr, u16), sequence_num: u32, acknowledge_num: u32, flags: Flags, window: u16, options: Options, data: &[u8]) -> Self {
		let data_offset = (mem::size_of::<Self>() + ((options.0.len() + 3) & !3)) / 4;
		let mut slf = Self {
			source: source.1.to_be_bytes(),
			destination: destination.1.to_be_bytes(),
			sequence_num: sequence_num.to_be_bytes(),
			acknowledge_num: acknowledge_num.to_be_bytes(),
			data_offset: (data_offset << 4).try_into().unwrap(),
			flags,
			window: window.to_be_bytes(),
			checksum: [0; 2],
			urgent_pointer: [0; 2],
		};
		// TODO
		slf.checksum = slf.checksum_ipv6(source.0, destination.0, options, data).unwrap().to_be_bytes();
		slf
	}

	from_be_fn!(source, u16);
	from_be_fn!(destination, u16);
	from_be_fn!(sequence_num, u32);
	from_be_fn!(acknowledge_num, u32);

	fn data_offset(&self) -> u8 {
		self.data_offset >> 4
	}

	from_be_fn!(window, u16);
	from_be_fn!(checksum, u16);
	from_be_fn!(urgent_pointer, u16);

	pub fn length(&self, data: &[u8]) -> Result<u16, ()> {
		let l = usize::from(self.data_offset()) * 4 + data.len();
		l.try_into().map_err(|_| ())
	}

	fn checksum_ipv6(&self, source: Ipv6Addr, destination: Ipv6Addr, options: Options, data: &[u8]) -> Result<u16, ChecksumError> {
		let (src, dest) = (source.octets(), destination.octets());
		let tcp_length = u16::try_from(
			mem::size_of_val(self) +
			((options.0.len() + 3) & !3) +
			data.len()
		).map_err(|_| ChecksumError::DataTooLarge)?.to_be_bytes();

		let sum = Checksum::new()
			.feed_ref(&src)
			.feed_ref(&dest)
			.feed_ref(&[0, 6]) // zero, protocol
			.feed_ref(&tcp_length)
			.feed_ref(&self.source)
			.feed_ref(&self.destination)
			.feed_ref(&self.sequence_num)
			.feed_ref(&self.acknowledge_num)
			.feed_ref(core::slice::from_ref(&self.data_offset))
			.feed_ref(core::slice::from_ref(&self.flags.0))
			.feed_ref(&self.window)
			.feed_ref(&self.checksum)
			.feed_ref(&self.urgent_pointer)
			.feed_ref(options.0)
			.feed_ref(data)
			.finish();
		Ok(sum)
	}

	/// Return the size of the header without options
	pub fn byte_len(&self) -> usize {
		mem::size_of_val(self)
	}
}

impl AsRef<[u8; mem::size_of::<Self>()]> for TcpHeader {
	fn as_ref(&self) -> &[u8; mem::size_of::<Self>()] {
		unsafe { &*(self as *const _ as *const _) }
	}
}

impl Default for TcpHeader {
	fn default() -> Self {
		Self::new((Ipv6Addr::UNSPECIFIED, 0), (Ipv6Addr::UNSPECIFIED, 0), 0, 0, Flags(0), 0, Options(&[]), &[])
	}
}

impl fmt::Debug for TcpHeader {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct(stringify!(TcpHeader))
			.field("source", &self.source())
			.field("destination", &self.destination())
			.field("sequence_num", &self.sequence_num())
			.field("acknowledge_num", &self.acknowledge_num())
			.field("data_offset", &self.data_offset())
			.field("flags", &self.flags)
			.field("window", &self.window())
			.field("checksum", &self.checksum())
			.field("urgent_pointer", &self.urgent_pointer())
			.finish()
	}
}

#[derive(Clone, Copy, PartialEq)]
#[repr(C)]
pub struct Flags(u8);

macro_rules! flag {
	($const:ident = $bit:literal, $get:ident, $set:ident) => {
		const $const: u8 = 1 << $bit;

		pub fn $get(&self) -> bool {
			self.0 & Self::$const != 0
		}

		pub fn $set(&mut self, enable: bool) -> Self {
			self.0 &= !Self::$const;
			self.0 |= Self::$const * u8::from(enable);
			*self
		}
	}
}

impl Flags {
	flag!(URGENT = 5, urgent, set_urgent);
	flag!(ACKNOWLEDGE = 4, acknowledge, set_acknowledge);
	flag!(PUSH = 3, push, set_push);
	flag!(RESET = 2, reset, set_reset);
	flag!(SYNCHRONIZE = 1, synchronize, set_synchronize);
	flag!(FINISH = 0, finish, set_finish);

	pub fn new() -> Self {
		Self(0)
	}
}

impl fmt::Debug for Flags {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.write_fmt(format_args!("{:08b}", self.0))?;
		self.urgent().then(|| f.write_str(" | URG")).unwrap_or(Ok(()))?;
		self.acknowledge().then(|| f.write_str(" | ACK")).unwrap_or(Ok(()))?;
		self.push().then(|| f.write_str(" | PSH")).unwrap_or(Ok(()))?;
		self.reset().then(|| f.write_str(" | RST")).unwrap_or(Ok(()))?;
		self.synchronize().then(|| f.write_str(" | SYN")).unwrap_or(Ok(()))?;
		self.finish().then(|| f.write_str(" | FIN")).unwrap_or(Ok(()))?;
		Ok(())
	}
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Options<'a>(&'a [u8]);

impl<'a> Options<'a> {
	pub const NONE: Self = Self(&[]);

	pub fn new(options: impl Iterator<Item = OptionData>, buf: &'a mut [u8]) -> Result<Self, ()> {
		let mut i = 0;
		for o in options {
			match o {
				OptionData::NoOperation => {
					buf[i] = 1;
					i += 1;
				}
				OptionData::MaximumSegmentSize(s) => {
					let [h, l] = s.to_be_bytes();
					buf[i..i + 4].copy_from_slice(&[2, 4, h, l]);
					i += 4;
				}
				OptionData::Timestamp { time, echo } => {
					buf[i..i + 2].copy_from_slice(&[8, 10]);
					buf[i + 2..i + 6].copy_from_slice(&time.to_be_bytes());
					buf[i + 6..i + 10].copy_from_slice(&echo.to_be_bytes());
					i += 10;
				}
				OptionData::WindowScale(s) => {
					buf[i..i + 3].copy_from_slice(&[3, 3, s]);
					i += 3;
				}
				_ => todo!(),
			}
		}
		Ok(Self(&buf[..i]))
	}

	pub fn iter(&self) -> OptionsIter<'a> {
		OptionsIter(&self.0)
	}

	pub fn byte_len(&self) -> usize {
		(self.0.len() + 3) & !3
	}

	fn next_option(data: &[u8]) -> Result<Option<(&[u8], &[u8])>, FromRawError> {
		let i = match data.get(0) {
			Some(0) | None => return Ok(None),
			Some(1) => 1, // No operation
			Some(2) => 4, // Maximum segment size
			Some(3) => 3, // Window scale
			Some(4) => 2, // Selective Acknowledgement permitted
			Some(5) => todo!(), // Selective ACKnowledgement (SACK)
			Some(8) => 10, // Timestamp and echo of previous timestamp
			Some(_) => return Err(FromRawError::BadOption),
		};
		Ok(Some(data.split_at(i)))
	}
}

impl AsRef<[u8]> for Options<'_> {
	fn as_ref(&self) -> &[u8] {
		self.0
	}
}

impl fmt::Debug for Options<'_> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		let mut s = f.debug_set();
		let mut d = self.0;
		while let Some((o, n)) = Self::next_option(d).unwrap() {
			s.entry(&format_args!("{:?}", o));
			d = n;
		}
		s.finish()
	}
}

#[derive(Clone, Copy, Debug)]
pub enum OptionData {
	NoOperation,
	MaximumSegmentSize(u16),
	SelectiveAcknowledgementPermitted,
	SelectiveAcknowledgement(SACK),
	Timestamp {
		time: u32,
		echo: u32,
	},
	WindowScale(u8),
}

#[derive(Clone, Copy, Debug)]
pub enum SACK {
	N1(u32),
	N2(u32, u32),
	N3(u32, u32, u32),
	N4(u32, u32, u32, u32),
}

pub struct OptionsIter<'a>(&'a [u8]);

impl Iterator for OptionsIter<'_> {
	type Item = OptionData;

	fn next(&mut self) -> Option<Self::Item> {
		let (r, d) = Options::next_option(self.0).unwrap()?;
		self.0 = d;
		match r[0] {
			0 => None,
			1 => Some(OptionData::NoOperation),
			2 => Some(OptionData::MaximumSegmentSize((r[2] as u16) << 8 | r[3] as u16)),
			4 => Some(OptionData::SelectiveAcknowledgementPermitted),
			5 => todo!(),
			8 => Some(OptionData::Timestamp {
				time: u32::from_be_bytes(r[2.. 6].try_into().unwrap()),
				echo: u32::from_be_bytes(r[6..10].try_into().unwrap()),
			}),
			_ => todo!(),
		}
	}
}

#[derive(Debug)]
pub enum ChecksumError {
	DataTooLarge,
}

#[derive(Debug)]
pub enum FromRawError {
	BadChecksum,
	Truncated,
	BadOption,
}

pub struct Tcp6HeaderBuilder<'a> {
	source_ip: Ipv6Addr,
	source_port: u16,
	destination_ip: Ipv6Addr,
	destination_port: u16,
	options: Options<'a>,
	data: &'a [u8],
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn checksum() {
		let src = Ipv6Addr::LOCALHOST;
		let dst = Ipv6Addr::UNSPECIFIED;
		let tcp = TcpHeader::new((src, 232), (dst, 244), 58, 23, Flags(23), 22, Options(&[1, 1, 2, 4, 5, 24]), b"gutentag");
		assert_eq!(tcp.checksum(), 55718);
	}
}
