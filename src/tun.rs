use crate::ifreq::{IfReq, NewIfReqError};
use core::mem;
use libc::{c_int, c_ulong, ioctl};
use std::io::{Error, Read, Write};

pub struct Tun {
	fd: c_int,
}

impl Tun {
	const SET_IFF: c_ulong = iow(b'T', 202, mem::size_of::<c_int>());

	pub fn new(name: &[u8]) -> Result<Self, NewTunError> {

		const PATH: &[u8] = b"/dev/net/tun\0";

		let ifr = IfReq::new_tun(name, true).map_err(NewTunError::IfReq)?;
		let fd = unsafe { libc::open(PATH.as_ptr().cast(), 2) }; // O_RDWR
		if fd < 0 {
			todo!("decode the returned error");
		}

		match unsafe { ioctl(fd, Self::SET_IFF, &ifr) } {
			0 => (),
			_ => {
				unsafe { libc::close(fd) };
				todo!("decode the returned error");
			},
		}

		Ok(Self { fd })
	}
}

impl Drop for Tun {
	fn drop(&mut self) {
		unsafe { libc::close(self.fd) };
	}
}

impl Read for Tun {
	fn read(&mut self, data: &mut [u8]) -> Result<usize, Error> {
		let ret = unsafe {
			libc::read(self.fd, data.as_mut_ptr().cast(), data.len())
		};
		(ret >= 0).then(|| ret as usize).ok_or_else(Error::last_os_error)
	}
}

impl Write for Tun {
	fn write(&mut self, data: &[u8]) -> Result<usize, Error> {
		let ret = unsafe {
			libc::write(self.fd, data.as_ptr().cast(), data.len())
		};
		(ret >= 0).then(|| ret as usize).ok_or_else(Error::last_os_error)
	}

	fn flush(&mut self) -> Result<(), Error> {
		Ok(())
	}
}

const fn iow(ty: u8, nr: u8, size: usize) -> c_ulong {
	ioc(1, ty, nr, size)
}

const fn ioc(dir: u8, ty: u8, nr: u8, size: usize) -> c_ulong {
	const NR_BITS: u32 = 8;
	const TY_BITS: u32 = 8;
	const SIZE_BITS: u32 = 14;
	const _DIR_BITS: u32 = 2;

	const NR: u32 = 0;
	const TY: u32 = NR + NR_BITS;
	const SIZE: u32 = TY + TY_BITS;
	const DIR: u32 = SIZE + SIZE_BITS;

	(dir as c_ulong) << DIR | (ty as c_ulong) << TY | (nr as c_ulong) << NR | (size as c_ulong) << SIZE
}

#[derive(Debug)]
pub enum NewTunError {
	IfReq(NewIfReqError),
}
