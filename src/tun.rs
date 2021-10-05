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

	pub fn add_ipv6_address(&mut self, ip: std::net::Ipv6Addr) {
		// TODO use rtnetlink directly
		std::process::Command::new("ip")
			.args(["-6", "addr", "add", &*format!("{}/96", ip), "dev", "stupid_tunnel"])
			.output()
			.unwrap();
		std::process::Command::new("ip")
			.args(["-6", "link", "set", "stupid_tunnel", "up"])
			.output()
			.unwrap();
		/*
		#[repr(C)]
		struct IfAddrMsg {
			family: u8,
			prefix_length: u8,
			flags: u8,
			scope: u8,
			index: u32,
		};

		#[repr(C)]
		struct Request {
			n: libc::nlmsghdr,
			ifa: IfAddrMsg,
		}

		let r = Request {
			n: libc::nlmsghdr {
				nlmsg_len: mem::size_of::<Request>().try_into().unwrap(),
				nlmsg_type: libc::RTM_NEWADDR.try_into().unwrap(),
				nlmsg_flags: (libc::NLM_F_CREATE | libc::NLM_F_EXCL | libc::NLM_F_REQUEST).try_into().unwrap(),
				nlmsg_pid: 0,
				nlmsg_seq: 0,
			},
			ifa: IfAddrMsg {
				family: libc::AF_INET6.try_into().unwrap(),
				prefix_length: 128 - 32,
				flags: 0,
				scope: 0,
				index: 85,
			}
		};

		unsafe {
			let nl = libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE);
			assert!(nl >= 0);
			libc::send(nl, &r as *const _ as *const _, mem::size_of_val(&r), 0);
			libc::close(nl);
		}
		*/
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
