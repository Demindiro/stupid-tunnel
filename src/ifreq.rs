#[repr(C)]
pub struct IfReq {
	name: [u8; Self::NAME_SIZE],
	data: Data,
}

#[repr(C)]
union Data {
	flags: u16,
}

impl IfReq {
	const NAME_SIZE: usize = 16;

	const FLAG_TUN: u16 = 0x0001;
	const FLAG_NO_PI: u16 = 0x1000;

	pub fn new_tun(name: &[u8], no_packet_info: bool) -> Result<Self, NewIfReqError> {
		let mut n = [0; Self::NAME_SIZE];
		if name.len() >= n.len() {
			return Err(NewIfReqError::NameTooLong);
		}
		n.iter_mut().zip(name.iter().chain(&[0])).for_each(|(w, r)| *w = *r);
		dbg!(Self::FLAG_TUN | u16::from(no_packet_info) * Self::FLAG_NO_PI);
		Ok(Self {
			name: n,
			data: Data {
				flags: Self::FLAG_TUN | u16::from(no_packet_info) * Self::FLAG_NO_PI,
			}
		})
	}
}

#[derive(Debug)]
pub enum NewIfReqError {
	NameTooLong,
}
