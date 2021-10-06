pub struct Checksum {
	odd_byte: Option<u8>,
	sum: usize,
}

impl Checksum {
	pub const fn new() -> Self {
		Self {
			odd_byte: None,
			sum: 0,
		}
	}

	pub fn feed(&mut self, iter: impl IntoIterator<Item = u8>) -> &mut Self {
		for x in iter {
			match self.odd_byte.take() {
				Some(y) => self.sum += usize::from(y) << 8 | usize::from(x),
				None => self.odd_byte = Some(x),
			}
		}
		self
	}

	pub fn feed_ref<'a>(&mut self, iter: impl IntoIterator<Item = &'a u8>) -> &mut Self {
		self.feed(iter.into_iter().copied())
	}

	pub fn finish(&mut self) -> u16 {
		let sum = self.sum + (usize::from(self.odd_byte.unwrap_or(0)) << 8);
		// TODO
		debug_assert!(sum <= u32::MAX as usize);
		dbg!(sum);
		(sum as u16 + (sum >> 16) as u16) ^ 0xffff
	}
}
