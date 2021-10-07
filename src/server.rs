use crate::*;
use std::net;
use std::io::{Error, Read, Write};

pub struct Server {
	pub address: net::SocketAddr,
}

impl Server {
	pub fn run(self) -> Result<!, RunError> {

		debug!("Starting server");
		let server = net::TcpListener::bind(self.address).map_err(RunError::Bind)?;
		
		loop {
			debug!("Waiting for client");
			let (stream, _) = server.accept().map_err(RunError::Accept)?;
			let _ = self.handle_client(stream);
		}
	}

	fn handle_client(&self, mut client: net::TcpStream) -> Result<!, Error> {
		let mut buf = [0; 0x10000];

		loop {
			let len = client.read(&mut buf)?;
			if len == 0 {
				return Err(Error::new(std::io::ErrorKind::NotConnected, ""));
			}

			let (sh, d) = stupid::StupidDataHeader::from_raw(&buf[..len]).unwrap();
			//assert!(usize::from(sh.data_length()) <= d.len());
			let _ = dbg!(core::str::from_utf8(&d[..usize::from(sh.data_length())]));
			
			/*
			match buf[0] {
				_ => todo!(),
			}
			*/
		}
	}
}

#[derive(Debug)]
pub enum RunError {
	Bind(Error),
	Accept(Error),
}
