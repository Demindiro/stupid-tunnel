#![feature(maybe_uninit_uninit_array, maybe_uninit_array_assume_init)]
#![feature(never_type)]

#[macro_use]
mod log;

macro_rules! from_be_fn {
	($name:ident, $ty:ty) => {
		pub fn $name(&self) -> $ty {
			<$ty>::from_be_bytes(self.$name)
		}
	}
}

mod checksum;
mod client;
mod icmp;
mod ip;
mod udp;
mod server;
mod stupid;
mod tcp;
mod tun;
mod ifreq;

use std::env;
use std::net;

use checksum::Checksum;

fn main() -> ! {
	
	let mut args = env::args();

	let _ = args.next(); // Skip name

	match args.next().as_deref() {
		Some("server") => {
			let server = server::Server {
				address: net::SocketAddr::new(net::IpAddr::V4(net::Ipv4Addr::LOCALHOST), 5434),
			};
			server.run().unwrap();
		}
		Some("client") => {
			let client = client::Client::new();
			client.run().unwrap()
		}
		_ => show_help(),
	}
}

fn show_help() -> ! {
	let name = env::args().next();
	let name = name.as_deref().unwrap_or("stupid_tunnel");
	eprintln!("Usage:");
	eprintln!("  {} server", name);
	eprintln!("  {} client", name);
	std::process::exit(1);
}
