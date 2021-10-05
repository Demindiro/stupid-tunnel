#[macro_export]
macro_rules! debug {
	($($arg:tt)*) => {{
		eprint!("[DEBUG] ");
		eprintln!($($arg)*);
	}}
}
