extern crate clap;

#[macro_use] extern crate error_chain;

use clap::{App, AppSettings};
use std::io::prelude::*;

macro_rules! warn {
  ($($arg:tt)*) => {{
    extern crate std;
    use std::io::prelude::*;
    let _ = writeln!(&mut std::io::stderr(), $($arg)*);
  }};
}
macro_rules! die {
  ($($arg:tt)*) => {{
    extern crate std;
    warn!($($arg)*);
    process::exit(-1)
  }};
}

mod error {
  error_chain!{
    foreign_links {
      Clap(::clap::Error);
    }
  }
}

use error::*;

fn run<I, T>(args: I) -> Result<()>
  where I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
{
  let matches = App::new(env!("CARGO_PKG_NAME"))
    .version(concat!("v", env!("CARGO_PKG_VERSION")))
    .author(env!("CARGO_PKG_AUTHORS"))
    .about(concat!(env!("CARGO_PKG_DESCRIPTION"), " - ", env!("CARGO_PKG_HOMEPAGE")))
    .setting(AppSettings::ColoredHelp)
    .get_matches_from_safe(args)?;

  Ok(())
}

fn main() {
  if let Err(ref e) = run(std::env::args()) {
    if let Error(ErrorKind::Clap(ref clap_error), _) = *e {
      use clap::ErrorKind::{HelpDisplayed, VersionDisplayed};
      write!(&mut std::io::stderr(), "{}", clap_error);
      match clap_error.kind {
        HelpDisplayed | VersionDisplayed => return,
        _ => std::process::exit(1)
      }
    }

    println!("error: {}", e);

    for e in e.iter().skip(1) {
      println!("caused by: {}", e);
    }

    if let Some(backtrace) = e.backtrace() {
      println!("backtrace: {:?}", backtrace);
    }

    std::process::exit(1);
  }
}
