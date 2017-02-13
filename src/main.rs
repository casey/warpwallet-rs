extern crate clap;
extern crate regex;

#[macro_use]
extern crate error_chain;

#[macro_use]
extern crate brev;

use clap::{App, AppSettings, Arg};
use regex::Regex;

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
    .about(concat!(env!("CARGO_PKG_DESCRIPTION"),
                   " - ",
                   env!("CARGO_PKG_HOMEPAGE")))
    .setting(AppSettings::ColoredHelp)
    .arg(Arg::with_name("salt")
         .short("s")
         .long("salt")
         .takes_value(true)
         .required(true))
    .arg(Arg::with_name("passphrase")
         .short("p")
         .long("passphrase")
         .takes_value(true)
         .required(true))
    .arg(Arg::with_name("mnemonic-length")
         .short("l")
         .long("mnemonic-length")
         .takes_value(true)
         .required(false))
    .get_matches_from_safe(args)?;

  let passphrase = matches.value_of("passphrase").unwrap();
  let salt = matches.value_of("salt").unwrap();

  if passphrase.len() == 0 {
    die!("passphrase may not be empty");
  }

  if salt.len() == 0 {
    die!("salt may not be empty");
  }

  let salt_re = Regex::new("^.+@.+[.].+$").unwrap();

  if !salt_re.is_match(salt) {
    die!("salt must be an email address, or at least match `{}`", salt_re.as_str());
  }

  let passphrase_re = Regex::new("^[ -~]+$").unwrap();

  if !passphrase_re.is_match(passphrase) {
    die!("passphrase must match `{}`", passphrase_re.as_str());
  }

  println!("salt: {}", salt);
  println!("passphrase: {}", passphrase);

  Ok(())
}

fn main() {
  if let Err(ref e) = run(std::env::args()) {
    if let Error(ErrorKind::Clap(ref clap_error), _) = *e {
      use clap::ErrorKind::{HelpDisplayed, VersionDisplayed};
      brev::err(clap_error);
      match clap_error.kind {
        HelpDisplayed | VersionDisplayed => return,
        _ => std::process::exit(1),
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

#[cfg(test)]
mod tests {
  #[test]
  fn no_op_test() {
    assert!(::run(&["hello"]).is_ok())
  }
}
