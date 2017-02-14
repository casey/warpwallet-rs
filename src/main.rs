#[macro_use] extern crate serde_derive;
#[macro_use] extern crate error_chain;
extern crate bitcoin;
extern crate brev;
extern crate clap;
extern crate regex;
extern crate ring;
extern crate ring_pwhash;
extern crate rustc_serialize;
extern crate serde_json;
extern crate secp256k1;

const SCRYPT_N: u8    = 18;
const SCRYPT_P: u32   = 1;
const SCRYPT_R: u32   = 8;
const PBKDF2_C: usize = 65536;
const DK_LEN:   usize = 32;

error_chain!{
  types {
    Error, ErrorKind, ResultExt;
  }


  foreign_links {
    Clap(::clap::Error);
  }

  errors {
    EmptyPassphrase
    EmptySalt
    BadSalt
    BadPassphrase
  }
}

use bitcoin::util::address::Privkey;
use bitcoin::util::base58::ToBase58;
use clap::{App, AppSettings, Arg};
use regex::Regex;
use rustc_serialize::hex::{FromHex, FromHexError};
use secp256k1::key::SecretKey;
use std::ops::BitXor;

struct Input {
  passphrase: Vec<u8>,
  salt:       Vec<u8>,
}

impl Input {
  fn new(passphrase: &str, salt: &str) -> Input {
    Input {
      passphrase: passphrase.as_bytes().to_vec(),
      salt:       salt.as_bytes().to_vec(),
    }
  }
}

struct Output {
  s1:          Seed,
  s2:          Seed,
  s3:          Seed,
  address:     String,
  private_key: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Seed {
  bytes: [u8; DK_LEN]
}

impl Seed {
  fn new() -> Seed {
    Seed {
      bytes: [0u8; DK_LEN]
    }
  }

  fn from_hex(hex: &str) -> Result<Seed, FromHexError> {
    let vec = hex.from_hex()?;
    if vec.len() != DK_LEN {
      return Err(FromHexError::InvalidHexLength);
    }
    let mut seed = Seed::new();
    for (i, byte) in vec.iter().enumerate() {
      seed.bytes[i] = *byte;
    }
    Ok(seed)
  }
}

impl BitXor for Seed {
  type Output = Self;

  fn bitxor(self, rhs: Self) -> Self {
    let mut result = Seed::new();
    for i in 0..DK_LEN {
      result.bytes[i] = self.bytes[i] ^ rhs.bytes[i];
    }
    result
  }
}

impl std::fmt::Display for Seed {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
      for byte in &self.bytes {
        write!(f, "{:x}", byte)?;
      }
      Ok(())
    }
}

#[derive(Debug, PartialEq)]
struct Options {
  passphrase: String,
  salt:       String,
}

#[derive(Serialize, Deserialize)]
struct SpecParams {
  #[serde(rename="N")]
  n:       u8,
  p:       u32,
  r:       u32,
  #[serde(rename="dkLen")]
  dk_len:  usize,
  pbkdf2c: usize,
}

#[derive(Serialize, Deserialize)]
struct TestVectorKeys {
  private: String,
  public:  String,
}

#[derive(Serialize, Deserialize)]
struct TestVector {
  passphrase: String,
  salt:       String,
  seeds:      (String, String, String),
  keys:       TestVectorKeys,
}

#[derive(Serialize, Deserialize)]
struct Spec {
  generated: String,
  version:   String,
  params:    SpecParams,
  vectors:   Vec<TestVector>,
}

fn parse_arguments<I, T>(args: I) -> Result<Options, Error>
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

  if passphrase.is_empty() {
    Err(ErrorKind::EmptyPassphrase)?
  }

  if salt.is_empty() {
    Err(ErrorKind::EmptySalt)?
  }

  let salt_re = Regex::new("^.+@.+[.].+$").unwrap();

  if !salt_re.is_match(salt) {
    Err(ErrorKind::BadSalt)?
  }

  let passphrase_re = Regex::new("^[ -~]+$").unwrap();

  if !passphrase_re.is_match(passphrase) {
    Err(ErrorKind::BadPassphrase)?
  }

  Ok(Options{
    salt:       salt.to_string(),
    passphrase: passphrase.to_string(),
  })
}

fn scrypt(passphrase: &[u8], salt: &[u8]) -> Seed {
  use ring_pwhash::scrypt::{scrypt, ScryptParams};

  let mut passphrase = passphrase.to_vec();
  passphrase.push(0x01);

  let mut salt = salt.to_vec();
  salt.push(0x01);

  let mut seed = Seed::new();

  scrypt(
    &passphrase,
    &salt,
    &ScryptParams::new(SCRYPT_N, SCRYPT_R, SCRYPT_P),
    &mut seed.bytes,
  );

  seed
}

fn pbkdf2(passphrase: &[u8], salt: &[u8]) -> Seed {
  use ring::pbkdf2::derive;
  use ring::pbkdf2::HMAC_SHA256;

  let mut passphrase = passphrase.to_vec();
  passphrase.push(0x02);

  let mut salt = salt.to_vec();
  salt.push(0x02);

  let mut seed = Seed::new();

  derive(
    &HMAC_SHA256,
    PBKDF2_C,
    &salt,
    &passphrase,
    &mut seed.bytes,
  );

  seed
}

fn seeds(input: Input) -> (Seed, Seed, Seed) {
  let s1 = scrypt(&input.passphrase, &input.salt);
  let s2 = pbkdf2(&input.passphrase, &input.salt);
  let s3 = s1 ^ s2;

  (s1, s2, s3)
}

fn private_key(seed: Seed) -> Privkey {
  use bitcoin::network::constants::Network;
  let secret_key = SecretKey::from_slice(&secp256k1::Secp256k1::new(), &seed.bytes).unwrap();
  let compressed = false;
  Privkey::from_key(
    Network::Bitcoin,
    secret_key,
    compressed,
  )
}

fn derive(input: Input) -> Output {
  let (s1, s2, s3) = seeds(input);

  let key = private_key(s3);

  Output {
    s1:          s1,
    s2:          s2,
    s3:          s3,
    private_key: key.to_base58(),
    address:     key.to_address(&secp256k1::Secp256k1::new()).unwrap().to_base58(),
  }
}

fn run<I, T>(args: I) -> Result<(), Error>
  where I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
{

  let options = parse_arguments(args)?;

  let input = Input::new(&options.passphrase, &options.salt);

  let _output = derive(input);

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

#[test]
fn parse_arguments_success() {
  let options = ::parse_arguments(&[
    "warpwallet",
    "--passphrase", "foo",
    "--salt", "foo@bar.com"
  ]).expect("argument parsing failed");

  assert_eq!(options.passphrase, "foo");
  assert_eq!(options.salt, "foo@bar.com");
}

#[test]
fn empty_salt() {
  match *::parse_arguments(&[
    "warpwallet",
    "--passphrase", "foo",
    "--salt", ""
  ]).unwrap_err().kind() {
    ErrorKind::EmptySalt => {},
    ref other => panic!("expected EmptySalt but got: {}", other),
  }
}

#[test]
fn empty_passphrase() {
  match *::parse_arguments(&[
    "warpwallet",
    "--passphrase", "foo",
    "--salt", "hello"
  ]).unwrap_err().kind() {
    ErrorKind::BadSalt => {},
    ref other => panic!("expected BadSalt but got: {}", other),
  }
}

#[test]
fn bad_salt() {
  match *::parse_arguments(&[
    "warpwallet",
    "--passphrase", "\t",
    "--salt", "hello@foo.com"
  ]).unwrap_err().kind() {
    ErrorKind::BadPassphrase => {},
    ref other => panic!("expected BadPassphrase but got: {}", other),
  }
}

#[test]
fn spec() {
  let json = brev::slurp("spec.json");
  let spec: Spec = serde_json::from_str(&json).unwrap();

  assert_eq!(spec.generated,      "Wed Nov 20 2013 09:32:05 GMT-0500 (EST)");
  assert_eq!(spec.version,        "1.0.4");
  assert_eq!(spec.params.n,       SCRYPT_N);
  assert_eq!(spec.params.p,       SCRYPT_P);
  assert_eq!(spec.params.r,       SCRYPT_R);
  assert_eq!(spec.params.dk_len,  DK_LEN);
  assert_eq!(spec.params.pbkdf2c, PBKDF2_C);
  assert_eq!(spec.vectors.len(),  12);

  fn check_seed(i: usize, expected: Seed, actual: Seed) {
    if expected == actual {
      println!("s{}:         {}", i + 1, actual);
    } else {
      assert_eq!(expected, actual);
    }
  }

  for (i, vector) in spec.vectors.iter().enumerate() {
    let input = Input::new(&vector.passphrase, &vector.salt);
    println!("testing vector {}:", i);
    println!("passphrase: {:}", &vector.passphrase);
    println!("salt:       {:}", &vector.salt);
    let output = derive(input);
    check_seed(0, Seed::from_hex(&vector.seeds.0).unwrap(), output.s1);
    check_seed(1, Seed::from_hex(&vector.seeds.1).unwrap(), output.s2);
    check_seed(2, Seed::from_hex(&vector.seeds.2).unwrap(), output.s3);
    // assert_eq!(vector.keys.private, output.private_key);
    assert_eq!(vector.keys.public,  output.address);
    println!();
  }
}
