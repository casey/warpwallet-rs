warpwallet
==========

[![crates.io
version](https://img.shields.io/crates/v/warpwallet.svg)](https://crates.io/crates/warpwallet)
[![Build Status](https://travis-ci.org/casey/warpwallet.svg?branch=master)](https://travis-ci.org/casey/warpwallet)

A rust implementation of [WarpWallet](https://keybase.io/warp).

Written by someone who barely understands how cryptography works, so you probably shouldn't use it.

The algorithm is:

```
s1  =	scrypt(key=(passphrase||0x1), salt=(salt||0x1), N=2^18, r=8, p=1, dkLen=32)
s2  =	pbkdf2(key=(passphrase||0x2), salt=(salt||0x2), c=2^16, dkLen=32, prf=HMAC_SHA256)
keypair = generate_bitcoin_keypair(s1 ⊕ s2)
```

todo
----

- actually derive keys
- print good messages for user facing errors
- test against provided test vectors
- derive a hd wallet mnemonic
- should i make it slower? --incompatible mode?
- derive with the same codepath as test
- end to end test against spec
