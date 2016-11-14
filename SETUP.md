Setup for a new developer:

- [ ] Install rust and cargo with [rustup](https://www.rustup.rs/)
- [ ] Install `just` with `cargo install just`
- [ ] Add `alias j=just` to your shell config to save a little typing
- [ ] Install other development dependencies with `just install-dev-dependencies`
- [ ] Tell your editor to use makefile syntax hilighting for justfiles
- [ ] Run `git remote add upstream git@github.com:ACCOUNT/PROJECT.git`.
      The `upstream` remote is used by a few justfile recipes as the repo where collaborative
      and public development occurs, as distinct from a personal fork or backup repo. 
