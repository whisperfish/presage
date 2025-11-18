# Presage

![CI Build](https://github.com/whisperfish/presage/workflows/Build/badge.svg)
![License](https://img.shields.io/github/license/whisperfish/presage)
[![API Docs](https://img.shields.io/badge/docs-presage-blue)](https://whisperfish.github.io/presage/presage)

A Rust library that helps building clients for the [Signal Messenger](https://signal.org/en/), using [libsignal-service-rs](https://github.com/whisperfish/libsignal-service-rs). It is designed to provide everything you need to get started.

Features:

- [x] Local storage with [sqlx](https://crates.io/sqlx) and `sqlite` (see #287) with optional encryption with `sqlcipher` (fixed in #335)
- [x] Registration
  - [x] SMS
  - [x] Voice call
- [x] Link as secondary device from Android / iOS app (like Signal Desktop)
- [x] Contacts (synchronized from primary device) and profiles
- [x] Groups
- [x] Messages (incoming and outgoing)
- [x] Fetch, decrypt and store attachments

## Instructions

Add the following to your `Cargo.toml`:

```toml
[dependencies]
presage = { git = "https://github.com/whisperfish/presage" }
presage-store-sled = { git = "https://github.com/whisperfish/presage" }

# For a discussion as to why, see: 
# https://github.com/whisperfish/libsignal-service-rs/tree/93c23cf27d27a17a803e34ea3dd6a82d268fa79e#working-around-the-issue-with-curve25519-dalek
[patch.crates-io]
curve25519-dalek = { git = 'https://github.com/signalapp/curve25519-dalek', tag = 'signal-curve25519-4.1.3' }
```

and look at the generated Rust documentation of the `Manager` struct to get started.

## Demo CLI

Included in this repository is a nearly fully functional CLI that can serve as an example to build your client (you can also use it to query your `presage` database):

```
# print help section
cargo run -- --help

# link as secondary device, a PNG with a QR code to scan should open
cargo run -- link-device --device-name presage

# start receiving messages
cargo run -- receive
```
