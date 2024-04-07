# Presage

![CI Build](https://github.com/whisperfish/presage/workflows/Build/badge.svg)
![License](https://img.shields.io/github/license/whisperfish/presage)
[![API Docs](https://img.shields.io/badge/docs-presage-blue)](https://whisperfish.github.io/presage/presage)

A Rust library that helps building clients for the [Signal Messenger](https://signal.org/en/), using [libsignal-service-rs](https://github.com/whisperfish/libsignal-service-rs). It is designed to provide everything you need to get started.

Features:

- [x] Local storage (using [sled](https://github.com/spacejam/sled))
  - [x] Registration/linking
  - [x] Contacts
  - [x] Groups
  - [x] Messages
  - [x] Local encryption (using [matrix-sdk-store-encryption](https://crates.io/crates/matrix-sdk-store-encryption))
- [x] Registration
  - [x] SMS
  - [x] Voice call
- [x] Link as secondary device from Android / iOS app (like Signal Desktop)
- [x] Synchronize contacts from primary device
- [x] Receive messages
- [x] Handle groups v2 (and change events)
- [x] Download + decrypt attachments
- [x] Send messages
- [x] Groups support

## Instructions

Add the following to your `Cargo.toml`:

```toml
[dependencies]
presage = { git = "https://github.com/whisperfish/presage" }
presage-store-sled = { git = "https://github.com/whisperfish/presage" }

# For a discussion as to why, see: 
# https://github.com/whisperfish/libsignal-service-rs#working-around-the-issue-with-curve25519-dalek
[patch.crates-io]
curve25519-dalek = { git = 'https://github.com/signalapp/curve25519-dalek', tag = 'signal-curve25519-4.1.1' }
```

and look at the generated Rust documentation of the `Manager` struct to get started.

## Demo CLI

Included in this repository is a CLI very similar (on purpose) to the great [signal-cli](https://github.com/AsamK/signal-cli):

```
# print help section
cargo run -- --help

# link as secondary device, a PNG with a QR code to scan should open
cargo run -- link-device --device-name presage

# start receiving messages
cargo run -- receive
```

For using the library, the CLI is a good starting point to learn how the API can be used.
