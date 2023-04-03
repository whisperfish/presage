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

Included in this repository is a CLI very similar (on purpose) to the great [signal-cli](https://github.com/AsamK/signal-cli):

```
# print help section
cargo run --example=cli -- --help

# link as secondary device, a PNG with a QR code to scan should open
cargo run --example=cli -- link-device --device-name presage

# start receiving messages
cargo run --example=cli -- receive
```

For usage of the library, a few examples are included under the `examples/` directory, and most features are demonstrated
in [examples/cli.rs](./examples/cli.rs).
