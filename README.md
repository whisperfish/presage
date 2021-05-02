# Presage

![CI](https://github.com/whisperfish/presage/workflows/CI/badge.svg)
![License](https://shields.io/github/license/whisperfish/presage.svg)

A Rust library that helps building clients for the [Signal Messenger](https://signal.org/en/), using [libsignal-service-rs](https://github.com/whisperfish/libsignal-service-rs). It is designed to provide everything you need to get started.

> :warning: **The API is considered unstable** - I am still experimenting here.

Features:

- [x] Configuration and secrets storage (using [sled](https://github.com/spacejam/sled))
  - [ ] Local encryption
- [x] Registration
  - [x] SMS
  - [x] Voice call
- [x] Link as secondary device from Android / iOS app (like Signal Desktop)
- [x] Synchronize contacts from primary device
- [x] Receive messages
- [ ] Fetch attachments (works, but not exposed currently)
- [x] Send messages
- [x] Groups support

## Instructions

Included in this repository is a CLI very similar (on purpose) to the great [signal-cli](https://github.com/AsamK/signal-cli):

```
# print help section
cargo run -- --help

# link as secondary device, a PNG with a QR code to scan should open
cargo run -- link-device --device-name presage

# start receiving messages
cargo run -- receive
```

For usage of the library, a few examples will be included under the `examples/` directory, but you might want to have a look
at [src/main.rs](src/main.rs) for now.
