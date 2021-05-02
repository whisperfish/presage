# Signal client/bot Rust library

![CI](https://github.com/whisperfish/presage/workflows/CI/badge.svg)

A Rust library that helps building clients for the [Signal Messenger](https://signal.org/en/), using [libsignal-service-rs](https://github.com/Michael-F-Bryan/libsignal-service-rs). It is designed to provide everything you need to get started.

> :warning: **The API is considered unstable** - I am still experimenting here.

Features:

- [x] Configuration and secrets storage (using [sled](https://github.com/spacejam/sled))
  - [ ] Local encryption
- [x] Registration
  - [x] SMS
  - [x] Voice call
- [x] Link as secondary device from Android / iOS app (like Signal Desktop)
- [x] Synchronize contacts from primary device (works, but not exposed currently)
- [x] Receive messages
- [ ] Fetch attachments (works, but not exposed currently)
- [x] Send messages
- [x] Groups support
