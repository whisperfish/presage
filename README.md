# Signal client/bot Rust library

This intends to be a high-level library to build bot and clients for [Signal](https://signal.org/en/) using [libsignal-service-rs](https://github.com/Michael-F-Bryan/libsignal-service-rs) and [libsignal-protocol-rs](https://github.com/Michael-F-Bryan/libsignal-protocol-rs).

> :warning: **The API is considered unstable** - I am still experimenting here.

Features:


- [x] Configuration storage (using [sled](https://github.com/spacejam/sled))
- [x] Registration
  - [x] SMS
  - [x] Voice
- [x] Link as secondary device from Android / iOS app
- [x] Receive messages
- [ ] Fetch attachments on local filesystem
- [ ] Send messages
  - [ ] Reactions
- [ ] Groups support
  - [ ] v1
  - [ ] v2 (mentions)

NB: some features will be implemented directly in `libsignal-service-rs` and mirrored here.
