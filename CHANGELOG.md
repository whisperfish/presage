# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

### Fixed

### Changed

## [0.5.1]

Note: this release splits the project into multiple crates, to prepare for adding concurrent store implementations.
While this might seem like a breaking change, the API has not been altered and your `Cargo.toml` should now look like:

```toml
[dependencies]
presage = { git = "https://github.com/whisperfish/presage" }
presage-store-sled = { git = "https://github.com/whisperfish/presage" }
```

and then get the store implementation from the store crate instead when importing it like `use presage_store_sled::SledStore;`.

### Added

- Add `Manager::submit_recaptcha_challenge`. (#143)
- Cache profile API responses. (#134)
- Add `is_registered` method to the store trait. (#156)

### Fixed

- Fix sending with example CLI. (#140)
- Fix sending with example CLI. (#140)
- Fix sending duplicate messages to group for other clients (like Signal Desktop). (#142)
- Fix storing of outgoing messages. (#144)

### Changed

- Handle message deletion sent by contacts. (#147)
- Split `presage` into multiple crates, before introducing additional store implementations. (#148)
- Messages are now sent, whenever possible (which should be all the time), as [sealed sender](https://signal.org/blog/sealed-sender/). [#159]
- Split project into multiple crates. (#148)

## [0.5.0]

### Added

- Group storage: group metadata is now stored in a local cache, to avoid issuing an API call whenever 
  group details need to be looked up. (#88)
- Optional desktop notifications in CLI. (#85)
- Add function to clear messages only. (#115)

### Fixed

- Fix get contact by ID method. (#91)
- Fix the key used when storing messages. (#111)
- Fix unlink when clearing store. (#112)

### Changed

- Improve sending messages speed by updating `libsignal-service-rs` and using its websocket in duplex mode (#92). Because of this change, polling on the stream returned by `Manager::receive_messages` is now required to send messages.
- Only `DataMessage` that are sent, received, or sent from another device are saved in the local store (#137).
- Changed (and fixed) the behaviour of the iterator returned by `SledStore::messages` (#119)
  * The iterator yields elements in chronological order (used to be reversed).
  * The iterator now implements `DoubleEndedIterator` which means you it can be reversed or consumed from the end.
  * The method now accepts the full range syntax, like `0..=1678295210` or `..` for all messages.
- Wait for contacts sync to be received and processed when linking as secondary device. (#106)
- Encrypt registration data (when store encryption is enabled). (#114)

[0.5.0]: https://github.com/whisperfish/presage/compare/0.4.0...0.5.0
[0.5.1]: https://github.com/whisperfish/presage/compare/0.5.0...0.5.1
[Unreleased]: https://github.com/whisperfish/presage/compare/0.5.1...main