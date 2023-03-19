# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
