# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Only `DataMessage` that are sent, received, or sent from another device are saved in the local store (#137)

- Changed (and fixed) the behaviour of the iterator returned by `SledStore::messages` (#119)
  * The iterator yields elements in chronological order (used to be reversed)
  * The iterator now implements `DoubleEndedIterator` which means you it can be reversed or consumed from the end
  * The method now accepts the full range syntax, like `0..=1678295210` or `..` for all messages

[unreleased]: https://github.com/whisperfish/presage/compare/0.4.0...HEAD
