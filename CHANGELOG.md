# Changelog

0.5.0-dev

- Changed (and fixed) the behaviour of the iterator returned by `SledStore::messages`:
  - The iterator yields elements in chronological order (used to be reversed)
  - The iterator now implements `DoubleEndedIterator` which means you it can be reversed or consumed from the end
  - The method now accepts the full range syntax, like `0..=1678295210` or `..` for all messages