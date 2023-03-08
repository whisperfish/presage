# Changelog

0.5.0-dev

- Changed (and fixed) the behaviour of the iterator returned by `SledStore::messages`. The order of messages is now from past to most recent messages, and the iterator can be reversed. The method now accepts the range syntax, like `0..=1678295210`.