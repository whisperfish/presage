# presage-store-sqlite

This is a store implementation for [`presage`](https://github.com/whisperfish/presage) using `sqlite` database.

## Features

- `runtime-tokio` - enables usage of [`tokio` runtime by `sqlx` crate](https://docs.rs/sqlx/latest/sqlx/) (*enabled by default*).
- `runtime-async-std` - enables usage of [`async-std` runtime by `sqlx` crate](https://docs.rs/sqlx/latest/sqlx/).
- `bundled` - bundles `sqlite` library with binary. Disable this feature only when you have linker errors, when other libraries try to bundle `sqlite` too (*enabled by default*).
