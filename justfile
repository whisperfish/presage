database_url := ("sqlite://" + justfile_directory() + "/test.db")

prepare-sqlx: setup-sqlx-db
    cargo sqlx prepare --workspace --database-url "{{database_url}}"

[working-directory: "presage-store-sqlite"]
setup-sqlx-db:
    cargo sqlx database setup --database-url "{{database_url}}"

install-sqlx:
    cargo binstall sqlx-cli@v0.8.3
