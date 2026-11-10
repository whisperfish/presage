//! The account's keys and the manager's services, against the SQLite store.

use presage::libsignal_service::libsignal_account_keys::AccountEntropyPool;
use presage::libsignal_service::master_key::{MasterKey, StorageServiceKey};
use presage::libsignal_service::prelude::phonenumber;
use presage::manager::{AccountKeys, Registered, RegistrationData};
use presage::store::StateStore;
use presage::Manager;
use presage_store_sqlite::{OnNewIdentity, SqliteStore};

async fn store() -> SqliteStore {
    SqliteStore::open(":memory:", OnNewIdentity::Trust)
        .await
        .unwrap()
}

/// A manager of a linked device, without a connection.
async fn linked(mut store: SqliteStore) -> Manager<SqliteStore, Registered> {
    let phone_number = phonenumber::parse(None, "+14155550100").unwrap();
    let registration = serde_json::json!({
        "signal_servers": "Staging",
        "device_name": "linked",
        "phone_number": phone_number,
        "uuid": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "pni": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "password": "password",
        "device_id": 2,
        "registration_id": 1,
        "pni_registration_id": 1,
        "profile_key": "a2FpanBxeGR2YWlhZWF1bG1zcm96Y2tqa2dicGpvd2M=",
    });
    // From a string: the profile key reads as a borrowed one.
    let registration: RegistrationData = serde_json::from_str(&registration.to_string()).unwrap();
    store.save_registration_data(&registration).await.unwrap();
    Manager::load_registered(store).await.unwrap()
}

#[tokio::test]
async fn the_keys_come_from_the_pool_and_else_from_the_stored_master_key() {
    let store = store().await;
    assert_eq!(AccountKeys::load(&store).await.unwrap(), None);

    // Stored at linking, before the pool existed.
    let stored = MasterKey::generate(&mut rand::rng());
    store.store_master_key(Some(&stored)).await.unwrap();
    let keys = AccountKeys::load(&store).await.unwrap().unwrap();
    assert_eq!(keys.master_key(), &stored);

    // Received later in a key sync: the stored master key is not the pool's.
    let pool = AccountEntropyPool::generate(&mut rand::rng());
    store.store_account_entropy_pool(Some(&pool)).await.unwrap();
    let keys = AccountKeys::load(&store).await.unwrap().unwrap();
    assert_eq!(keys.master_key().inner, pool.derive_svr_key());
}

/// A linked device that got its pool in a key sync has no stored master key.
#[tokio::test]
async fn the_pool_alone_gives_the_storage_key() {
    let store = store().await;
    let pool = AccountEntropyPool::generate(&mut rand::rng());
    store.store_account_entropy_pool(Some(&pool)).await.unwrap();
    assert_eq!(store.fetch_master_key().await.unwrap(), None);

    let keys = AccountKeys::load(&store).await.unwrap().unwrap();
    let master_key = MasterKey {
        inner: pool.derive_svr_key(),
    };
    assert_eq!(
        keys.storage_key(),
        StorageServiceKey::from_master_key(&master_key)
    );
}

#[tokio::test]
async fn services_have_the_storage_key_once_the_keys_are_known() {
    let store = store().await;
    let manager = linked(store.clone()).await;
    let services = manager.services().await.unwrap();
    assert_eq!(services.account_keys, None);
    assert!(services.storage_service().await.unwrap().is_none());

    let pool = AccountEntropyPool::generate(&mut rand::rng());
    store.store_account_entropy_pool(Some(&pool)).await.unwrap();
    let services = manager.services().await.unwrap();
    assert_eq!(services.account_keys, Some(AccountKeys::from_pool(&pool)));
}
