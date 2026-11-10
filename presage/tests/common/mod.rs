use presage::libsignal_service::prelude::phonenumber;
use presage::manager::{Registered, RegistrationData};
use presage::store::StateStore;
use presage::Manager;
use presage_store_sqlite::{OnNewIdentity, SqliteStore};

pub async fn store() -> SqliteStore {
    SqliteStore::open(":memory:", OnNewIdentity::Trust)
        .await
        .unwrap()
}

/// A manager of a linked device, without a connection.
pub async fn linked(mut store: SqliteStore) -> Manager<SqliteStore, Registered> {
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
