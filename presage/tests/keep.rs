//! What is kept of a message, against the SQLite store.

use chrono::{TimeZone, Utc};
use presage::libsignal_service::content::{Content, ContentBody, Metadata};
use presage::libsignal_service::proto::DataMessage;
use presage::libsignal_service::protocol::ServiceId;
use presage::libsignal_service::push_service::DEFAULT_DEVICE_ID;
use presage::manager::keep_profile_key;
use presage::model::contacts::Contact;
use presage::model::jobs::Job;
use presage::store::ContentsStore;
use presage_store_sqlite::{OnNewIdentity, SqliteStore};

const ALICE: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const BOB: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

fn id(s: &str) -> ServiceId {
    ServiceId::parse_from_service_id_string(s).unwrap()
}

fn content(sender: &str, timestamp: u64, body: ContentBody) -> Content {
    let at = Utc.timestamp_millis_opt(timestamp as i64).unwrap();
    Content {
        metadata: Metadata {
            sender: id(sender),
            destination: id(BOB),
            sender_device: *DEFAULT_DEVICE_ID,
            server_guid: None,
            client_timestamp: at,
            server_timestamp: at,
            needs_receipt: false,
            unidentified_sender: false,
            was_plaintext: false,
            pni_verified: None,
        },
        body,
    }
}

async fn store() -> SqliteStore {
    SqliteStore::open(":memory:", OnNewIdentity::Trust)
        .await
        .unwrap()
}

/// The key is stored with the message, not by the job that fetches the profile after it.
#[tokio::test]
async fn a_senders_profile_key_is_stored_before_their_profile_is_fetched() {
    let mut store = store().await;
    let with_key = |key: [u8; 32]| {
        content(
            ALICE,
            1000,
            ContentBody::DataMessage(DataMessage {
                body: Some("hi".into()),
                timestamp: Some(1000),
                profile_key: Some(key.to_vec()),
                expire_timer: Some(60),
                expire_timer_version: Some(2),
                ..Default::default()
            }),
        )
    };
    let fetch = |profile_key| Job::FetchProfile {
        aci: id(ALICE).raw_uuid().into_bytes(),
        profile_key,
        expire_timer: 60,
        expire_timer_version: 2,
    };

    let job = keep_profile_key(&mut store, &with_key([1; 32])).await;
    assert_eq!(job.unwrap(), Some(fetch([1; 32])));
    let stored = store.profile_key(&id(ALICE)).await.unwrap().unwrap();
    assert_eq!(stored.bytes, [1; 32]);
    assert!(store.contact_by_id(&id(ALICE)).await.unwrap().is_none());

    // No contact yet (the fetch failed, say): their next message asks for it again.
    let job = keep_profile_key(&mut store, &with_key([1; 32])).await;
    assert_eq!(job.unwrap(), Some(fetch([1; 32])));

    let contact = Contact {
        uuid: id(ALICE).raw_uuid(),
        phone_number: None,
        name: "Alice".into(),
        profile_key: vec![1; 32],
        expire_timer: 60,
        expire_timer_version: 2,
        inbox_position: 0,
        avatar: None,
        verified: Default::default(),
    };
    store.save_contact(&contact).await.unwrap();
    let job = keep_profile_key(&mut store, &with_key([1; 32])).await;
    assert_eq!(job.unwrap(), None);

    // A new key is stored at once too, and their profile fetched again.
    let job = keep_profile_key(&mut store, &with_key([2; 32])).await;
    assert_eq!(job.unwrap(), Some(fetch([2; 32])));
    let stored = store.profile_key(&id(ALICE)).await.unwrap().unwrap();
    assert_eq!(stored.bytes, [2; 32]);
}

#[tokio::test]
async fn a_message_without_a_profile_key_asks_for_nothing() {
    let mut store = store().await;
    let message = content(
        ALICE,
        1000,
        ContentBody::DataMessage(DataMessage {
            body: Some("hi".into()),
            timestamp: Some(1000),
            ..Default::default()
        }),
    );
    let job = keep_profile_key(&mut store, &message).await;
    assert_eq!(job.unwrap(), None);
    assert!(store.profile_key(&id(ALICE)).await.unwrap().is_none());
}
