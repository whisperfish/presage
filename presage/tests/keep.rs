//! What is kept of a message, against the SQLite store.

use chrono::{TimeZone, Utc};
use presage::libsignal_service::content::{Content, ContentBody, Metadata};
use presage::libsignal_service::proto::{
    data_message::Delete, sync_message, DataMessage, EditMessage, SyncMessage, TypingMessage,
};
use presage::libsignal_service::protocol::ServiceId;
use presage::libsignal_service::push_service::DEFAULT_DEVICE_ID;
use presage::manager::{keep, keep_profile_key, Kept};
use presage::model::contacts::Contact;
use presage::model::jobs::Job;
use presage::store::{ContentsStore, Thread};
use presage_store_sqlite::{OnNewIdentity, SqliteStore};

const ALICE: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const BOB: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const NOBODY: &str = "00000000-0000-0000-0000-000000000000";
const TWO_DAYS_MS: u64 = 2 * 24 * 60 * 60 * 1000;

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

fn text(sender: &str, timestamp: u64, body: &str) -> Content {
    content(
        sender,
        timestamp,
        ContentBody::DataMessage(DataMessage {
            body: Some(body.to_owned()),
            timestamp: Some(timestamp),
            ..Default::default()
        }),
    )
}

fn delete(sender: &str, timestamp: u64, target: u64) -> Content {
    content(
        sender,
        timestamp,
        ContentBody::DataMessage(DataMessage {
            timestamp: Some(timestamp),
            delete: Some(Delete {
                target_sent_timestamp: Some(target),
            }),
            ..Default::default()
        }),
    )
}

fn edit_message(timestamp: u64, target: u64, body: &str) -> EditMessage {
    EditMessage {
        target_sent_timestamp: Some(target),
        data_message: Some(DataMessage {
            body: Some(body.to_owned()),
            timestamp: Some(timestamp),
            ..Default::default()
        }),
    }
}

fn edit(sender: &str, timestamp: u64, target: u64, body: &str) -> Content {
    let edit = edit_message(timestamp, target, body);
    content(sender, timestamp, ContentBody::EditMessage(edit))
}

/// The text a stored message shows, edited or not.
async fn stored_text(store: &SqliteStore, sender: &str, timestamp: u64) -> Option<String> {
    let thread = Thread::Contact(id(ALICE));
    let stored = store.message(&thread, &id(sender), timestamp).await;
    match stored.unwrap()?.body {
        ContentBody::DataMessage(message) => message.body,
        ContentBody::EditMessage(edit) => edit.data_message?.body,
        ContentBody::SynchronizeMessage(SyncMessage {
            content: Some(sync_message::Content::Sent(sent)),
            ..
        }) => sent.edit_message?.data_message?.body,
        _ => None,
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

#[tokio::test]
async fn a_message_is_stored_in_its_senders_thread() {
    let mut store = store().await;
    let kept = keep(&mut store, &text(ALICE, 1000, "hi"), None)
        .await
        .unwrap();
    assert_eq!(
        kept,
        Kept::Stored {
            thread: Thread::Contact(id(ALICE)),
            timestamp: 1000
        }
    );
    assert_eq!(
        stored_text(&store, ALICE, 1000).await.as_deref(),
        Some("hi")
    );
}

#[tokio::test]
async fn only_the_sender_deletes_their_message() {
    let mut store = store().await;
    keep(&mut store, &text(ALICE, 1000, "hi"), None)
        .await
        .unwrap();
    let thread = Thread::Contact(id(ALICE));
    // Bob's delete of Alice's message, in Alice's thread by the override.
    let refused = keep(&mut store, &delete(BOB, 2000, 1000), Some(thread.clone()))
        .await
        .unwrap();
    assert_eq!(refused, Kept::NotStored);
    assert_eq!(
        stored_text(&store, ALICE, 1000).await.as_deref(),
        Some("hi")
    );

    let deleted = keep(&mut store, &delete(ALICE, 2000, 1000), None)
        .await
        .unwrap();
    assert_eq!(
        deleted,
        Kept::Deleted {
            thread: thread.clone(),
            timestamp: 1000
        }
    );
    // The original is gone, and a tombstone of nobody's is in its place.
    assert!(store
        .message(&thread, &id(ALICE), 1000)
        .await
        .unwrap()
        .is_none());
    let stored = store
        .message(&thread, &id(NOBODY), 1000)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(stored.body, ContentBody::NullMessage(_)));
    // The delete itself is not stored.
    assert_eq!(store.messages(&thread, ..).await.unwrap().count(), 1);
}

#[tokio::test]
async fn a_delete_after_two_days_is_refused() {
    let mut store = store().await;
    keep(&mut store, &text(ALICE, 1000, "hi"), None)
        .await
        .unwrap();
    let refused = keep(&mut store, &delete(ALICE, 1000 + TWO_DAYS_MS, 1000), None)
        .await
        .unwrap();
    assert_eq!(refused, Kept::NotStored);
    assert_eq!(
        stored_text(&store, ALICE, 1000).await.as_deref(),
        Some("hi")
    );

    let deleted = keep(
        &mut store,
        &delete(ALICE, 1000 + TWO_DAYS_MS - 1, 1000),
        None,
    )
    .await
    .unwrap();
    assert!(matches!(deleted, Kept::Deleted { .. }));
}

#[tokio::test]
async fn a_second_edit_names_the_first_edits_time() {
    let mut store = store().await;
    let thread = Thread::Contact(id(ALICE));
    keep(&mut store, &text(ALICE, 1000, "one"), None)
        .await
        .unwrap();
    let first = keep(&mut store, &edit(ALICE, 2000, 1000, "two"), None)
        .await
        .unwrap();
    assert_eq!(
        first,
        Kept::Edited {
            thread: thread.clone(),
            timestamp: 1000
        }
    );
    // Signal's apps name the message by its latest edit.
    let second = keep(&mut store, &edit(ALICE, 3000, 2000, "three"), None)
        .await
        .unwrap();
    assert_eq!(
        second,
        Kept::Edited {
            thread: thread.clone(),
            timestamp: 1000
        }
    );
    let stored = store
        .message(&thread, &id(ALICE), 1000)
        .await
        .unwrap()
        .unwrap();
    let ContentBody::EditMessage(edit) = stored.body else {
        panic!("the edit takes the message's place");
    };
    assert_eq!(edit.target_sent_timestamp, Some(1000));
    assert_eq!(edit.data_message.unwrap().body.as_deref(), Some("three"));
    assert_eq!(store.messages(&thread, ..).await.unwrap().count(), 1);
}

#[tokio::test]
async fn a_delete_of_an_edited_message_names_the_edits_time() {
    let mut store = store().await;
    let thread = Thread::Contact(id(ALICE));
    keep(&mut store, &text(ALICE, 1000, "one"), None)
        .await
        .unwrap();
    keep(&mut store, &edit(ALICE, 2000, 1000, "two"), None)
        .await
        .unwrap();
    let deleted = keep(&mut store, &delete(ALICE, 3000, 2000), None)
        .await
        .unwrap();
    assert_eq!(
        deleted,
        Kept::Deleted {
            thread: thread.clone(),
            timestamp: 1000
        }
    );
    assert!(store
        .message(&thread, &id(ALICE), 1000)
        .await
        .unwrap()
        .is_none());
}

/// An edit sent from another device of ours comes in a sync message.
#[tokio::test]
async fn a_second_edit_from_our_other_device_finds_the_message() {
    let mut store = store().await;
    let thread = Thread::Contact(id(ALICE));
    let sent = |timestamp, message, edit_message| {
        content(
            BOB,
            timestamp,
            ContentBody::SynchronizeMessage(SyncMessage {
                content: Some(sync_message::Content::Sent(sync_message::Sent {
                    destination_service_id: Some(ALICE.into()),
                    timestamp: Some(timestamp),
                    message,
                    edit_message,
                    ..Default::default()
                })),
                ..Default::default()
            }),
        )
    };
    let original = DataMessage {
        body: Some("one".into()),
        timestamp: Some(1000),
        ..Default::default()
    };
    keep(&mut store, &sent(1000, Some(original), None), None)
        .await
        .unwrap();
    for (timestamp, target, body) in [(2000, 1000, "two"), (3000, 2000, "three")] {
        let edit = edit_message(timestamp, target, body);
        let kept = keep(&mut store, &sent(timestamp, None, Some(edit)), None)
            .await
            .unwrap();
        assert_eq!(
            kept,
            Kept::Edited {
                thread: thread.clone(),
                timestamp: 1000
            }
        );
    }
    assert_eq!(
        stored_text(&store, BOB, 1000).await.as_deref(),
        Some("three")
    );
    assert_eq!(store.messages(&thread, ..).await.unwrap().count(), 1);
}

#[tokio::test]
async fn an_edit_by_someone_else_is_refused() {
    let mut store = store().await;
    keep(&mut store, &text(ALICE, 1000, "one"), None)
        .await
        .unwrap();
    let thread = Thread::Contact(id(ALICE));
    let refused = keep(&mut store, &edit(BOB, 2000, 1000, "two"), Some(thread))
        .await
        .unwrap();
    assert_eq!(refused, Kept::NotStored);
    assert_eq!(
        stored_text(&store, ALICE, 1000).await.as_deref(),
        Some("one")
    );
}

#[tokio::test]
async fn typing_is_not_stored() {
    let mut store = store().await;
    let typing = content(
        ALICE,
        1000,
        ContentBody::TypingMessage(TypingMessage::default()),
    );
    let kept = keep(&mut store, &typing, None).await.unwrap();
    assert_eq!(kept, Kept::NotStored);
}

#[tokio::test]
async fn two_senders_messages_at_one_millisecond_are_both_kept() {
    let mut store = store().await;
    let thread = Thread::Contact(id(ALICE));
    keep(&mut store, &text(ALICE, 1000, "mine"), None)
        .await
        .unwrap();
    let theirs = keep(&mut store, &text(BOB, 1000, "theirs"), Some(thread.clone()))
        .await
        .unwrap();
    assert_eq!(
        theirs,
        Kept::Stored {
            thread: thread.clone(),
            timestamp: 1000
        }
    );
    assert_eq!(
        stored_text(&store, ALICE, 1000).await.as_deref(),
        Some("mine")
    );
    assert_eq!(
        stored_text(&store, BOB, 1000).await.as_deref(),
        Some("theirs")
    );
}

#[tokio::test]
async fn a_delete_finds_only_its_senders_message() {
    let mut store = store().await;
    let thread = Thread::Contact(id(ALICE));
    keep(&mut store, &text(ALICE, 1000, "mine"), None)
        .await
        .unwrap();
    keep(&mut store, &text(BOB, 1000, "theirs"), Some(thread.clone()))
        .await
        .unwrap();
    // Bob's delete names the time both were sent at: his goes, hers stays.
    let deleted = keep(&mut store, &delete(BOB, 2000, 1000), Some(thread.clone()))
        .await
        .unwrap();
    assert!(matches!(deleted, Kept::Deleted { .. }));
    assert_eq!(
        stored_text(&store, ALICE, 1000).await.as_deref(),
        Some("mine")
    );
    assert!(store
        .message(&thread, &id(BOB), 1000)
        .await
        .unwrap()
        .is_none());
}
