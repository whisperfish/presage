//! What is kept of a message.

use libsignal_service::{
    content::{Content, ContentBody},
    prelude::Uuid,
    proto::{
        addressable_message::Author,
        data_message::Delete,
        sync_message::{self, Content as SyncContent},
        DataMessage, EditMessage, NullMessage, SyncMessage,
    },
    protocol::{Aci, ServiceId},
    zkgroup::profiles::ProfileKey,
    ServiceIdExt,
};
use tracing::{debug, warn};

use crate::model::jobs::Job;
use crate::store::{ContentExt, Store, Thread};
use crate::Error;

/// How long after sending a message its sender can still delete it for everyone, as received.
/// Signal-Android accepts its send window, a day by default, plus a day:
/// [MessageConstraintsUtil](https://github.com/signalapp/Signal-Android/blob/main/app/src/main/java/org/thoughtcrime/securesms/util/MessageConstraintsUtil.kt).
const DELETE_FOR_EVERYONE_WINDOW_MS: u64 = 2 * 24 * 60 * 60 * 1000;

/// What [`keep`] did with a message.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Kept {
    /// Stored in `thread` under its sender and `timestamp`, where [`ContentsStore::message`]
    /// finds it.
    ///
    /// [`ContentsStore::message`]: crate::store::ContentsStore::message
    Stored { thread: Thread, timestamp: u64 },
    /// An edit, stored in the place of its sender's message sent at `timestamp`.
    Edited { thread: Thread, timestamp: u64 },
    /// Its sender's message sent at `timestamp` deleted for everyone.
    Deleted { thread: Thread, timestamp: u64 },
    /// Nothing stored: there was nothing to store, or what it names isn't its sender's.
    NotStored,
}

/// Stores `message` as receiving does: a delete or an edit applied to the sender's own message,
/// a contact's expire timer updated. `thread` names the thread of an outgoing message, which
/// its content doesn't say.
pub async fn keep<S: Store>(
    store: &mut S,
    message: &Content,
    thread: Option<Thread>,
) -> Result<Kept, Error<S::Error>> {
    let thread = match thread {
        Some(thread) => thread,
        None => Thread::try_from(message)?,
    };

    // only save DataMessage and SynchronizeMessage (sent)
    match &message.body {
        ContentBody::DecryptionErrorMessage(e) => {
            warn!(error = ?e, "was asked to save a DecryptionErrorMessage; this should not happen");
            return Ok(Kept::NotStored);
        }
        ContentBody::NullMessage(_) => {}
        ContentBody::DataMessage(data_message)
        | ContentBody::SynchronizeMessage(SyncMessage {
            content:
                Some(SyncContent::Sent(sync_message::Sent {
                    message: Some(data_message),
                    ..
                })),
            ..
        }) => {
            // Note: The expire timer fields of data messages are only for contacts.
            // Expire timers are handled for groups via upsert_group due to a revision change.
            if let Thread::Contact(_) = thread {
                let version = data_message.expire_timer_version.unwrap_or(1);
                store
                    .update_expire_timer(
                        &thread,
                        data_message.expire_timer.unwrap_or_default(),
                        version,
                    )
                    .await?;
            }

            if let DataMessage {
                delete:
                    Some(Delete {
                        target_sent_timestamp: Some(ts),
                    }),
                ..
            } = data_message
            {
                return delete_for_everyone(store, thread, message, *ts).await;
            }
        }
        ContentBody::SynchronizeMessage(SyncMessage {
            content: Some(SyncContent::DeleteForMe(delete)),
            ..
        }) => {
            // TODO: Conversations, local-only deletes, attachments
            for d in delete.message_deletes.iter().flat_map(|m| &m.messages) {
                let sender = match &d.author {
                    Some(Author::AuthorServiceId(id)) => {
                        ServiceId::parse_from_service_id_string(id)
                    }
                    Some(Author::AuthorServiceIdBinary(id)) => {
                        ServiceId::parse_from_service_id_binary(id)
                    }
                    Some(Author::AuthorE164(_)) => None,
                    None => None,
                };
                let Some(sender) = sender else {
                    warn!("Could not parse author of delete-for-self message; ignoring.");
                    continue;
                };
                let Some(timestamp) = d.sent_timestamp else {
                    warn!("Timestamp of delete-for-self message not given; ignoring.");
                    continue;
                };
                let Ok(Some(thread)) = store
                    .thread_for_sender_and_timestamp(&sender, timestamp)
                    .await
                else {
                    warn!("Message referenced by delete-for-self message not found; ignoring.");
                    continue;
                };
                // Note: Not marking the message as deleted, like when receiving deletion requests by others.
                // This matches the behavior of Signal Desktop, where the message completely disappears from the timeline.
                let result = store.delete_message(&thread, &sender, timestamp).await;
                if !result.is_ok_and(|d| d) {
                    warn!(
                        "Could not delete message referenced by delete-for-self message; ignoring."
                    );
                }
            }
            return Ok(Kept::NotStored);
        }
        ContentBody::EditMessage(EditMessage {
            target_sent_timestamp: Some(target),
            data_message: Some(_),
        })
        | ContentBody::SynchronizeMessage(SyncMessage {
            content:
                Some(SyncContent::Sent(sync_message::Sent {
                    edit_message:
                        Some(EditMessage {
                            target_sent_timestamp: Some(target),
                            data_message: Some(_),
                        }),
                    ..
                })),
            ..
        }) => return edit(store, thread, message, *target).await,
        // Call signaling is transient; calls are recorded by `CallEvent`s instead.
        ContentBody::CallMessage(_) => return Ok(Kept::NotStored),
        ContentBody::SynchronizeMessage(SyncMessage {
            content: Some(SyncContent::CallEvent(_)),
            ..
        }) => {}
        ContentBody::SynchronizeMessage(msg) => {
            debug!(
                ?msg,
                "skipping saving sync message without interesting fields"
            );
            return Ok(Kept::NotStored);
        }
        ContentBody::ReceiptMessage(_) => {}
        ContentBody::TypingMessage(msg) => {
            debug!(?msg, "skipping saving typing message");
            return Ok(Kept::NotStored);
        }
        ContentBody::StoryMessage(msg) => {
            debug!(?msg, "skipping story message");
            return Ok(Kept::NotStored);
        }
        ContentBody::EditMessage(msg) => {
            debug!(?msg, "invalid edited");
            return Ok(Kept::NotStored);
        }
    }

    // A message is stored by thread, time and sender: it takes the place of none but its
    // sender's own.
    let timestamp = message.metadata.client_timestamp.timestamp_millis() as u64;
    store.save_message(&thread, message.clone()).await?;
    Ok(Kept::Stored { thread, timestamp })
}

/// Replaces the sender's message that `target` names by an empty `NullMessage` of nobody's, if
/// it is recent enough. Only the sender's own is found: a message is known by its sender and
/// time.
async fn delete_for_everyone<S: Store>(
    store: &mut S,
    thread: Thread,
    message: &Content,
    target: u64,
) -> Result<Kept, Error<S::Error>> {
    let sender = message.metadata.sender;
    let sent = message.metadata.client_timestamp.timestamp_millis() as u64;
    match store
        .message_sent_or_edited_at(&thread, &sender, target)
        .await?
    {
        Some(mut existing) if sent.saturating_sub(target) < DELETE_FOR_EVERYONE_WINDOW_MS => {
            let timestamp = existing.metadata.client_timestamp.timestamp_millis() as u64;
            store.delete_message(&thread, &sender, timestamp).await?;
            // replace the existing message by an empty NullMessage
            existing.metadata.sender = Aci::from(Uuid::nil()).into();
            existing.body = NullMessage::default().into();
            store.save_message(&thread, existing).await?;
            debug!(%thread, timestamp, "message in thread deleted");
            Ok(Kept::Deleted { thread, timestamp })
        }
        Some(_) => {
            warn!(%thread, target, "ignoring delete of a message too old");
            Ok(Kept::NotStored)
        }
        None => {
            warn!(%thread, target, "could not find the sender's message to delete in thread");
            Ok(Kept::NotStored)
        }
    }
}

/// Stores an edit in the place of its sender's message it edits, naming it by its first time,
/// also when the edit names an earlier edit's.
async fn edit<S: Store>(
    store: &mut S,
    thread: Thread,
    message: &Content,
    target: u64,
) -> Result<Kept, Error<S::Error>> {
    match store
        .message_sent_or_edited_at(&thread, &message.metadata.sender, target)
        .await?
    {
        Some(original) => {
            let mut edit = message.clone();
            edit.metadata.client_timestamp = original.metadata.client_timestamp;
            retarget_edit(&mut edit, original.timestamp());
            let timestamp = edit.metadata.client_timestamp.timestamp_millis() as u64;
            store.save_message(&thread, edit).await?;
            Ok(Kept::Edited { thread, timestamp })
        }
        None => {
            warn!(%thread, target, "ignoring edit of a message that isn't its sender's or not found");
            Ok(Kept::NotStored)
        }
    }
}

/// Points an edit at `original`, the first time of the message it edits.
fn retarget_edit(edit: &mut Content, original: u64) {
    match &mut edit.body {
        ContentBody::SynchronizeMessage(SyncMessage {
            content:
                Some(SyncContent::Sent(sync_message::Sent {
                    edit_message: Some(edit),
                    ..
                })),
            ..
        })
        | ContentBody::EditMessage(edit) => edit.target_sent_timestamp = Some(original),
        _ => {}
    }
}

/// Stores the profile key `message` carries for its sender, before the message is handed on:
/// sending to them by sealed sender needs it. Returns the job that fetches the profile of a
/// sender who is no contact yet, or whose key changed.
pub async fn keep_profile_key<S: Store>(
    store: &mut S,
    message: &Content,
) -> Result<Option<Job>, Error<S::Error>> {
    let (ContentBody::DataMessage(data_message)
    | ContentBody::SynchronizeMessage(SyncMessage {
        content:
            Some(SyncContent::Sent(sync_message::Sent {
                message: Some(data_message),
                ..
            })),
        ..
    })) = &message.body
    else {
        return Ok(None);
    };
    let Some(profile_key_bytes) = data_message
        .profile_key
        .as_deref()
        .and_then(|key| <[u8; 32]>::try_from(key).ok())
    else {
        return Ok(None);
    };
    let sender = message.metadata.sender;
    let Some(aci) = sender.aci() else {
        debug!("not storing profile for PNI contact");
        return Ok(None);
    };

    let profile_key = ProfileKey::create(profile_key_bytes);
    let changed = store
        .profile_key(&sender)
        .await?
        .is_none_or(|known| known.bytes != profile_key.bytes);
    if changed {
        debug!(sender = %sender.service_id_string(), "inserting profile key for");
        store.upsert_profile_key(&aci.into(), profile_key).await?;
    }

    // Either:
    // - insert a new contact with the profile information
    // - update the contact if the profile key has changed
    // TODO: mark this contact as "created by us" maybe to know whether we should update it or not
    if changed || store.contact_by_id(&sender).await?.is_none() {
        return Ok(Some(Job::FetchProfile {
            aci: Uuid::from(aci).into_bytes(),
            profile_key: profile_key_bytes,
            expire_timer: data_message.expire_timer.unwrap_or_default(),
            expire_timer_version: data_message.expire_timer_version.unwrap_or(1),
        }));
    }
    Ok(None)
}
