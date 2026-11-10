//! What is kept of a message.

use libsignal_service::{
    content::{Content, ContentBody},
    prelude::Uuid,
    proto::{
        sync_message::{self, Content as SyncContent},
        SyncMessage,
    },
    zkgroup::profiles::ProfileKey,
    ServiceIdExt,
};
use tracing::debug;

use crate::model::jobs::Job;
use crate::store::Store;
use crate::Error;

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
