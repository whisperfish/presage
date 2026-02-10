//! Traits that are used by the manager for storing the data.

use std::{fmt, future::Future, ops::RangeBounds, time::SystemTime};

use libsignal_service::{
    content::{ContentBody, Metadata},
    groups_v2::Timer,
    pre_keys::PreKeysStore,
    prelude::{Content, MasterKey, ProfileKey, Uuid, UuidError},
    proto::{
        sync_message::{self, Sent},
        verified, DataMessage, EditMessage, GroupContextV2, SyncMessage, Verified,
    },
    protocol::{
        IdentityKey, IdentityKeyPair, ProtocolAddress, ProtocolStore, SenderCertificate,
        SenderKeyStore, ServiceId,
    },
    push_service::DEFAULT_DEVICE_ID,
    session_store::SessionStoreExt,
    zkgroup::GroupMasterKeyBytes,
    Profile,
};
use serde::{Deserialize, Serialize};
use tracing::trace;

use crate::{
    manager::RegistrationData,
    model::{contacts::Contact, groups::Group},
    AvatarBytes,
};

/// An error trait implemented by store error types
pub trait StoreError: std::error::Error + Sync + Send {}

/// Stores the registered state of the manager
pub trait StateStore {
    type StateStoreError: StoreError;

    /// Load registered (or linked) state
    fn load_registration_data(
        &self,
    ) -> impl Future<Output = Result<Option<RegistrationData>, Self::StateStoreError>>;

    fn set_aci_identity_key_pair(
        &self,
        key_pair: IdentityKeyPair,
    ) -> impl Future<Output = Result<(), Self::StateStoreError>>;

    fn set_pni_identity_key_pair(
        &self,
        key_pair: IdentityKeyPair,
    ) -> impl Future<Output = Result<(), Self::StateStoreError>>;

    /// Save registered (or linked) state
    fn save_registration_data(
        &mut self,
        state: &RegistrationData,
    ) -> impl Future<Output = Result<(), Self::StateStoreError>> + Send;

    fn sender_certificate(
        &self,
    ) -> impl Future<Output = Result<Option<SenderCertificate>, Self::StateStoreError>>;

    fn save_sender_certificate(
        &self,
        certificate: &SenderCertificate,
    ) -> impl Future<Output = Result<(), Self::StateStoreError>>;

    /// Returns whether this store contains registration data or not
    fn is_registered(&self) -> impl Future<Output = bool>;

    /// Clear registration data (including keys), but keep received messages, groups and contacts.
    fn clear_registration(&mut self) -> impl Future<Output = Result<(), Self::StateStoreError>>;

    fn fetch_master_key(
        &self,
    ) -> impl Future<Output = Result<Option<MasterKey>, Self::StateStoreError>>;

    fn store_master_key(
        &self,
        master_key: Option<&MasterKey>,
    ) -> impl Future<Output = Result<(), Self::StateStoreError>>;
}

/// Stores messages, contacts, groups and profiles
pub trait ContentsStore: Send + Sync {
    type ContentsStoreError: StoreError;

    /// Iterator over the contacts
    type ContactsIter: Iterator<Item = Result<Contact, Self::ContentsStoreError>>;

    /// Iterator over all stored groups
    ///
    /// Each items is a tuple consisting of the group master key and its corresponding data.
    type GroupsIter: Iterator<Item = Result<(GroupMasterKeyBytes, Group), Self::ContentsStoreError>>;

    /// Iterator over all stored messages
    type MessagesIter: Iterator<Item = Result<Content, Self::ContentsStoreError>>;

    /// Iterator over all stored sticker packs
    type StickerPacksIter: Iterator<Item = Result<StickerPack, Self::ContentsStoreError>>;

    // Clear all profiles
    fn clear_profiles(&mut self) -> impl Future<Output = Result<(), Self::ContentsStoreError>>;

    // Clear all stored messages
    fn clear_contents(&mut self) -> impl Future<Output = Result<(), Self::ContentsStoreError>>;

    // Messages

    /// Clear all stored messages.
    fn clear_messages(&mut self) -> impl Future<Output = Result<(), Self::ContentsStoreError>>;

    /// Clear the messages in a thread.
    fn clear_thread(
        &mut self,
        thread: &Thread,
    ) -> impl Future<Output = Result<(), Self::ContentsStoreError>>;

    /// Save a message in a [Thread] identified by a timestamp.
    fn save_message(
        &self,
        thread: &Thread,
        message: Content,
    ) -> impl Future<Output = Result<(), Self::ContentsStoreError>>;

    /// Delete a single message, identified by its received timestamp from a thread.
    /// Useful when you want to delete a message locally only.
    fn delete_message(
        &mut self,
        thread: &Thread,
        timestamp: u64,
    ) -> impl Future<Output = Result<bool, Self::ContentsStoreError>>;

    /// Retrieve a message from a [Thread] by its timestamp.
    fn message(
        &self,
        thread: &Thread,
        timestamp: u64,
    ) -> impl Future<Output = Result<Option<Content>, Self::ContentsStoreError>>;

    /// Retrieve all messages from a [Thread] within a range in time
    fn messages(
        &self,
        thread: &Thread,
        range: impl RangeBounds<u64>,
    ) -> impl Future<Output = Result<Self::MessagesIter, Self::ContentsStoreError>>;

    /// Get the expire timer from a [Thread], which corresponds to either [Contact::expire_timer]
    /// or [Group::disappearing_messages_timer].
    fn expire_timer(
        &self,
        thread: &Thread,
    ) -> impl Future<Output = Result<Option<(u32, u32)>, Self::ContentsStoreError>> {
        async move {
            match thread {
                Thread::Contact(uuid) => Ok(self
                    .contact_by_id(uuid)
                    .await?
                    .map(|c| (c.expire_timer, c.expire_timer_version))),
                Thread::Group(key) => Ok(self
                    .group(*key)
                    .await?
                    .and_then(|g| g.disappearing_messages_timer)
                    // TODO: most likely we can have versions here
                    .map(|t| (t.duration, 1))), // Groups do not have expire_timer_version
            }
        }
    }

    /// Update the expire timer from a [Thread], which corresponds to either [Contact::expire_timer]
    /// or [Group::disappearing_messages_timer].
    fn update_expire_timer(
        &mut self,
        thread: &Thread,
        timer: u32,
        version: u32,
    ) -> impl Future<Output = Result<(), Self::ContentsStoreError>> {
        async move {
            trace!(%thread, timer, version, "updating expire timer");
            match thread {
                Thread::Contact(uuid) => {
                    let contact = self.contact_by_id(uuid).await?;
                    if let Some(mut contact) = contact {
                        let current_version = contact.expire_timer_version;
                        if version <= current_version {
                            return Ok(());
                        }
                        contact.expire_timer_version = version;
                        contact.expire_timer = timer;
                        self.save_contact(&contact).await?;
                    }
                    Ok(())
                }
                Thread::Group(key) => {
                    let group = self.group(*key).await?;
                    if let Some(mut g) = group {
                        g.disappearing_messages_timer = Some(Timer { duration: timer });
                        self.save_group(*key, g).await?;
                    }
                    Ok(())
                }
            }
        }
    }

    // Contacts

    /// Clear all saved synchronized contact data
    fn clear_contacts(&mut self) -> impl Future<Output = Result<(), Self::ContentsStoreError>>;

    /// Save a contact
    fn save_contact(
        &mut self,
        contacts: &Contact,
    ) -> impl Future<Output = Result<(), Self::ContentsStoreError>> + Send;

    /// Get an iterator on all stored (synchronized) contacts
    fn contacts(
        &self,
    ) -> impl Future<Output = Result<Self::ContactsIter, Self::ContentsStoreError>>;

    /// Get contact data for a single user by its [Uuid].
    fn contact_by_id(
        &self,
        id: &Uuid,
    ) -> impl Future<Output = Result<Option<Contact>, Self::ContentsStoreError>> + Send;

    /// Delete all cached group data
    fn clear_groups(&mut self) -> impl Future<Output = Result<(), Self::ContentsStoreError>>;

    /// Save a group in the cache
    fn save_group(
        &self,
        master_key: GroupMasterKeyBytes,
        group: impl Into<Group>,
    ) -> impl Future<Output = Result<(), Self::ContentsStoreError>>;

    /// Get an iterator on all cached groups
    fn groups(&self) -> impl Future<Output = Result<Self::GroupsIter, Self::ContentsStoreError>>;

    /// Retrieve a single unencrypted group indexed by its `[GroupMasterKeyBytes]`
    fn group(
        &self,
        master_key: GroupMasterKeyBytes,
    ) -> impl Future<Output = Result<Option<Group>, Self::ContentsStoreError>>;

    /// Save a group avatar in the cache
    fn save_group_avatar(
        &self,
        master_key: GroupMasterKeyBytes,
        avatar: &AvatarBytes,
    ) -> impl Future<Output = Result<(), Self::ContentsStoreError>>;

    /// Retrieve a group avatar from the cache.
    fn group_avatar(
        &self,
        master_key: GroupMasterKeyBytes,
    ) -> impl Future<Output = Result<Option<AvatarBytes>, Self::ContentsStoreError>>;

    // Profiles

    /// Insert or update the profile key of a contact
    fn upsert_profile_key(
        &mut self,
        uuid: &Uuid,
        key: ProfileKey,
    ) -> impl Future<Output = Result<bool, Self::ContentsStoreError>> + Send;

    /// Get the profile key for a contact
    fn profile_key(
        &self,
        service_id: &ServiceId,
    ) -> impl Future<Output = Result<Option<ProfileKey>, Self::ContentsStoreError>> + Send;

    /// Save a profile by [Uuid] and [ProfileKey].
    fn save_profile(
        &mut self,
        uuid: Uuid,
        key: ProfileKey,
        profile: Profile,
    ) -> impl Future<Output = Result<(), Self::ContentsStoreError>>;

    /// Retrieve a profile by [Uuid] and [ProfileKey].
    fn profile(
        &self,
        uuid: Uuid,
        key: ProfileKey,
    ) -> impl Future<Output = Result<Option<Profile>, Self::ContentsStoreError>>;

    /// Save a profile avatar by [Uuid] and [ProfileKey].
    fn save_profile_avatar(
        &mut self,
        uuid: Uuid,
        key: ProfileKey,
        profile: &AvatarBytes,
    ) -> impl Future<Output = Result<(), Self::ContentsStoreError>>;

    /// Retrieve a profile avatar by [Uuid] and [ProfileKey].
    fn profile_avatar(
        &self,
        uuid: Uuid,
        key: ProfileKey,
    ) -> impl Future<Output = Result<Option<AvatarBytes>, Self::ContentsStoreError>>;

    // Stickers

    /// Add a sticker pack
    fn add_sticker_pack(
        &mut self,
        pack: &StickerPack,
    ) -> impl Future<Output = Result<(), Self::ContentsStoreError>> + Send;

    /// Gets a cached sticker pack
    fn sticker_pack(
        &self,
        id: &[u8],
    ) -> impl Future<Output = Result<Option<StickerPack>, Self::ContentsStoreError>>;

    /// Removes a sticker pack
    fn remove_sticker_pack(
        &mut self,
        id: &[u8],
    ) -> impl Future<Output = Result<bool, Self::ContentsStoreError>>;

    /// Get an iterator on all installed stickerpacks
    fn sticker_packs(
        &self,
    ) -> impl Future<Output = Result<Self::StickerPacksIter, Self::ContentsStoreError>>;
}

/// The manager store trait combining all other stores into a single one
pub trait Store:
    StateStore<StateStoreError = Self::Error>
    + ContentsStore<ContentsStoreError = Self::Error>
    + Send
    + Sync
    + Clone
    + 'static
{
    type Error: StoreError;
    type AciStore: ProtocolStore
        + PreKeysStore
        + SenderKeyStore
        + SessionStoreExt
        + Send
        + Sync
        + Clone;
    type PniStore: ProtocolStore
        + PreKeysStore
        + SenderKeyStore
        + SessionStoreExt
        + Send
        + Sync
        + Clone;

    /// Clear the entire store
    ///
    /// This can be useful when resetting an existing client.
    fn clear(
        &mut self,
    ) -> impl Future<Output = Result<(), <Self as StateStore>::StateStoreError>> + Send;

    fn aci_protocol_store(&self) -> Self::AciStore;

    fn pni_protocol_store(&self) -> Self::PniStore;
}

/// A thread specifies where a message was sent, either to or from a contact or in a group.
#[derive(Debug, Hash, Eq, PartialEq, Clone, Deserialize, Serialize)]
pub enum Thread {
    /// The message was sent inside a contact-chat.
    /// TODO: make this correctly either ACI or PNI (store the ServiceId)
    Contact(Uuid),
    // Cannot use GroupMasterKey as unable to extract the bytes.
    /// The message was sent inside a groups-chat with the [`GroupMasterKeyBytes`] (specified as bytes).
    Group(GroupMasterKeyBytes),
}

impl fmt::Display for Thread {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Thread::Contact(uuid) => write!(f, "Thread(contact={uuid})"),
            Thread::Group(master_key_bytes) => {
                write!(f, "Thread(group={:x?})", &master_key_bytes[..4])
            }
        }
    }
}

impl TryFrom<&Content> for Thread {
    type Error = UuidError;

    fn try_from(content: &Content) -> Result<Self, Self::Error> {
        match &content.body {
            // [1-1] Message sent by us with another device
            ContentBody::SynchronizeMessage(SyncMessage {
                sent:
                    Some(Sent {
                        destination_service_id: Some(uuid),
                        ..
                    }),
                ..
            }) => Ok(Self::Contact(Uuid::parse_str(uuid)?)),
            // [Group] message from somebody else
            ContentBody::DataMessage(DataMessage {
                group_v2:
                    Some(GroupContextV2 {
                        master_key: Some(key),
                        ..
                    }),
                ..
            })
            // [Group] message sent by us with another device
            | ContentBody::SynchronizeMessage(SyncMessage {
                sent:
                    Some(Sent {
                        message:
                            Some(DataMessage {
                                group_v2:
                                    Some(GroupContextV2 {
                                        master_key: Some(key),
                                        ..
                                    }),
                                ..
                            }),
                        ..
                    }),
                ..
            })
            // [Group] message edit sent by us with another device
            | ContentBody::SynchronizeMessage(SyncMessage {
                sent:
                    Some(Sent {
                        edit_message:
                            Some(EditMessage {
                                data_message:
                                    Some(DataMessage {
                                        group_v2:
                                            Some(GroupContextV2 {
                                                master_key: Some(key),
                                                ..
                                            }),
                                        ..
                                    }),
                                ..
                            }),
                        ..
                    }),
                ..
            })
            // [Group] Message edit sent by somebody else
            | ContentBody::EditMessage(EditMessage {
                data_message:
                    Some(DataMessage {
                        group_v2:
                            Some(GroupContextV2 {
                                master_key: Some(key),
                                ..
                            }),
                        ..
                    }),
                ..
            }) => Ok(Self::Group(
                key.clone()
                    .try_into()
                    .expect("Group master key to have 32 bytes"),
            )),
            // [1-1] Any other message directly to us
            _ => Ok(Thread::Contact(content.metadata.sender.raw_uuid())),
        }
    }
}

/// Extension trait of [`Content`]
pub trait ContentExt {
    fn timestamp(&self) -> u64;
}

impl ContentExt for Content {
    /// The original timestamp of the message.
    fn timestamp(&self) -> u64 {
        match self.body {
            ContentBody::SynchronizeMessage(SyncMessage {
                sent:
                    Some(sync_message::Sent {
                        timestamp: Some(ts),
                        ..
                    }),
                ..
            }) => ts,
            ContentBody::SynchronizeMessage(SyncMessage {
                sent:
                    Some(sync_message::Sent {
                        edit_message:
                            Some(EditMessage {
                                target_sent_timestamp: Some(ts),
                                ..
                            }),
                        ..
                    }),
                ..
            }) => ts,
            ContentBody::EditMessage(EditMessage {
                target_sent_timestamp: Some(ts),
                ..
            }) => ts,
            _ => self.metadata.timestamp,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StickerPack {
    pub id: Vec<u8>,
    pub key: Vec<u8>,
    pub manifest: StickerPackManifest,
}

/// equivalent to [Pack](crate::proto::Pack)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StickerPackManifest {
    pub title: String,
    pub author: String,
    pub cover: Option<Sticker>,
    pub stickers: Vec<Sticker>,
}

impl From<libsignal_service::proto::Pack> for StickerPackManifest {
    fn from(value: libsignal_service::proto::Pack) -> Self {
        Self {
            title: value.title().to_owned(),
            author: value.author().to_owned(),
            cover: value.cover.map(Into::into),
            stickers: value.stickers.into_iter().map(|s| s.into()).collect(),
        }
    }
}

/// equivalent to [Sticker](crate::proto::pack::Sticker)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sticker {
    pub id: u32,
    pub emoji: Option<String>,
    pub content_type: Option<String>,
    pub bytes: Option<Vec<u8>>,
}

impl From<libsignal_service::proto::pack::Sticker> for Sticker {
    fn from(value: libsignal_service::proto::pack::Sticker) -> Self {
        Self {
            id: value.id(),
            emoji: value.emoji,
            content_type: value.content_type,
            bytes: None,
        }
    }
}

/// Saves a message that can show users when the identity of a contact has changed
/// On Signal Android, this is usually displayed as: "Your safety number with XYZ has changed."
pub async fn save_trusted_identity_message<S: Store>(
    store: &S,
    protocol_address: &ProtocolAddress,
    right_identity_key: IdentityKey,
    verified_state: verified::State,
) -> Result<(), S::Error> {
    let Some(sender) = ServiceId::parse_from_service_id_string(protocol_address.name()) else {
        return Ok(());
    };

    // TODO: this is a hack to save a message showing that the verification status changed
    // It is possibly ok to do it like this, but rebuidling the metadata and content body feels dirty
    let thread = Thread::Contact(sender.raw_uuid());
    let verified_sync_message = Content {
        metadata: Metadata {
            sender,
            destination: sender,
            sender_device: *DEFAULT_DEVICE_ID,
            server_guid: None,
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            needs_receipt: false,
            unidentified_sender: false,
            was_plaintext: false,
        },
        body: SyncMessage {
            verified: Some(Verified {
                destination_aci: None,
                destination_aci_binary: None,
                identity_key: Some(right_identity_key.public_key().serialize().to_vec()),
                state: Some(verified_state.into()),
                null_message: None,
            }),
            ..Default::default()
        }
        .into(),
    };

    store.save_message(&thread, verified_sync_message).await
}
