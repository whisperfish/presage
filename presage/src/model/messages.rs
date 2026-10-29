use libsignal_service::{prelude::Content, protocol::ServiceId};

#[derive(Debug)]
pub enum Received {
    /// when the receive loop is empty, happens when opening the websocket for the first time
    /// once you're done synchronizing all pending messages for this registered client.
    QueueEmpty,

    /// Got contacts (only applies if linked to a primary device
    /// Contacts can be later queried in the store.
    Contacts,

    // Failed to receive a message from the specified service ID.
    // A session reset with the contact may fix this.
    DecryptionError(ServiceId),

    /// Incoming decrypted message with metadata and content
    Content(Box<Content>),

    /// Changes to a group that no message told of, oldest first: read from the server's log
    /// when a message showed the group further on than the stored copy, which is up to date
    /// with them now. Comes before that message; the change the message carries, if any, isn't
    /// among them.
    MissedGroupChanges {
        master_key: [u8; 32],
        changes: Vec<MissedGroupChange>,
    },
}

/// A group change no message told of.
#[derive(Debug, Clone)]
pub struct MissedGroupChange {
    pub changes: libsignal_service::groups_v2::GroupChanges,
    /// As the server signed it, encrypted: what a message telling of it would have carried in
    /// its [`GroupContextV2`](libsignal_service::proto::GroupContextV2).
    pub signed: libsignal_service::proto::GroupChange,
}
