use libsignal_service::{
    prelude::{Content, Uuid},
    protocol::ServiceId,
};

#[derive(Debug)]
pub enum Received {
    /// when the receive loop is empty, happens when opening the websocket for the first time
    /// once you're done synchronizing all pending messages for this registered client.
    QueueEmpty,

    /// Got contacts (only applies if linked to a primary device
    /// Contacts can be later queried in the store.
    Contacts {
        /// Whether the primary device sent all its contacts.
        complete: bool,
        /// The contacts saved, or `None` if the list couldn't be read, parsed or saved in full.
        /// Entries without an ACI are skipped.
        saved: Option<Vec<Uuid>>,
    },

    // Failed to receive a message from the specified service ID.
    // A session reset with the contact may fix this.
    DecryptionError(ServiceId),

    /// Incoming decrypted message with metadata and content
    Content(Box<Content>),
}
