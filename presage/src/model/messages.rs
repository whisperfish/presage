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

    /// A sticker pack installed on another device (announced in a sync message, which comes as
    /// [`Received::Content`] first) has been downloaded and stored: it can be listed now.
    StickerPackInstalled {
        pack_id: Vec<u8>,
    },
}
