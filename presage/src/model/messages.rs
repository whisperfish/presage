use libsignal_service::{
    prelude::Content,
    proto::DecryptionErrorMessage,
    protocol::{DeviceId, ServiceId, SignalProtocolError},
};

#[derive(Debug)]
pub enum Received {
    /// when the receive loop is empty, happens when opening the websocket for the first time
    /// once you're done synchronizing all pending messages for this registered client.
    QueueEmpty,

    /// Got contacts (only applies if linked to a primary device
    /// Contacts can be later queried in the store.
    Contacts,

    /// Failed to decrypt a message from the specified service ID; `error` says why.
    /// A session reset with the contact may fix this, unless the error is
    /// [`SignalProtocolError::DuplicatedMessage`]: a message delivered again, already handled.
    DecryptionError {
        sender: ServiceId,
        error: SignalProtocolError,
    },

    /// One of the sender's devices failed to decrypt a message of ours: a retry receipt, which
    /// names the message by its timestamp. Signal's clients resend it to that device.
    RetryReceipt {
        sender: ServiceId,
        sender_device: DeviceId,
        message: DecryptionErrorMessage,
    },

    /// Incoming decrypted message with metadata and content
    Content(Box<Content>),
}
