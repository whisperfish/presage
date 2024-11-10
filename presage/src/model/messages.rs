use libsignal_service::prelude::Content;

#[derive(Debug)]
pub enum Received {
    /// when the receive loop is empty, happens when opening the websocket for the first time
    /// once you're done synchronizing all pending messages for this registered client.
    QueueEmpty,

    // got contacts synchronization
    Contacts,

    Content(Content),
}
