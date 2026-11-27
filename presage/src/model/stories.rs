use libsignal_service::{proto::StoryMessage, protocol::Aci, zkgroup::GroupMasterKeyBytes};

/// A story, identified by its sender and sent timestamp.
#[derive(Debug, Clone, PartialEq)]
pub struct Story {
    pub sender: Aci,
    pub timestamp: u64,
    pub message: StoryMessage,
    pub viewed: bool,
}

impl Story {
    pub fn group_master_key(&self) -> Option<GroupMasterKeyBytes> {
        group_master_key(&self.message)
    }
}

/// The master key of the group a story was posted to.
pub fn group_master_key(message: &StoryMessage) -> Option<GroupMasterKeyBytes> {
    message
        .group
        .as_ref()?
        .master_key
        .as_deref()?
        .try_into()
        .ok()
}
