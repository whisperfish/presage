use derivative::Derivative;
use libsignal_service::{
    groups_v2::Role,
    prelude::{AccessControl, Member, ProfileKey, Timer, Uuid},
};
use serde::{Deserialize, Serialize};

use super::ServiceIdType;

#[derive(Debug, Serialize, Deserialize)]
pub struct Group {
    pub title: String,
    pub avatar: String,
    pub disappearing_messages_timer: Option<Timer>,
    pub access_control: Option<AccessControl>,
    pub revision: u32,
    pub members: Vec<Member>,
    pub pending_members: Vec<PendingMember>,
    pub requesting_members: Vec<RequestingMember>,
    pub invite_link_password: Vec<u8>,
    pub description: Option<String>,
}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct PendingMember {
    // for backwards compatibility
    pub uuid: Uuid,
    #[serde(default)]
    pub service_id_type: ServiceIdType,
    pub role: Role,
    pub added_by_uuid: Uuid,
    pub timestamp: u64,
}

#[derive(Derivative, Clone, Deserialize, Serialize)]
#[derivative(Debug)]
pub struct RequestingMember {
    pub uuid: Uuid,
    pub profile_key: ProfileKey,
    pub timestamp: u64,
}

impl Into<Group> for libsignal_service::groups_v2::Group {
    fn into(self) -> Group {
        Group {
            title: self.title,
            avatar: self.avatar,
            disappearing_messages_timer: self.disappearing_messages_timer,
            access_control: self.access_control,
            revision: self.revision,
            members: self.members,
            pending_members: self.pending_members.into_iter().map(Into::into).collect(),
            requesting_members: self
                .requesting_members
                .into_iter()
                .map(Into::into)
                .collect(),
            invite_link_password: self.invite_link_password,
            description: self.description,
        }
    }
}

impl Into<PendingMember> for libsignal_service::groups_v2::PendingMember {
    fn into(self) -> PendingMember {
        PendingMember {
            uuid: self.address.uuid,
            service_id_type: self.address.identity.into(),
            role: self.role,
            added_by_uuid: self.added_by_uuid,
            timestamp: self.timestamp,
        }
    }
}

impl Into<RequestingMember> for libsignal_service::groups_v2::RequestingMember {
    fn into(self) -> RequestingMember {
        RequestingMember {
            uuid: self.uuid,
            profile_key: self.profile_key,
            timestamp: self.timestamp,
        }
    }
}
