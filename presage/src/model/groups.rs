use libsignal_service::{
    groups_v2::Role,
    prelude::{AccessControl, ProfileKey, Timer, Uuid},
    protocol::Aci,
};
use serde::{Deserialize, Serialize};

use super::ServiceIdType;
use libsignal_service::utils::serde_aci;

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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Member {
    #[serde(alias = "uuid", with = "serde_aci")]
    pub aci: Aci,
    pub role: Role,
    pub profile_key: ProfileKey,
    pub joined_at_revision: u32,
}

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct PendingMember {
    // for backwards compatibility
    pub uuid: Uuid,
    #[serde(default)]
    pub service_id_type: ServiceIdType,
    pub role: Role,
    #[serde(alias = "added_by_uuid", with = "serde_aci")]
    pub added_by_aci: Aci,
    pub timestamp: u64,
}

#[derive(derive_more::Debug, Clone, Deserialize, Serialize)]
pub struct RequestingMember {
    #[serde(alias = "uuid", with = "serde_aci")]
    pub aci: Aci,
    #[debug(ignore)]
    pub profile_key: ProfileKey,
    pub timestamp: u64,
}

impl From<libsignal_service::groups_v2::Group> for Group {
    fn from(val: libsignal_service::groups_v2::Group) -> Self {
        Group {
            title: val.title,
            avatar: val.avatar,
            disappearing_messages_timer: val.disappearing_messages_timer,
            access_control: val.access_control,
            revision: val.revision,
            members: val.members.into_iter().map(Into::into).collect(),
            pending_members: val.pending_members.into_iter().map(Into::into).collect(),
            requesting_members: val.requesting_members.into_iter().map(Into::into).collect(),
            invite_link_password: val.invite_link_password,
            description: val.description,
        }
    }
}

impl From<libsignal_service::groups_v2::Member> for Member {
    fn from(val: libsignal_service::groups_v2::Member) -> Self {
        Member {
            aci: val.aci,
            role: val.role,
            profile_key: val.profile_key,
            joined_at_revision: val.joined_at_revision,
        }
    }
}

impl From<libsignal_service::groups_v2::PendingMember> for PendingMember {
    fn from(val: libsignal_service::groups_v2::PendingMember) -> Self {
        PendingMember {
            uuid: val.address.raw_uuid(),
            service_id_type: val.address.kind().into(),
            role: val.role,
            added_by_aci: val.added_by_aci,
            timestamp: val.timestamp,
        }
    }
}

impl From<libsignal_service::groups_v2::RequestingMember> for RequestingMember {
    fn from(val: libsignal_service::groups_v2::RequestingMember) -> Self {
        RequestingMember {
            aci: val.aci,
            profile_key: val.profile_key,
            timestamp: val.timestamp,
        }
    }
}
