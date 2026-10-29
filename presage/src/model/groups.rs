use base64::Engine as _;
use libsignal_service::{
    groups_v2::{AccessRequired, GroupChange, GroupChanges, Role},
    prelude::{ProfileKey, Timer, Uuid},
    protocol::{Aci, ServiceId},
    utils::BASE64_RELAXED,
};
use serde::{Deserialize, Serialize};

use super::ServiceIdType;
use libsignal_service::utils::serde_aci;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessControl {
    pub attributes: AccessRequired,
    pub members: AccessRequired,
    pub add_from_invite_link: AccessRequired,
    #[serde(default = "default_access_required")]
    pub member_label: AccessRequired,
}

/// According to https://github.com/signalapp/Signal-Desktop/blob/9c246150585a65b6c3be324e2c214cb4f62c6102/ts/groups.preload.ts#L503.
fn default_access_required() -> AccessRequired {
    AccessRequired::Member
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl Group {
    /// Whether `aci` is a full member (not only invited or requesting to join).
    pub fn is_member(&self, aci: &Aci) -> bool {
        self.members.iter().any(|member| member.aci == *aci)
    }
    /// Applies `changes`, the group's next revision, as the server made it: what Signal's apps
    /// do with the change a message carries, instead of fetching the group again. False, and
    /// the group as it was, if `changes` isn't the next revision or doesn't apply to it
    /// exactly: then only the server's copy says what the group is now.
    pub fn apply(&mut self, changes: &GroupChanges) -> bool {
        if changes.version != self.revision.wrapping_add(1) {
            return false;
        }
        let mut next = self.clone();
        for change in &changes.changes {
            if !next.apply_one(change, changes.version) {
                return false;
            }
        }
        next.revision = changes.version;
        *self = next;
        true
    }

    fn apply_one(&mut self, change: &GroupChange, version: u32) -> bool {
        match change {
            GroupChange::NewMember(member) => {
                self.forget(&ServiceId::from(member.aci));
                self.members.push(member.clone().into());
            }
            GroupChange::DeleteMember(aci) => self.members.retain(|m| m.aci != *aci),
            GroupChange::ModifyMemberRole { aci, role } => match self.member(aci) {
                Some(member) => member.role = *role,
                None => return false,
            },
            GroupChange::ModifyMemberProfileKey { aci, profile_key } => match self.member(aci) {
                Some(member) => member.profile_key = *profile_key,
                None => return false,
            },
            GroupChange::NewPendingMember(pending) => {
                self.pending_members.push(pending.clone().into())
            }
            GroupChange::DeletePendingMember(address) => {
                self.pending_members.retain(|p| !p.is(address))
            }
            GroupChange::PromotePendingMember {
                address,
                profile_key,
            } => {
                let ServiceId::Aci(aci) = address else {
                    return false;
                };
                let Some(role) = self.take_pending(address) else {
                    return false;
                };
                self.join(*aci, role, *profile_key, version);
            }
            GroupChange::PromotePendingPniAciMemberProfileKey(promoted) => {
                let Some(role) = self.take_pending(&ServiceId::from(promoted.pni)) else {
                    return false;
                };
                self.join(promoted.aci, role, promoted.profile_key, version);
            }
            GroupChange::NewRequestingMember(requesting) => {
                self.requesting_members.retain(|r| r.aci != requesting.aci);
                self.requesting_members.push(requesting.clone().into());
            }
            GroupChange::DeleteRequestingMember(aci) => {
                self.requesting_members.retain(|r| r.aci != *aci)
            }
            GroupChange::PromoteRequestingMember { aci, role } => {
                let Some(index) = self.requesting_members.iter().position(|r| r.aci == *aci) else {
                    return false;
                };
                let requesting = self.requesting_members.remove(index);
                self.join(*aci, *role, requesting.profile_key, version);
            }
            GroupChange::Title(title) => self.title = title.clone(),
            GroupChange::Avatar(path) => self.avatar = path.clone(),
            GroupChange::Timer(timer) => self.disappearing_messages_timer = timer.clone(),
            GroupChange::Description(description) => self.description = description.clone(),
            GroupChange::InviteLinkPassword(password) => match BASE64_RELAXED.decode(password) {
                Ok(password) => self.invite_link_password = password,
                Err(_) => return false,
            },
            GroupChange::AttributeAccess(access) => match &mut self.access_control {
                Some(control) => control.attributes = *access,
                None => return false,
            },
            GroupChange::MemberAccess(access) => match &mut self.access_control {
                Some(control) => control.members = *access,
                None => return false,
            },
            GroupChange::InviteLinkAccess(access) => match &mut self.access_control {
                Some(control) => control.add_from_invite_link = *access,
                None => return false,
            },
            GroupChange::MemberLabelAccess(access) => match &mut self.access_control {
                Some(control) => control.member_label = *access,
                None => return false,
            },
            GroupChange::MemberLabel {
                user_id,
                label_emoji,
                label_string,
            } => {
                let ServiceId::Aci(aci) = user_id else {
                    return false;
                };
                match self.member(aci) {
                    Some(member) => {
                        member.label = label_string.clone();
                        member.label_emoji = label_emoji.clone();
                    }
                    None => return false,
                }
            }
            // Not kept here.
            GroupChange::AnnouncementOnly(_)
            | GroupChange::AddBannedMember(_)
            | GroupChange::DeleteBannedMember(_)
            | GroupChange::TerminateGroup => {}
        }
        true
    }

    fn member(&mut self, aci: &Aci) -> Option<&mut Member> {
        self.members.iter_mut().find(|member| member.aci == *aci)
    }

    /// The role `address` was invited with, its invitation gone.
    fn take_pending(&mut self, address: &ServiceId) -> Option<Role> {
        let index = self.pending_members.iter().position(|p| p.is(address))?;
        Some(self.pending_members.remove(index).role)
    }

    /// `aci` a member, no longer invited or asking.
    fn join(&mut self, aci: Aci, role: Role, profile_key: ProfileKey, version: u32) {
        self.forget(&ServiceId::from(aci));
        self.members.push(Member {
            aci,
            role,
            profile_key,
            joined_at_revision: version,
            label: None,
            label_emoji: None,
        });
    }

    /// `address` neither a member, nor invited, nor asking.
    fn forget(&mut self, address: &ServiceId) {
        self.members.retain(|m| ServiceId::from(m.aci) != *address);
        self.pending_members.retain(|p| !p.is(address));
        self.requesting_members
            .retain(|r| ServiceId::from(r.aci) != *address);
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Member {
    #[serde(alias = "uuid", with = "serde_aci")]
    pub aci: Aci,
    pub role: Role,
    pub profile_key: ProfileKey,
    pub joined_at_revision: u32,
    pub label: Option<String>,
    pub label_emoji: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
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

impl PendingMember {
    /// Whether `address` is the one invited.
    fn is(&self, address: &ServiceId) -> bool {
        self.uuid == address.raw_uuid()
            && self.service_id_type == ServiceIdType::from(address.kind())
    }
}

impl From<libsignal_service::groups_v2::Group> for Group {
    fn from(val: libsignal_service::groups_v2::Group) -> Self {
        Group {
            title: val.title,
            avatar: val.avatar,
            disappearing_messages_timer: val.disappearing_messages_timer,
            access_control: val.access_control.map(Into::into),
            revision: val.version,
            members: val.members.into_iter().map(Into::into).collect(),
            pending_members: val
                .members_pending_profile_key
                .into_iter()
                .map(Into::into)
                .collect(),
            requesting_members: val
                .members_pending_admin_approval
                .into_iter()
                .map(Into::into)
                .collect(),
            invite_link_password: val.invite_link_password,
            description: val.description_text,
        }
    }
}

impl From<libsignal_service::groups_v2::Member> for Member {
    fn from(val: libsignal_service::groups_v2::Member) -> Self {
        Member {
            aci: val.aci,
            role: val.role,
            profile_key: val.profile_key,
            joined_at_revision: val.joined_at_version,
            label: val.label,
            label_emoji: val.label_emoji,
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

impl From<libsignal_service::groups_v2::AccessControl> for AccessControl {
    fn from(val: libsignal_service::groups_v2::AccessControl) -> Self {
        Self {
            attributes: val.attributes,
            members: val.members,
            add_from_invite_link: val.add_from_invite_link,
            member_label: val.member_label,
        }
    }
}

#[cfg(test)]
mod tests {
    use libsignal_service::groups_v2::{self, AccessRequired, GroupChange, GroupChanges, Role};
    use libsignal_service::prelude::ProfileKey;
    use libsignal_service::protocol::Aci;

    use super::{AccessControl, Group, Member, RequestingMember};

    fn aci(n: u8) -> Aci {
        Aci::from_uuid_bytes([n; 16])
    }

    fn key(n: u8) -> ProfileKey {
        ProfileKey::create([n; 32])
    }

    fn group() -> Group {
        Group {
            title: "before".to_owned(),
            avatar: String::new(),
            disappearing_messages_timer: None,
            access_control: Some(AccessControl {
                attributes: AccessRequired::Member,
                members: AccessRequired::Member,
                add_from_invite_link: AccessRequired::Unsatisfiable,
                member_label: AccessRequired::Member,
            }),
            revision: 4,
            members: vec![Member {
                aci: aci(1),
                role: Role::Administrator,
                profile_key: key(1),
                joined_at_revision: 0,
                label: None,
                label_emoji: None,
            }],
            pending_members: Vec::new(),
            requesting_members: vec![RequestingMember {
                aci: aci(3),
                profile_key: key(3),
                timestamp: 1,
            }],
            invite_link_password: Vec::new(),
            description: None,
        }
    }

    fn changes(version: u32, changes: Vec<GroupChange>) -> GroupChanges {
        GroupChanges {
            group_id: [0; 32],
            editor: aci(1),
            version,
            changes,
            change_epoch: 0,
        }
    }

    #[test]
    fn the_next_revision_applies() {
        let mut group = group();
        let applied = group.apply(&changes(
            5,
            vec![
                GroupChange::Title("after".to_owned()),
                GroupChange::NewMember(groups_v2::Member {
                    aci: aci(2),
                    role: Role::Default,
                    profile_key: key(2),
                    joined_at_version: 5,
                    label: None,
                    label_emoji: None,
                }),
                GroupChange::PromoteRequestingMember {
                    aci: aci(3),
                    role: Role::Default,
                },
                GroupChange::ModifyMemberRole {
                    aci: aci(2),
                    role: Role::Administrator,
                },
                GroupChange::InviteLinkAccess(AccessRequired::Administrator),
                GroupChange::InviteLinkPassword("AQID".to_owned()),
                GroupChange::DeleteMember(aci(1)),
            ],
        ));
        assert!(applied);
        assert_eq!(group.revision, 5);
        assert_eq!(group.title, "after");
        let members: Vec<_> = group.members.iter().map(|m| (m.aci, m.role)).collect();
        assert_eq!(
            members,
            [(aci(2), Role::Administrator), (aci(3), Role::Default)]
        );
        assert_eq!(group.members[1].profile_key.bytes, key(3).bytes);
        assert_eq!(group.members[1].joined_at_revision, 5);
        assert!(group.requesting_members.is_empty());
        assert_eq!(group.invite_link_password, [1, 2, 3]);
    }

    #[test]
    fn a_change_that_does_not_fit_leaves_the_group_as_it_was() {
        let mut group = group();
        // Not the next revision.
        assert!(!group.apply(&changes(6, vec![GroupChange::Title("after".to_owned())])));
        // About someone who isn't a member: the copy here is off.
        assert!(!group.apply(&changes(
            5,
            vec![
                GroupChange::Title("after".to_owned()),
                GroupChange::ModifyMemberRole {
                    aci: aci(9),
                    role: Role::Administrator,
                },
            ],
        )));
        assert_eq!(group.revision, 4);
        assert_eq!(group.title, "before");
    }
}
