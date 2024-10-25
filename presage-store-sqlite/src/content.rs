use std::marker::PhantomData;

use bytes::Bytes;
use presage::{
    libsignal_service::{
        models::Attachment,
        prelude::{
            phonenumber::{self, PhoneNumber},
            Content, ProfileKey,
        },
        zkgroup::{self, GroupMasterKeyBytes},
        Profile,
    },
    model::{contacts::Contact, groups::Group},
    proto::{verified, Verified},
    store::{ContentsStore, StickerPack, Thread},
};
use sqlx::{query, types::Uuid};

use crate::{SqliteStore, SqliteStoreError};

impl ContentsStore for SqliteStore {
    type ContentsStoreError = SqliteStoreError;

    type ContactsIter = Box<dyn Iterator<Item = Result<Contact, Self::ContentsStoreError>>>;

    type GroupsIter = DummyIter<Result<(GroupMasterKeyBytes, Group), Self::ContentsStoreError>>;

    type MessagesIter = DummyIter<Result<Content, Self::ContentsStoreError>>;

    type StickerPacksIter = DummyIter<Result<StickerPack, Self::ContentsStoreError>>;

    async fn clear_profiles(&mut self) -> Result<(), Self::ContentsStoreError> {
        todo!()
    }

    async fn clear_contents(&mut self) -> Result<(), Self::ContentsStoreError> {
        todo!()
    }

    async fn clear_messages(&mut self) -> Result<(), Self::ContentsStoreError> {
        todo!()
    }

    async fn clear_thread(&mut self, thread: &Thread) -> Result<(), Self::ContentsStoreError> {
        todo!()
    }

    async fn save_message(
        &self,
        thread: &Thread,
        message: Content,
    ) -> Result<(), Self::ContentsStoreError> {
        todo!()
    }

    async fn delete_message(
        &mut self,
        thread: &Thread,
        timestamp: u64,
    ) -> Result<bool, Self::ContentsStoreError> {
        todo!()
    }

    async fn message(
        &self,
        thread: &Thread,
        timestamp: u64,
    ) -> Result<Option<Content>, Self::ContentsStoreError> {
        todo!()
    }

    async fn messages(
        &self,
        thread: &Thread,
        range: impl std::ops::RangeBounds<u64>,
    ) -> Result<Self::MessagesIter, Self::ContentsStoreError> {
        todo!()
    }

    async fn clear_contacts(&mut self) -> Result<(), Self::ContentsStoreError> {
        query!("DELETE FROM contacts").execute(&self.db).await?;
        Ok(())
    }

    async fn save_contact(&mut self, contact: Contact) -> Result<(), Self::ContentsStoreError> {
        let profile_key: &[u8] = contact.profile_key.as_ref();
        let avatar_bytes = contact.avatar.map(|a| a.reader.to_vec());
        let phone_number = contact.phone_number.map(|p| p.to_string());

        let mut tx = self.db.begin().await?;

        query!(
            "INSERT INTO contacts(uuid, phone_number, name, color, profile_key, expire_timer, expire_timer_version, inbox_position, archived, avatar)
            VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
            contact.uuid,
            phone_number,
            contact.name,
            contact.color,
            profile_key,
            contact.expire_timer,
            contact.expire_timer_version,
            contact.inbox_position,
            contact.archived,
            avatar_bytes,
        ).execute(&mut *tx).await?;

        let Verified {
            destination_aci,
            identity_key,
            state,
            ..
        } = contact.verified;
        let verified_state = match verified::State::from_i32(state.unwrap_or_default()) {
            None | Some(verified::State::Default) => None,
            Some(verified::State::Unverified) => Some("unverified"),
            Some(verified::State::Verified) => Some("verified"),
        };

        query!(
            "INSERT INTO contacts_verification_state(destination_aci, identity_key, is_verified)
            VALUES($1, $2, $3)",
            destination_aci,
            identity_key,
            verified_state,
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await;

        Ok(())
    }

    async fn contacts(&self) -> Result<Self::ContactsIter, Self::ContentsStoreError> {
        let contacts = query!(
            "SELECT *
                FROM contacts c
                LEFT JOIN contacts_verification_state cv ON c.uuid = cv.destination_aci 
                ORDER BY inbox_position
            "
        )
        .fetch_all(&self.db)
        .await?
        .into_iter()
        .map(|r| {
            Ok(Contact {
                uuid: r.uuid.parse()?,
                phone_number: r
                    .phone_number
                    .map(|p| phonenumber::parse(None, &p))
                    .transpose()?,
                name: r.name,
                color: r.color,
                verified: Verified {
                    destination_aci: r.destination_aci,
                    identity_key: r.identity_key,
                    state: r.is_verified.map(|v| {
                        match v {
                            true => verified::State::Verified,
                            false => verified::State::Unverified,
                        }
                        .into()
                    }),
                    null_message: None,
                },
                profile_key: r.profile_key,
                expire_timer: r.expire_timer as u32,
                expire_timer_version: r.expire_timer_version as u32,
                inbox_position: r.inbox_position as u32,
                archived: r.archived,
                avatar: r.avatar.map(|b| Attachment {
                    content_type: "application/octet-stream".into(),
                    reader: Bytes::from(b),
                }),
            })
        });

        Ok(Box::new(contacts))
    }

    async fn contact_by_id(
        &self,
        uuid: &Uuid,
    ) -> Result<Option<presage::model::contacts::Contact>, Self::ContentsStoreError> {
        query!(
            "SELECT *
                FROM contacts c
                LEFT JOIN contacts_verification_state cv ON c.uuid = cv.destination_aci
                WHERE c.uuid = $1
                ORDER BY inbox_position
                LIMIT 1
            ",
            uuid
        )
        .fetch_optional(&self.db)
        .await?
        .map(|r| {
            Ok(Contact {
                uuid: r.uuid.parse()?,
                phone_number: r
                    .phone_number
                    .map(|p| phonenumber::parse(None, &p))
                    .transpose()?,
                name: r.name,
                color: r.color,
                verified: Verified {
                    destination_aci: Some(r.destination_aci),
                    identity_key: Some(r.identity_key),
                    state: r.is_verified.map(|v| {
                        match v {
                            true => verified::State::Verified,
                            false => verified::State::Unverified,
                        }
                        .into()
                    }),
                    null_message: None,
                },
                profile_key: r.profile_key,
                expire_timer: r.expire_timer as u32,
                expire_timer_version: r.expire_timer_version as u32,
                inbox_position: r.inbox_position as u32,
                archived: r.archived,
                avatar: r.avatar.map(|b| Attachment {
                    content_type: "application/octet-stream".into(),
                    reader: Bytes::from(b),
                }),
            })
        })
        .transpose()
    }

    async fn clear_groups(&mut self) -> Result<(), Self::ContentsStoreError> {
        query!("DELETE FROM groups").execute(&self.db).await?;
        Ok(())
    }

    async fn save_group(
        &self,
        master_key: zkgroup::GroupMasterKeyBytes,
        group: impl Into<presage::model::groups::Group>,
    ) -> Result<(), Self::ContentsStoreError> {
        todo!()
    }

    async fn groups(&self) -> Result<Self::GroupsIter, Self::ContentsStoreError> {
        todo!()
    }

    async fn group(
        &self,
        master_key: zkgroup::GroupMasterKeyBytes,
    ) -> Result<Option<presage::model::groups::Group>, Self::ContentsStoreError> {
        todo!()
    }

    async fn save_group_avatar(
        &self,
        master_key: zkgroup::GroupMasterKeyBytes,
        avatar: &presage::AvatarBytes,
    ) -> Result<(), Self::ContentsStoreError> {
        todo!()
    }

    async fn group_avatar(
        &self,
        master_key: zkgroup::GroupMasterKeyBytes,
    ) -> Result<Option<presage::AvatarBytes>, Self::ContentsStoreError> {
        todo!()
    }

    async fn upsert_profile_key(
        &mut self,
        uuid: &Uuid,
        key: ProfileKey,
    ) -> Result<bool, Self::ContentsStoreError> {
        todo!()
    }

    async fn profile_key(
        &self,
        uuid: &Uuid,
    ) -> Result<Option<ProfileKey>, Self::ContentsStoreError> {
        todo!()
    }

    async fn save_profile(
        &mut self,
        uuid: Uuid,
        key: ProfileKey,
        profile: Profile,
    ) -> Result<(), Self::ContentsStoreError> {
        todo!()
    }

    async fn profile(
        &self,
        uuid: Uuid,
        key: ProfileKey,
    ) -> Result<Option<Profile>, Self::ContentsStoreError> {
        todo!()
    }

    async fn save_profile_avatar(
        &mut self,
        uuid: Uuid,
        key: ProfileKey,
        profile: &presage::AvatarBytes,
    ) -> Result<(), Self::ContentsStoreError> {
        todo!()
    }

    async fn profile_avatar(
        &self,
        uuid: Uuid,
        key: ProfileKey,
    ) -> Result<Option<presage::AvatarBytes>, Self::ContentsStoreError> {
        todo!()
    }

    async fn add_sticker_pack(
        &mut self,
        pack: &StickerPack,
    ) -> Result<(), Self::ContentsStoreError> {
        todo!()
    }

    async fn sticker_pack(
        &self,
        id: &[u8],
    ) -> Result<Option<StickerPack>, Self::ContentsStoreError> {
        todo!()
    }

    async fn remove_sticker_pack(&mut self, id: &[u8]) -> Result<bool, Self::ContentsStoreError> {
        todo!()
    }

    async fn sticker_packs(&self) -> Result<Self::StickerPacksIter, Self::ContentsStoreError> {
        todo!()
    }
}

pub struct DummyIter<T> {
    _data: PhantomData<T>,
}

impl<T> Iterator for DummyIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        todo!()
    }
}
