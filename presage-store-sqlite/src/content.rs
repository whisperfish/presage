use std::marker::PhantomData;

use bytes::Bytes;
use presage::{
    libsignal_service::{
        models::Attachment,
        prelude::{
            phonenumber::{self, PhoneNumber},
            Content, ProfileKey,
        },
        profile_name::ProfileName,
        zkgroup::{self, GroupMasterKeyBytes},
        Profile,
    },
    model::{contacts::Contact, groups::Group},
    proto::{verified, Verified},
    store::{ContentsStore, StickerPack, Thread},
};
use sqlx::{query, query_as, query_scalar, types::Uuid};

use crate::{SqliteStore, SqliteStoreError};

impl ContentsStore for SqliteStore {
    type ContentsStoreError = SqliteStoreError;

    type ContactsIter = Box<dyn Iterator<Item = Result<Contact, Self::ContentsStoreError>>>;

    type GroupsIter =
        Box<dyn Iterator<Item = Result<(GroupMasterKeyBytes, Group), Self::ContentsStoreError>>>;

    type MessagesIter = Box<dyn Iterator<Item = Result<Content, Self::ContentsStoreError>>>;

    type StickerPacksIter = Box<dyn Iterator<Item = Result<StickerPack, Self::ContentsStoreError>>>;

    async fn clear_profiles(&mut self) -> Result<(), Self::ContentsStoreError> {
        query!("DELETE FROM profiles").execute(&self.db).await?;
        Ok(())
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
            "INSERT INTO contacts
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
        )
        .execute(&mut *tx)
        .await?;

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
        let contacts = query_as!(
            SqlContact,
            "SELECT *
                FROM contacts c
                LEFT JOIN contacts_verification_state cv ON c.uuid = cv.destination_aci 
                ORDER BY inbox_position
            "
        )
        .fetch_all(&self.db)
        .await?
        .into_iter()
        .map(TryInto::try_into);

        Ok(Box::new(contacts))
    }

    async fn contact_by_id(
        &self,
        uuid: &Uuid,
    ) -> Result<Option<presage::model::contacts::Contact>, Self::ContentsStoreError> {
        query_as!(
            SqlContact,
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
        .map(TryInto::try_into)
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
        let profile_key_bytes = key.get_bytes();
        let profile_key_slice = profile_key_bytes.as_slice();
        let rows_upserted = query!(
            "INSERT INTO profile_keys VALUES($1, $2)",
            uuid,
            profile_key_slice
        )
        .execute(&self.db)
        .await?
        .rows_affected();
        Ok(rows_upserted == 1)
    }

    async fn profile_key(
        &self,
        uuid: &Uuid,
    ) -> Result<Option<ProfileKey>, Self::ContentsStoreError> {
        let profile_key =
            query_scalar!("SELECT key FROM profile_keys WHERE uuid = $1 LIMIT 1", uuid)
                .fetch_optional(&self.db)
                .await?
                .and_then(|key_bytes| key_bytes.try_into().ok().map(ProfileKey::create));
        Ok(profile_key)
    }

    async fn save_profile(
        &mut self,
        uuid: Uuid,
        _key: ProfileKey,
        profile: Profile,
    ) -> Result<(), Self::ContentsStoreError> {
        let given_name = profile.name.clone().map(|n| n.given_name);
        let family_name = profile.name.map(|n| n.family_name).flatten();
        query!(
            "INSERT INTO profiles VALUES($1, $2, $3, $4, $5, $6)",
            uuid,
            given_name,
            family_name,
            profile.about,
            profile.about_emoji,
            profile.avatar
        )
        .execute(&self.db)
        .await?;
        todo!()
    }

    async fn profile(
        &self,
        uuid: Uuid,
        key: ProfileKey,
    ) -> Result<Option<Profile>, Self::ContentsStoreError> {
        let key_bytes = key.get_bytes();
        let key_slice = key_bytes.as_slice();
        query_as!(
            SqlProfile,
            "SELECT pk.key, p.* FROM profile_keys pk
             LEFT JOIN profiles p ON pk.uuid = p.uuid
             WHERE pk.uuid = $1
             LIMIT 1",
            uuid
        )
        .fetch_optional(&self.db)
        .await?
        .map(TryInto::try_into)
        .transpose()
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

struct SqlContact {
    uuid: String,
    phone_number: Option<String>,
    name: String,
    color: Option<String>,
    profile_key: Vec<u8>,
    expire_timer: i64,
    expire_timer_version: i64,
    inbox_position: i64,
    archived: bool,
    avatar: Option<Vec<u8>>,

    destination_aci: Option<String>,
    identity_key: Option<Vec<u8>>,
    is_verified: Option<bool>,
}

impl TryInto<Contact> for SqlContact {
    type Error = SqliteStoreError;

    fn try_into(self) -> Result<Contact, Self::Error> {
        Ok(Contact {
            uuid: self.uuid.parse()?,
            phone_number: self
                .phone_number
                .map(|p| phonenumber::parse(None, &p))
                .transpose()?,
            name: self.name,
            color: self.color,
            verified: Verified {
                destination_aci: self.destination_aci,
                identity_key: self.identity_key,
                state: self.is_verified.map(|v| {
                    match v {
                        true => verified::State::Verified,
                        false => verified::State::Unverified,
                    }
                    .into()
                }),
                null_message: None,
            },
            profile_key: self.profile_key,
            expire_timer: self.expire_timer as u32,
            expire_timer_version: self.expire_timer_version as u32,
            inbox_position: self.inbox_position as u32,
            archived: self.archived,
            avatar: self.avatar.map(|b| Attachment {
                content_type: "application/octet-stream".into(),
                reader: Bytes::from(b),
            }),
        })
    }
}

struct SqlProfile {
    uuid: String,
    key: Vec<u8>,
    given_name: Option<String>,
    family_name: Option<String>,
    about: Option<String>,
    about_emoji: Option<String>,
    avatar: Option<String>,
}

impl TryInto<Profile> for SqlProfile {
    type Error = SqliteStoreError;

    fn try_into(self) -> Result<Profile, Self::Error> {
        Ok(Profile {
            name: self.given_name.map(|gn| ProfileName {
                given_name: gn,
                family_name: self.family_name,
            }),
            about: self.about,
            about_emoji: self.about_emoji,
            avatar: self.avatar,
        })
    }
}
