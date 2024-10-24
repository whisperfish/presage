use std::marker::PhantomData;

use presage::{
    libsignal_service::{prelude::Content, zkgroup::GroupMasterKeyBytes},
    model::{contacts::Contact, groups::Group},
    store::{ContentsStore, Sticker, StickerPack},
};

use crate::{SqliteStore, SqliteStoreError};

impl ContentsStore for SqliteStore {
    type ContentsStoreError = SqliteStoreError;

    type ContactsIter = DummyIter<Result<Contact, Self::ContentsStoreError>>;

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

    async fn clear_thread(
        &mut self,
        thread: &presage::store::Thread,
    ) -> Result<(), Self::ContentsStoreError> {
        todo!()
    }

    async fn save_message(
        &self,
        thread: &presage::store::Thread,
        message: presage::libsignal_service::prelude::Content,
    ) -> Result<(), Self::ContentsStoreError> {
        todo!()
    }

    async fn delete_message(
        &mut self,
        thread: &presage::store::Thread,
        timestamp: u64,
    ) -> Result<bool, Self::ContentsStoreError> {
        todo!()
    }

    async fn message(
        &self,
        thread: &presage::store::Thread,
        timestamp: u64,
    ) -> Result<Option<presage::libsignal_service::prelude::Content>, Self::ContentsStoreError>
    {
        todo!()
    }

    async fn messages(
        &self,
        thread: &presage::store::Thread,
        range: impl std::ops::RangeBounds<u64>,
    ) -> Result<Self::MessagesIter, Self::ContentsStoreError> {
        todo!()
    }

    async fn clear_contacts(&mut self) -> Result<(), Self::ContentsStoreError> {
        todo!()
    }

    async fn save_contact(
        &mut self,
        contacts: &presage::model::contacts::Contact,
    ) -> Result<(), Self::ContentsStoreError> {
        todo!()
    }

    async fn contacts(&self) -> Result<Self::ContactsIter, Self::ContentsStoreError> {
        todo!()
    }

    async fn contact_by_id(
        &self,
        id: &presage::libsignal_service::prelude::Uuid,
    ) -> Result<Option<presage::model::contacts::Contact>, Self::ContentsStoreError> {
        todo!()
    }

    async fn clear_groups(&mut self) -> Result<(), Self::ContentsStoreError> {
        todo!()
    }

    async fn save_group(
        &self,
        master_key: presage::libsignal_service::zkgroup::GroupMasterKeyBytes,
        group: impl Into<presage::model::groups::Group>,
    ) -> Result<(), Self::ContentsStoreError> {
        todo!()
    }

    async fn groups(&self) -> Result<Self::GroupsIter, Self::ContentsStoreError> {
        todo!()
    }

    async fn group(
        &self,
        master_key: presage::libsignal_service::zkgroup::GroupMasterKeyBytes,
    ) -> Result<Option<presage::model::groups::Group>, Self::ContentsStoreError> {
        todo!()
    }

    async fn save_group_avatar(
        &self,
        master_key: presage::libsignal_service::zkgroup::GroupMasterKeyBytes,
        avatar: &presage::AvatarBytes,
    ) -> Result<(), Self::ContentsStoreError> {
        todo!()
    }

    async fn group_avatar(
        &self,
        master_key: presage::libsignal_service::zkgroup::GroupMasterKeyBytes,
    ) -> Result<Option<presage::AvatarBytes>, Self::ContentsStoreError> {
        todo!()
    }

    async fn upsert_profile_key(
        &mut self,
        uuid: &presage::libsignal_service::prelude::Uuid,
        key: presage::libsignal_service::prelude::ProfileKey,
    ) -> Result<bool, Self::ContentsStoreError> {
        todo!()
    }

    async fn profile_key(
        &self,
        uuid: &presage::libsignal_service::prelude::Uuid,
    ) -> Result<Option<presage::libsignal_service::prelude::ProfileKey>, Self::ContentsStoreError>
    {
        todo!()
    }

    async fn save_profile(
        &mut self,
        uuid: presage::libsignal_service::prelude::Uuid,
        key: presage::libsignal_service::prelude::ProfileKey,
        profile: presage::libsignal_service::Profile,
    ) -> Result<(), Self::ContentsStoreError> {
        todo!()
    }

    async fn profile(
        &self,
        uuid: presage::libsignal_service::prelude::Uuid,
        key: presage::libsignal_service::prelude::ProfileKey,
    ) -> Result<Option<presage::libsignal_service::Profile>, Self::ContentsStoreError> {
        todo!()
    }

    async fn save_profile_avatar(
        &mut self,
        uuid: presage::libsignal_service::prelude::Uuid,
        key: presage::libsignal_service::prelude::ProfileKey,
        profile: &presage::AvatarBytes,
    ) -> Result<(), Self::ContentsStoreError> {
        todo!()
    }

    async fn profile_avatar(
        &self,
        uuid: presage::libsignal_service::prelude::Uuid,
        key: presage::libsignal_service::prelude::ProfileKey,
    ) -> Result<Option<presage::AvatarBytes>, Self::ContentsStoreError> {
        todo!()
    }

    async fn add_sticker_pack(
        &mut self,
        pack: &presage::store::StickerPack,
    ) -> Result<(), Self::ContentsStoreError> {
        todo!()
    }

    async fn sticker_pack(
        &self,
        id: &[u8],
    ) -> Result<Option<presage::store::StickerPack>, Self::ContentsStoreError> {
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
