use presage::{
    libsignal_service::{prelude::Uuid, protocol::Aci},
    model::stories::Story,
    store::{StoriesStore, Thread},
};
use sqlx::{query, query_as, query_scalar};

use crate::{SqliteStore, SqliteStoreError, data::SqlStory};

impl StoriesStore for SqliteStore {
    async fn save_story(&mut self, story: &Story) -> Result<(), Self::ContentsStoreError> {
        let sender_uuid = Uuid::from(story.sender);
        let ts = sql_timestamp(story.timestamp)?;
        let story_message = prost::Message::encode_to_vec(&story.message);
        query!(
            "INSERT INTO stories (sender_uuid, ts, story_message, viewed) VALUES (?, ?, ?, ?)
            ON CONFLICT DO UPDATE SET story_message = excluded.story_message",
            sender_uuid,
            ts,
            story_message,
            story.viewed,
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn story(
        &self,
        sender: &Aci,
        timestamp: u64,
    ) -> Result<Option<Story>, Self::ContentsStoreError> {
        let sender_uuid = Uuid::from(*sender);
        let ts = sql_timestamp(timestamp)?;
        query_as!(
            SqlStory,
            r#"SELECT sender_uuid AS "sender_uuid: _", ts, story_message, viewed
            FROM stories WHERE sender_uuid = ? AND ts = ?"#,
            sender_uuid,
            ts,
        )
        .fetch_optional(&self.db)
        .await?
        .map(Story::try_from)
        .transpose()
    }

    async fn stories(&self) -> Result<Vec<Story>, Self::ContentsStoreError> {
        query_as!(
            SqlStory,
            r#"SELECT sender_uuid AS "sender_uuid: _", ts, story_message, viewed
            FROM stories ORDER BY ts"#,
        )
        .fetch_all(&self.db)
        .await?
        .into_iter()
        .map(Story::try_from)
        .collect()
    }

    async fn mark_story_viewed(
        &mut self,
        sender: &Aci,
        timestamp: u64,
    ) -> Result<bool, Self::ContentsStoreError> {
        let sender_uuid = Uuid::from(*sender);
        let ts = sql_timestamp(timestamp)?;
        let res = query!(
            "UPDATE stories SET viewed = TRUE WHERE sender_uuid = ? AND ts = ? AND NOT viewed",
            sender_uuid,
            ts,
        )
        .execute(&self.db)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn delete_story(
        &mut self,
        sender: &Aci,
        timestamp: u64,
    ) -> Result<bool, Self::ContentsStoreError> {
        let sender_uuid = Uuid::from(*sender);
        let ts = sql_timestamp(timestamp)?;
        let res = query!(
            "DELETE FROM stories WHERE sender_uuid = ? AND ts = ?",
            sender_uuid,
            ts,
        )
        .execute(&self.db)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn delete_stories_before(
        &mut self,
        timestamp: u64,
    ) -> Result<u64, Self::ContentsStoreError> {
        let ts = sql_timestamp(timestamp)?;
        let res = query!("DELETE FROM stories WHERE ts < ?", ts)
            .execute(&self.db)
            .await?;
        Ok(res.rows_affected())
    }

    async fn clear_stories(&mut self) -> Result<(), Self::ContentsStoreError> {
        query!("DELETE FROM stories").execute(&self.db).await?;
        Ok(())
    }

    async fn set_stories_hidden(
        &mut self,
        thread: &Thread,
        hidden: bool,
    ) -> Result<(), Self::ContentsStoreError> {
        match (thread, hidden) {
            (Thread::Contact(service_id), true) => {
                let uuid = service_id.raw_uuid();
                query!(
                    "INSERT OR IGNORE INTO hidden_story_contacts (uuid) VALUES (?)",
                    uuid
                )
                .execute(&self.db)
                .await?;
            }
            (Thread::Contact(service_id), false) => {
                let uuid = service_id.raw_uuid();
                query!("DELETE FROM hidden_story_contacts WHERE uuid = ?", uuid)
                    .execute(&self.db)
                    .await?;
            }
            (Thread::Group(master_key), true) => {
                let master_key = master_key.as_slice();
                query!(
                    "INSERT OR IGNORE INTO hidden_story_groups (master_key) VALUES (?)",
                    master_key
                )
                .execute(&self.db)
                .await?;
            }
            (Thread::Group(master_key), false) => {
                let master_key = master_key.as_slice();
                query!(
                    "DELETE FROM hidden_story_groups WHERE master_key = ?",
                    master_key
                )
                .execute(&self.db)
                .await?;
            }
        }
        Ok(())
    }

    async fn are_stories_hidden(&self, thread: &Thread) -> Result<bool, Self::ContentsStoreError> {
        let hidden = match thread {
            Thread::Contact(service_id) => {
                let uuid = service_id.raw_uuid();
                query_scalar!(
                    "SELECT EXISTS(SELECT 1 FROM hidden_story_contacts WHERE uuid = ?)",
                    uuid
                )
                .fetch_one(&self.db)
                .await?
            }
            Thread::Group(master_key) => {
                let master_key = master_key.as_slice();
                query_scalar!(
                    "SELECT EXISTS(SELECT 1 FROM hidden_story_groups WHERE master_key = ?)",
                    master_key
                )
                .fetch_one(&self.db)
                .await?
            }
        };
        Ok(hidden != 0)
    }
}

fn sql_timestamp(timestamp: u64) -> Result<i64, SqliteStoreError> {
    timestamp
        .try_into()
        .map_err(|_| SqliteStoreError::InvalidFormat)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::OnNewIdentity;

    #[tokio::test]
    async fn stories_keep_viewed_state_and_expire() -> Result<(), Box<dyn std::error::Error>> {
        let mut store = SqliteStore::open(":memory:", OnNewIdentity::Trust).await?;
        let sender = Aci::from(Uuid::from_u128(1));
        let story = |timestamp| Story {
            sender,
            timestamp,
            message: Default::default(),
            viewed: false,
        };

        store.save_story(&story(10)).await?;
        store.save_story(&story(20)).await?;
        assert!(store.mark_story_viewed(&sender, 10).await?);
        assert!(!store.mark_story_viewed(&sender, 10).await?);
        store.save_story(&story(10)).await?;
        assert!(store.story(&sender, 10).await?.unwrap().viewed);

        assert_eq!(store.delete_stories_before(15).await?, 1);
        assert_eq!(store.stories().await?, vec![story(20)]);
        assert!(store.delete_story(&sender, 20).await?);
        assert!(!store.delete_story(&sender, 20).await?);
        assert!(store.stories().await?.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn hiding_stories_is_per_thread() -> Result<(), Box<dyn std::error::Error>> {
        let mut store = SqliteStore::open(":memory:", OnNewIdentity::Trust).await?;
        let contact = Thread::Contact(Aci::from(Uuid::from_u128(1)).into());
        let group = Thread::Group([1; 32]);

        store.set_stories_hidden(&contact, true).await?;
        store.set_stories_hidden(&contact, true).await?;
        assert!(store.are_stories_hidden(&contact).await?);
        assert!(!store.are_stories_hidden(&group).await?);
        store.set_stories_hidden(&group, true).await?;
        store.set_stories_hidden(&contact, false).await?;
        assert!(!store.are_stories_hidden(&contact).await?);
        assert!(store.are_stories_hidden(&group).await?);

        Ok(())
    }
}
