use std::future::Future;

use libsignal_service::protocol::Aci;

use crate::model::stories::Story;

use super::{ContentsStore, Thread};

pub trait StoriesStore: ContentsStore {
    /// Save a story, keeping the viewed state if it is already stored.
    fn save_story(
        &mut self,
        story: &Story,
    ) -> impl Future<Output = Result<(), Self::ContentsStoreError>>;

    fn story(
        &self,
        sender: &Aci,
        timestamp: u64,
    ) -> impl Future<Output = Result<Option<Story>, Self::ContentsStoreError>>;

    /// All stored stories, oldest first.
    fn stories(&self) -> impl Future<Output = Result<Vec<Story>, Self::ContentsStoreError>>;

    fn mark_story_viewed(
        &mut self,
        sender: &Aci,
        timestamp: u64,
    ) -> impl Future<Output = Result<bool, Self::ContentsStoreError>>;

    fn delete_story(
        &mut self,
        sender: &Aci,
        timestamp: u64,
    ) -> impl Future<Output = Result<bool, Self::ContentsStoreError>>;

    /// Delete the stories sent before `timestamp`, returning how many were deleted.
    fn delete_stories_before(
        &mut self,
        timestamp: u64,
    ) -> impl Future<Output = Result<u64, Self::ContentsStoreError>>;

    fn clear_stories(&mut self) -> impl Future<Output = Result<(), Self::ContentsStoreError>>;

    fn set_stories_hidden(
        &mut self,
        thread: &Thread,
        hidden: bool,
    ) -> impl Future<Output = Result<(), Self::ContentsStoreError>>;

    fn are_stories_hidden(
        &self,
        thread: &Thread,
    ) -> impl Future<Output = Result<bool, Self::ContentsStoreError>>;
}
