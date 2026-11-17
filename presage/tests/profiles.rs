//! Stored profiles and how current they are, against the SQLite store. A profile that is not
//! current is fetched, which these tests have no connection for.

use presage::libsignal_service::prelude::{ProfileKey, Uuid};
use presage::libsignal_service::Profile;
use presage::model::replicas::{Freshness, Replica};
use presage::store::ContentsStore;

mod common;
use common::{linked, store};

const KEY: ProfileKey = ProfileKey { bytes: [7; 32] };

fn profile(avatar: Option<&str>) -> Profile {
    Profile {
        about: Some("about".into()),
        avatar: avatar.map(Into::into),
        ..Default::default()
    }
}

#[tokio::test]
async fn a_current_profile_is_the_stored_one() {
    let mut store = store().await;
    let mut manager = linked(store.clone()).await;
    let uuid = Uuid::from_u128(3);
    let stored = profile(Some("path"));
    store.save_profile(uuid, KEY, stored).await.unwrap();
    let fetched = Freshness::now(None);
    store
        .set_replica(&Replica::Profile(uuid), fetched)
        .await
        .unwrap();

    let profile = manager.retrieve_profile_by_uuid(uuid, KEY).await.unwrap();
    assert_eq!(profile.about.as_deref(), Some("about"));
    // Not fetched: as current as it was.
    let noted = store.replica(&Replica::Profile(uuid)).await.unwrap();
    assert_eq!(noted, Some(fetched));

    let avatar = vec![1, 2, 3];
    store.save_profile_avatar(uuid, KEY, &avatar).await.unwrap();
    let found = manager.retrieve_profile_avatar_by_uuid(uuid, KEY).await;
    assert_eq!(found.unwrap(), Some(avatar));
}

/// The picture was removed: the one stored before is not the profile's any more.
#[tokio::test]
async fn a_profile_without_a_picture_has_none_whatever_is_stored() {
    let mut store = store().await;
    let mut manager = linked(store.clone()).await;
    let uuid = Uuid::from_u128(3);
    let before = profile(Some("path"));
    store.save_profile(uuid, KEY, before).await.unwrap();
    store
        .save_profile_avatar(uuid, KEY, &vec![1, 2, 3])
        .await
        .unwrap();
    store.save_profile(uuid, KEY, profile(None)).await.unwrap();
    store
        .set_replica(&Replica::Profile(uuid), Freshness::now(None))
        .await
        .unwrap();

    let found = manager.retrieve_profile_avatar_by_uuid(uuid, KEY).await;
    assert_eq!(found.unwrap(), None);
}
