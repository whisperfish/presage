//! How current this device's copy of something the server has is.

use std::time::Duration;

use libsignal_service::prelude::Uuid;

/// Something the server has and the store keeps a copy of. The store notes each copy's
/// [`Freshness`] ([`ContentsStore::set_replica`]), and one rule decides when to fetch again:
/// the server's version moved on, or the copy is older than its kind is trusted for.
///
/// [`ContentsStore::set_replica`]: crate::store::ContentsStore::set_replica
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Replica {
    /// A profile, which changes without notice: a new name or picture keeps the profile key.
    Profile(Uuid),
    /// The storage service's manifest, which has a version.
    StorageManifest,
}

impl Replica {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Profile(_) => "profile",
            Self::StorageManifest => "storage-manifest",
        }
    }

    pub fn id(&self) -> Vec<u8> {
        match self {
            Self::Profile(uuid) => uuid.as_bytes().to_vec(),
            Self::StorageManifest => Vec::new(),
        }
    }

    /// How long a copy without a version is taken as current.
    pub fn max_age(&self) -> Option<Duration> {
        match self {
            Self::Profile(_) => Some(Duration::from_secs(24 * 60 * 60)),
            Self::StorageManifest => None,
        }
    }
}

/// When a [`Replica`] was last fetched, and at which version if it has one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Freshness {
    pub version: Option<u64>,
    /// In milliseconds since the epoch.
    pub fetched_at: u64,
}

impl Freshness {
    pub fn now(version: Option<u64>) -> Self {
        Self {
            version,
            fetched_at: now(),
        }
    }
}

/// Whether the copy of `replica` last noted as `freshness` should be fetched again by age:
/// never fetched, or fetched longer ago than [`Replica::max_age`].
pub fn stale(replica: &Replica, freshness: Option<Freshness>, now: u64) -> bool {
    match (freshness, replica.max_age()) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(freshness), Some(max_age)) => {
            now.saturating_sub(freshness.fetched_at) > max_age.as_millis() as u64
        }
    }
}

pub(crate) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_millis() as u64)
}

#[cfg(test)]
mod tests {
    use super::{stale, Freshness, Replica};
    use libsignal_service::prelude::Uuid;

    const DAY: u64 = 24 * 60 * 60 * 1000;

    #[test]
    fn a_profile_is_fetched_again_after_a_day() {
        let profile = Replica::Profile(Uuid::nil());
        let fetched = |fetched_at| {
            Some(Freshness {
                version: None,
                fetched_at,
            })
        };
        assert!(stale(&profile, None, DAY));
        assert!(!stale(&profile, fetched(1), DAY));
        assert!(stale(&profile, fetched(1), DAY + 2));
    }

    #[test]
    fn a_versioned_copy_does_not_age() {
        let fetched = Some(Freshness {
            version: Some(3),
            fetched_at: 0,
        });
        assert!(!stale(&Replica::StorageManifest, fetched, 365 * DAY));
        assert!(stale(&Replica::StorageManifest, None, 0));
    }
}
