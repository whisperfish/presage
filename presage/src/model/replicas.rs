//! How current this device's copy of something the server has is.

/// Something the server has and the store keeps a copy of. The store notes each copy's
/// [`Freshness`] ([`ContentsStore::set_replica`]): it is fetched again once the server's
/// version moved on.
///
/// [`ContentsStore::set_replica`]: crate::store::ContentsStore::set_replica
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Replica {
    /// The storage service's manifest, which has a version.
    StorageManifest,
}

impl Replica {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::StorageManifest => "storage-manifest",
        }
    }

    pub fn id(&self) -> Vec<u8> {
        match self {
            Self::StorageManifest => Vec::new(),
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

pub(crate) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_millis() as u64)
}
