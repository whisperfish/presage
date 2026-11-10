//! Work presage owes after a message, kept in the store until done.

use std::fmt;
use std::time::Duration;

use libsignal_service::prelude::Uuid;
use serde::{Deserialize, Serialize};

/// What presage still has to do for something it received. The store keeps it
/// ([`ContentsStore::enqueue_job`]) until it is done, so that a failure, or the process
/// ending, puts it off instead of losing it. Run while receiving.
///
/// [`ContentsStore::enqueue_job`]: crate::store::ContentsStore::enqueue_job
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Job {
    /// Fetch the profile of a sender seen first, or with a new profile key, and save them as a
    /// contact.
    FetchProfile {
        aci: [u8; 16],
        profile_key: [u8; 32],
        expire_timer: u32,
        expire_timer_version: u32,
    },
    /// Bring a group up to `revision`, which a message showed when fetching the group failed.
    UpdateGroup { master_key: [u8; 32], revision: u32 },
    /// Download a sticker pack installed on another device.
    InstallStickerPack { pack_id: Vec<u8>, pack_key: Vec<u8> },
    /// Read the groups the storage service lists.
    SyncStorage,
    /// Save the contacts another device sent: `contacts` is its `SyncMessage.Contacts`.
    SaveContacts { contacts: Vec<u8> },
    /// Send our contacts to a device of ours that asked.
    AnswerContacts,
    /// Send the account's keys to a device of ours that asked.
    AnswerKeys,
    /// Send the block list to a device of ours that asked.
    AnswerBlocked,
    /// Ask the primary device for the account's keys.
    RequestKeys,
}

impl Job {
    /// One job waits per key: queued again, it takes the place of the one waiting.
    pub fn key(&self) -> String {
        match self {
            Self::FetchProfile { aci, .. } => format!("profile:{}", hex::encode(aci)),
            Self::UpdateGroup { master_key, .. } => format!("group:{}", hex::encode(master_key)),
            Self::InstallStickerPack { pack_id, .. } => {
                format!("sticker-pack:{}", hex::encode(pack_id))
            }
            Self::SyncStorage => "storage".into(),
            Self::SaveContacts { .. } => "contacts".into(),
            Self::AnswerContacts => "answer:contacts".into(),
            Self::AnswerKeys => "answer:keys".into(),
            Self::AnswerBlocked => "answer:blocked".into(),
            Self::RequestKeys => "request:keys".into(),
        }
    }
}

/// The job for the log, without the keys it carries.
impl fmt::Display for Job {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FetchProfile { aci, .. } => {
                write!(f, "fetch the profile of {}", Uuid::from_bytes(*aci))
            }
            Self::UpdateGroup {
                master_key,
                revision,
            } => write!(
                f,
                "update group {:x?} to revision {revision}",
                &master_key[..4]
            ),
            Self::InstallStickerPack { pack_id, .. } => {
                write!(f, "install sticker pack {}", hex::encode(pack_id))
            }
            Self::SyncStorage => f.write_str("sync storage"),
            Self::SaveContacts { .. } => f.write_str("save contacts"),
            Self::AnswerContacts => f.write_str("answer contacts"),
            Self::AnswerKeys => f.write_str("answer keys"),
            Self::AnswerBlocked => f.write_str("answer blocked"),
            Self::RequestKeys => f.write_str("request keys"),
        }
    }
}

/// As [`fmt::Display`]: a job carries keys.
impl fmt::Debug for Job {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Job({self})")
    }
}

/// A [`Job`] as the store keeps it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueuedJob {
    pub id: u64,
    pub job: Job,
    /// How often another job took this one's place under its key: a run settles only the job
    /// it began with.
    pub generation: u64,
    /// How often it failed.
    pub attempts: u32,
    /// Not before this time, in milliseconds since the epoch.
    pub due_at: u64,
}

const WAITS_SECS: [u64; 6] = [5, 30, 120, 600, 3600, 6 * 3600];

/// How long after failing `attempts` times a job waits, or `None` once it is given up. A
/// failure of the connection says nothing against the job: it waits, the longest wait at most,
/// and isn't given up.
pub fn backoff(attempts: u32, connection_failed: bool) -> Option<Duration> {
    let wait = WAITS_SECS.get(attempts.checked_sub(1)? as usize).copied();
    wait.or(connection_failed.then_some(WAITS_SECS[WAITS_SECS.len() - 1]))
        .map(Duration::from_secs)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{backoff, Job};

    #[test]
    fn one_job_per_subject() {
        let fetch = |profile_key| Job::FetchProfile {
            aci: [1; 16],
            profile_key,
            expire_timer: 0,
            expire_timer_version: 1,
        };
        assert_eq!(fetch([2; 32]).key(), fetch([3; 32]).key());
        assert_ne!(Job::AnswerContacts.key(), Job::AnswerKeys.key());
    }

    #[test]
    fn the_log_shows_no_keys() {
        let jobs = [
            Job::FetchProfile {
                aci: [1; 16],
                profile_key: [0xab; 32],
                expire_timer: 0,
                expire_timer_version: 1,
            },
            Job::UpdateGroup {
                master_key: [0xab; 32],
                revision: 3,
            },
            Job::InstallStickerPack {
                pack_id: vec![1; 16],
                pack_key: vec![0xab; 32],
            },
            Job::SaveContacts {
                contacts: vec![0xab; 32],
            },
        ];
        for job in jobs {
            // Four bytes of a group's master key name it, as in a thread's.
            assert!(!format!("{job}").contains("ababababab"));
            assert!(!format!("{job:?}").contains("ababababab"));
            assert!(!format!("{job:?}").contains("171, 171"));
        }
    }

    #[test]
    fn a_job_waits_longer_each_time_and_is_given_up() {
        let waits: Vec<_> = (1..=6).map(|attempts| backoff(attempts, false)).collect();
        let secs = [5, 30, 120, 600, 3600, 6 * 3600];
        assert_eq!(waits, secs.map(|secs| Some(Duration::from_secs(secs))));
        assert!(backoff(7, false).is_none());
    }

    #[test]
    fn a_job_the_connection_failed_is_not_given_up() {
        assert_eq!(backoff(1, true), backoff(1, false));
        assert_eq!(backoff(70, true), backoff(6, false));
    }
}
