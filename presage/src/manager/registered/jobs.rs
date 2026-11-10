//! Runs the [`Job`]s the store keeps, while receiving.

use std::collections::HashSet;
use std::fmt;
use std::panic::AssertUnwindSafe;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures::channel::mpsc;
use futures::future::{self, Either};
use futures::{pin_mut, FutureExt, StreamExt};
use libsignal_service::prelude::{MessageSenderError, ProtobufMessage, ServiceError, Uuid};
use libsignal_service::profile_cipher::ProfileCipher;
use libsignal_service::proto::sync_message::{self, Content as SyncContent, StickerPackOperation};
use libsignal_service::proto::{contact_details, SyncMessage};
use libsignal_service::protocol::{Aci, ServiceId};
use libsignal_service::push_service::PushService;
use libsignal_service::receiver::MessageReceiver;
use libsignal_service::sender::ContactDetails;
use libsignal_service::zkgroup::profiles::ProfileKey;
use libsignal_service::{ProfileManagerError, StorageServiceError};
use tracing::{debug, error, warn};

use super::{download_sticker_pack, save_contact_from_profile, update_group, Registered};
use crate::model::jobs::{backoff, Job, QueuedJob};
use crate::model::messages::Received;
use crate::store::Store;
use crate::{Error, Manager};

/// How many jobs run at once.
const CONCURRENT: usize = 2;

impl<S: Store> Manager<S, Registered> {
    /// Does `job`. Returns what it brings, to tell the client.
    async fn run_job(mut self, job: &Job) -> Result<Vec<Received>, Error<S::Error>> {
        match job {
            Job::FetchProfile {
                aci,
                profile_key,
                expire_timer,
                expire_timer_version,
            } => {
                let aci = Aci::from(Uuid::from_bytes(*aci));
                let profile_key = ProfileKey::create(*profile_key);
                // Their key changed again meanwhile: that message queued a fetch of its own.
                let current = self.store.profile_key(&aci.into()).await?;
                if current.is_some_and(|current| current.bytes != profile_key.bytes) {
                    return Ok(Vec::new());
                }
                let profile = self
                    .identified_websocket(false)
                    .await?
                    .retrieve_profile_by_id(aci, Some(profile_key))
                    .await?;
                let profile = ProfileCipher::new(profile_key).decrypt(profile)?;
                save_contact_from_profile(
                    &mut self.store,
                    aci,
                    profile_key,
                    profile,
                    *expire_timer,
                    *expire_timer_version,
                )
                .await?;
                Ok(Vec::new())
            }
            Job::UpdateGroup {
                master_key,
                revision,
            } => {
                let mut groups_manager = Box::pin(self.groups_manager()).await?;
                update_group(&self.store, &mut groups_manager, master_key, revision).await?;
                Ok(Vec::new())
            }
            Job::InstallStickerPack { pack_id, pack_key } => {
                let operation = StickerPackOperation {
                    pack_id: Some(pack_id.clone()),
                    pack_key: Some(pack_key.clone()),
                    r#type: Some(sync_message::sticker_pack_operation::Type::Install as i32),
                };
                let websocket = self.unidentified_websocket().await?;
                let pack = download_sticker_pack(self.store.clone(), websocket, &operation).await?;
                debug!(
                    "downloaded sticker pack: {} made by {}",
                    pack.manifest.title, pack.manifest.author
                );
                Ok(vec![Received::StickerPackInstalled {
                    pack_id: pack_id.clone(),
                }])
            }
            Job::SyncStorage => {
                // Again while the manifest moves on: what tells of a change during the read
                // queues this same job, which this run settles.
                let mut read = None;
                while let Some(version) = self.sync_groups_from_storage_service().await? {
                    if read.is_some_and(|read| version <= read) {
                        break;
                    }
                    read = Some(version);
                }
                Ok(Vec::new())
            }
            Job::SaveContacts { contacts } => {
                let contacts = sync_message::Contacts::decode(contacts.as_slice())
                    .map_err(ServiceError::from)?;
                let push_service = self.identified_push_service();
                save_contacts(&mut self.store, push_service, &contacts).await?;
                Ok(vec![Received::Contacts])
            }
            Job::AnswerContacts => {
                // All of them or no answer: the answer replaces what the other device has.
                let contacts = self
                    .store
                    .contacts()
                    .await?
                    .collect::<Result<Vec<_>, _>>()?;
                let aci = self.state.data.service_ids.aci();
                self.new_message_sender()
                    .await?
                    .send_contact_details(
                        &ServiceId::Aci(aci),
                        None,
                        contacts.into_iter().map(|c| ContactDetails {
                            number: c.phone_number.map(|p| p.to_string()),
                            aci: Some(c.uuid.to_string()),
                            aci_binary: Some(c.uuid.into_bytes().into()),
                            name: Some(c.name),
                            avatar: c.avatar.map(|a| contact_details::Avatar {
                                content_type: Some(a.content_type),
                                length: a.reader.len().try_into().ok(),
                            }),
                            expire_timer: Some(c.expire_timer),
                            expire_timer_version: Some(c.expire_timer_version),
                            inbox_position: None,
                        }),
                        false,
                        true,
                    )
                    .await?;
                Ok(Vec::new())
            }
            Job::AnswerKeys => {
                let account_entropy_pool = self
                    .store
                    .fetch_account_entropy_pool()
                    .await?
                    .map(|pool| pool.to_string());
                self.send_sync(SyncContent::Keys(sync_message::Keys {
                    account_entropy_pool,
                    media_root_backup_key: None,
                }))
                .await?;
                Ok(Vec::new())
            }
            Job::AnswerBlocked => {
                warn!("storing blocked user is not implemented yet! we will not report blocked users to the device requesting the sync.");
                self.send_sync(SyncContent::Blocked(sync_message::Blocked {
                    numbers: vec![],
                    acis: vec![],
                    acis_binary: vec![],
                    group_ids: vec![],
                }))
                .await?;
                Ok(Vec::new())
            }
            Job::RequestKeys => {
                // They came meanwhile.
                if self.store.fetch_account_entropy_pool().await?.is_some() {
                    return Ok(Vec::new());
                }
                self.send_sync(SyncContent::Request(sync_message::Request {
                    r#type: Some(sync_message::request::Type::Keys.into()),
                }))
                .await?;
                Ok(Vec::new())
            }
        }
    }

    async fn send_sync(&self, content: SyncContent) -> Result<(), Error<S::Error>> {
        self.new_message_sender()
            .await?
            .send_sync_message(SyncMessage {
                content: Some(content),
                ..SyncMessage::with_padding(&mut rand::rng())
            })
            .await?;
        Ok(())
    }
}

/// Queues `job` and wakes the runner, if one runs. A job that can't be queued is lost.
pub(super) async fn enqueue<S: Store>(store: &mut S, wake: &tokio::sync::Notify, job: Job) {
    match store.enqueue_job(&job).await {
        Ok(()) => wake.notify_one(),
        Err(error) => error!(%error, %job, "failed to queue a job"),
    }
}

/// Downloads and saves the contacts a device of ours sent.
pub(super) async fn save_contacts<S: Store>(
    store: &mut S,
    push_service: PushService,
    contacts: &sync_message::Contacts,
) -> Result<(), Error<S::Error>> {
    let contacts = MessageReceiver::new(push_service)
        .retrieve_contacts(contacts)
        .await?;
    for contact in contacts.filter_map(Result::ok) {
        store.save_contact(&contact.into()).await?;
    }
    Ok(())
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_millis() as u64)
}

/// Runs the queued jobs until dropped: each when it is due, all of them once at the start (the
/// connection is new, whatever made them fail may be gone). A job that fails waits
/// ([`backoff`]) and is given up after its last wait, unless it was the connection that failed.
/// What a job brings is told to `told`.
pub(super) async fn run<S: Store>(
    manager: Manager<S, Registered>,
    told: mpsc::UnboundedSender<Received>,
) {
    let wake = manager.state.jobs_wake.clone();
    let store = manager.store.clone();
    let (finished, mut done) = mpsc::unbounded();
    let mut in_flight = HashSet::new();
    // Those queued at the start, until each has run once whatever its wait.
    let mut at_start: Option<HashSet<u64>> = None;
    loop {
        let jobs = store.jobs().await.unwrap_or_else(|error| {
            error!(%error, "failed to read the queued jobs");
            Vec::new()
        });
        let at_start = at_start.get_or_insert_with(|| jobs.iter().map(|job| job.id).collect());
        let now_ms = now();
        let mut next_due = None;
        for job in jobs {
            if in_flight.contains(&job.id) {
                continue;
            }
            if job.due_at > now_ms && !at_start.contains(&job.id) {
                next_due = Some(next_due.map_or(job.due_at, |due: u64| due.min(job.due_at)));
            } else if in_flight.len() < CONCURRENT {
                at_start.remove(&job.id);
                in_flight.insert(job.id);
                let (manager, told, finished) = (manager.clone(), told.clone(), finished.clone());
                // A task of its own: a job goes on while this loop waits for the store.
                tokio::task::spawn_local(async move {
                    let mut store = manager.store.clone();
                    let id = job.id;
                    let run = AssertUnwindSafe(manager.run_job(&job.job)).catch_unwind();
                    match run.await {
                        Ok(result) => settle(&mut store, &told, job, result).await,
                        // It would panic again.
                        Err(_) => {
                            error!(job = %job.job, "job panicked; giving up");
                            if let Err(error) = store.finish_job(&job).await {
                                error!(%error, "failed to note a job's outcome; it runs again");
                            }
                        }
                    }
                    let _ = finished.unbounded_send(id);
                });
            }
        }

        let sleep = async {
            match next_due {
                Some(due) => {
                    tokio::time::sleep(Duration::from_millis(due.saturating_sub(now_ms))).await
                }
                None => future::pending().await,
            }
        };
        let woken = async {
            let notified = wake.notified();
            pin_mut!(sleep, notified);
            future::select(sleep, notified).await;
        };
        pin_mut!(woken);
        if let Either::Left((Some(id), _)) = future::select(done.next(), woken).await {
            in_flight.remove(&id);
        }
    }
}

/// Whether `error` is the connection's and not the server's answer: worth trying again, and no
/// reason to give a job up.
pub(super) fn connection_failed<E: std::error::Error>(error: &Error<E>) -> bool {
    let service = |error: &ServiceError| {
        matches!(
            error,
            ServiceError::Timeout { .. }
                | ServiceError::SendError { .. }
                | ServiceError::IO(_)
                | ServiceError::WsError(_)
                | ServiceError::WsClosing { .. }
                | ServiceError::RateLimitExceeded { .. }
        )
    };
    match error {
        Error::ServiceError(error)
        | Error::ProfileManagerError(ProfileManagerError::ServiceError(error))
        | Error::StorageServiceError(StorageServiceError::Service(error)) => service(error),
        Error::MessageSenderError(error) => {
            matches!(&**error, MessageSenderError::ServiceError(error) if service(error))
        }
        Error::Timeout(_) => true,
        _ => false,
    }
}

/// An error with its causes, each after a colon: reqwest's own message leaves them out ("error
/// sending request for url" doesn't say that the connection closed under the request).
pub(super) struct Causes<'a>(pub(super) &'a dyn std::error::Error);

impl fmt::Display for Causes<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)?;
        let mut source = self.0.source();
        while let Some(cause) = source {
            write!(f, ": {cause}")?;
            source = cause.source();
        }
        Ok(())
    }
}

async fn settle<S: Store>(
    store: &mut S,
    told: &mpsc::UnboundedSender<Received>,
    job: QueuedJob,
    result: Result<Vec<Received>, Error<S::Error>>,
) {
    let stored = match result {
        Ok(received) => {
            debug!(job = %job.job, "job done");
            for received in received {
                // Fails only once the stream is gone.
                let _ = told.unbounded_send(received);
            }
            store.finish_job(&job).await
        }
        Err(error) => match backoff(job.attempts + 1, connection_failed(&error)) {
            Some(wait) => {
                warn!(error = %Causes(&error), job = %job.job, ?wait, "job failed; trying again later");
                store.retry_job(&job, now() + wait.as_millis() as u64).await
            }
            None => {
                error!(error = %Causes(&error), job = %job.job, "job failed; giving up");
                store.finish_job(&job).await
            }
        },
    };
    if let Err(error) = stored {
        error!(%error, "failed to note a job's outcome; it runs again");
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use libsignal_service::prelude::ServiceError;

    use super::{connection_failed, Causes};
    use crate::Error;

    /// A broken connection is worth fetching again; a refusal isn't.
    #[test]
    fn only_a_failed_connection_is_tried_again() {
        let failed = |error| connection_failed(&Error::<Infallible>::ServiceError(error));
        assert!(failed(ServiceError::SendError {
            reason: "connection closed before message completed".into()
        }));
        assert!(failed(ServiceError::IO(std::io::Error::other("reset"))));
        assert!(failed(ServiceError::Timeout { reason: "late" }));
        assert!(!failed(ServiceError::Unauthorized));
        assert!(!connection_failed(&Error::<Infallible>::UnknownGroup));
    }

    /// The causes follow the error, as reqwest's own message leaves them out.
    #[test]
    fn an_error_is_logged_with_its_causes() {
        #[derive(Debug, thiserror::Error)]
        #[error("error sending request for url")]
        struct Sending(#[source] std::io::Error);

        let error = Sending(std::io::Error::other(
            "connection closed before message completed",
        ));
        assert_eq!(
            Causes(&error).to_string(),
            "error sending request for url: connection closed before message completed"
        );
        assert_eq!(Causes(&std::io::Error::other("alone")).to_string(), "alone");
    }
}
