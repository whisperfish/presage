//! Integration test for the DecryptionErrorMessage handler that fires inside
//! `Manager::receive_messages`' receive loop. The handler's job is to wipe
//! every session held with the sender so that the next outbound message
//! re-establishes from a fresh prekey bundle. Before it was added, presage
//! received the peer's session-reset request, logged it, and did nothing —
//! which left sender and recipient permanently out of sync any time crypto
//! drift occurred.
//!
//! This lives under `tests/` rather than as an inline unit test because
//! presage depends on presage-store-sqlite only as a dev-dependency, and
//! presage-store-sqlite itself depends on presage via `path = "../presage"`.
//! That circularity confuses `cargo test`'s resolver in the same-crate
//! unit-test slot, but integration tests are compiled as external crates and
//! avoid it.

use libsignal_service::content::{Content, ContentBody, Metadata};
use libsignal_service::proto::{DataMessage, DecryptionErrorMessage};
use libsignal_service::protocol::{
    DeviceId, ProtocolAddress, ServiceId, SessionRecord, SessionStore,
};
use presage::manager::registered::{
    delete_all_sessions_for_recipient, maybe_handle_decryption_error_message,
};
use presage::store::Store;
use presage_store_sqlite::{OnNewIdentity, SqliteStore};

const SENDER_UUID: &str = "9d0652a3-dcc3-4d11-975f-74d61598733f";
const DESTINATION_UUID: &str = "11111111-1111-1111-1111-111111111111";

fn sender() -> ServiceId {
    ServiceId::parse_from_service_id_string(SENDER_UUID).expect("valid UUID")
}

fn address() -> ProtocolAddress {
    ProtocolAddress::new(
        SENDER_UUID.to_string(),
        DeviceId::try_from(1u32).expect("valid device id"),
    )
}

fn content_from_sender(body: ContentBody) -> Content {
    Content {
        metadata: Metadata {
            destination: ServiceId::parse_from_service_id_string(DESTINATION_UUID)
                .expect("valid UUID"),
            sender: sender(),
            sender_device: DeviceId::try_from(1u32).expect("valid device id"),
            timestamp: 0,
            needs_receipt: false,
            unidentified_sender: true,
            was_plaintext: false,
            server_guid: None,
        },
        body,
    }
}

async fn seed_sessions<S: Store>(store: &S) -> Result<(), Box<dyn std::error::Error>> {
    let mut aci = store.aci_protocol_store();
    let mut pni = store.pni_protocol_store();
    aci.store_session(&address(), &SessionRecord::new_fresh())
        .await?;
    pni.store_session(&address(), &SessionRecord::new_fresh())
        .await?;
    Ok(())
}

async fn sessions_present<S: Store>(store: &S) -> Result<(bool, bool), Box<dyn std::error::Error>> {
    let aci = store
        .aci_protocol_store()
        .load_session(&address())
        .await?
        .is_some();
    let pni = store
        .pni_protocol_store()
        .load_session(&address())
        .await?
        .is_some();
    Ok((aci, pni))
}

/// Core behaviour change: a sealed-sender DecryptionErrorMessage from a
/// peer should cause us to wipe both our ACI and PNI sessions for that peer.
/// Before this change the handler logged the DEM and continued — leaving the
/// stale ratchet in place, so every subsequent outbound hit the same failure.
#[tokio::test]
async fn dem_content_wipes_both_aci_and_pni_sessions_for_sender(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = SqliteStore::open(":memory:", OnNewIdentity::Trust).await?;

    seed_sessions(&store).await?;
    assert_eq!(
        sessions_present(&store).await?,
        (true, true),
        "test setup: sessions seeded in both stores"
    );

    let dem = DecryptionErrorMessage {
        timestamp: Some(1),
        device_id: Some(1),
        ratchet_key: None,
    };
    let content = content_from_sender(ContentBody::DecryptionErrorMessage(dem));

    let handled = maybe_handle_decryption_error_message(&store, &content).await;

    assert!(
        handled,
        "DEM content must signal it was handled (caller will skip further processing)"
    );
    assert_eq!(
        sessions_present(&store).await?,
        (false, false),
        "both ACI and PNI sessions must be wiped after DEM handling — this is the fix"
    );

    Ok(())
}

/// Regression guard: non-DEM contents (DataMessage, SyncMessage, etc.) must
/// NOT short-circuit the receive loop and must NOT touch any sessions.
/// Without this guard a future refactor could widen the archival to unrelated
/// message types and invisibly drop the peer's session every message.
#[tokio::test]
async fn data_message_does_not_wipe_sessions(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = SqliteStore::open(":memory:", OnNewIdentity::Trust).await?;

    seed_sessions(&store).await?;

    let content = content_from_sender(ContentBody::DataMessage(DataMessage {
        body: Some("hello".to_string()),
        ..Default::default()
    }));

    let handled = maybe_handle_decryption_error_message(&store, &content).await;

    assert!(
        !handled,
        "DataMessage content must not short-circuit the receive loop"
    );
    assert_eq!(
        sessions_present(&store).await?,
        (true, true),
        "DataMessage must not touch sessions"
    );

    Ok(())
}

/// Idempotency: a second DEM from the same sender (likely after they send
/// another session-restart because they still haven't seen a fresh prekey
/// message from us) must also succeed with no state change. This guards
/// against the archival path accidentally erroring on already-empty stores
/// and letting DEMs leak through to orchestrator-level handling.
#[tokio::test]
async fn delete_all_sessions_for_recipient_is_idempotent(
) -> Result<(), Box<dyn std::error::Error>> {
    let store = SqliteStore::open(":memory:", OnNewIdentity::Trust).await?;

    // No sessions seeded; deleting should still be a clean no-op.
    delete_all_sessions_for_recipient(&store, &sender()).await?;
    delete_all_sessions_for_recipient(&store, &sender()).await?;

    Ok(())
}
