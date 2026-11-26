use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use libsignal_service::proto::{
    sync_message::{Configuration, Content as SyncContent},
    SyncMessage,
};

use crate::model::settings::Settings;
use crate::store::Store;
use crate::{Error, Manager};

use super::{Registered, RegistrationType};

impl<S: Store> Manager<S, Registered> {
    pub fn settings(&self) -> Settings {
        self.state
            .settings
            .read()
            .expect("settings lock poisoned")
            .clone()
    }

    pub async fn set_read_receipts(&mut self, enabled: bool) -> Result<(), Error<S::Error>> {
        self.set_settings(Settings {
            read_receipts: enabled,
            ..self.settings()
        })
        .await
    }

    pub async fn set_link_previews(&mut self, enabled: bool) -> Result<(), Error<S::Error>> {
        self.set_settings(Settings {
            link_previews: enabled,
            ..self.settings()
        })
        .await
    }

    pub async fn set_typing_indicators(&mut self, enabled: bool) -> Result<(), Error<S::Error>> {
        self.set_settings(Settings {
            typing_indicators: enabled,
            ..self.settings()
        })
        .await
    }

    pub async fn set_unidentified_delivery_indicators(
        &mut self,
        enabled: bool,
    ) -> Result<(), Error<S::Error>> {
        self.set_settings(Settings {
            unidentified_delivery_indicators: enabled,
            ..self.settings()
        })
        .await
    }

    async fn set_settings(&mut self, settings: Settings) -> Result<(), Error<S::Error>> {
        self.store.save_settings(&settings).await?;
        let configuration = Configuration::from(&settings);
        *self.state.settings.write().expect("settings lock poisoned") = settings;

        // Linked devices take their configuration from the primary.
        if self.registration_type() == RegistrationType::Primary {
            let sync_message = SyncMessage {
                content: Some(SyncContent::Configuration(configuration)),
                ..SyncMessage::with_padding(&mut rand::rng())
            };
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_millis() as u64;
            self.send_message(self.state.data.service_ids.aci(), sync_message, timestamp)
                .await?;
        }

        Ok(())
    }
}

pub(crate) async fn update_settings<S: Store>(
    store: &mut S,
    settings: &RwLock<Settings>,
    update: impl FnOnce(&mut Settings),
) -> Result<(), S::Error> {
    let mut updated = settings.read().expect("settings lock poisoned").clone();
    update(&mut updated);
    store.save_settings(&updated).await?;
    *settings.write().expect("settings lock poisoned") = updated;
    Ok(())
}
