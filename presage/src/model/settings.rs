use libsignal_service::proto::sync_message::Configuration;
use serde::{Deserialize, Serialize};

/// Account-wide preferences, kept in sync with the other devices of the account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub read_receipts: bool,
    pub typing_indicators: bool,
    pub link_previews: bool,
    pub unidentified_delivery_indicators: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            read_receipts: true,
            typing_indicators: true,
            link_previews: true,
            unidentified_delivery_indicators: false,
        }
    }
}

impl Settings {
    /// Applies the fields present in a configuration sync message.
    pub fn apply(&mut self, configuration: &Configuration) {
        let Configuration {
            read_receipts,
            unidentified_delivery_indicators,
            typing_indicators,
            link_previews,
        } = *configuration;
        if let Some(value) = read_receipts {
            self.read_receipts = value;
        }
        if let Some(value) = unidentified_delivery_indicators {
            self.unidentified_delivery_indicators = value;
        }
        if let Some(value) = typing_indicators {
            self.typing_indicators = value;
        }
        if let Some(value) = link_previews {
            self.link_previews = value;
        }
    }
}

impl From<Settings> for Configuration {
    fn from(settings: Settings) -> Self {
        Self {
            read_receipts: Some(settings.read_receipts),
            unidentified_delivery_indicators: Some(settings.unidentified_delivery_indicators),
            typing_indicators: Some(settings.typing_indicators),
            link_previews: Some(settings.link_previews),
        }
    }
}
