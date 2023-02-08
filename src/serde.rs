pub mod serde_profile_key {
    use libsignal_service::prelude::ProfileKey;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(profile_key: &ProfileKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&base64::encode(&profile_key.bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<ProfileKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: [u8; 32] = base64::decode(String::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)?
            .try_into()
            .map_err(|e: Vec<u8>| serde::de::Error::invalid_length(e.len(), &"32 bytes"))?;
        Ok(ProfileKey::create(bytes))
    }
}
