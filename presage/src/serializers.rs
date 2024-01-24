pub(crate) mod serde_profile_key {

    use base64::{engine::general_purpose, Engine};
    use libsignal_service::prelude::ProfileKey;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S>(profile_key: &ProfileKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&general_purpose::STANDARD.encode(profile_key.bytes))
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<ProfileKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: [u8; 32] = general_purpose::STANDARD
            .decode(String::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)?
            .try_into()
            .map_err(|e: Vec<u8>| serde::de::Error::invalid_length(e.len(), &"32 bytes"))?;
        Ok(ProfileKey::create(bytes))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_serialize_deserialize() {
            let profile_key = ProfileKey {
                bytes: *b"kaijpqxdvaiaeaulmsrozckjkgbpjowc",
            };
            let mut serializer = serde_json::Serializer::new(Vec::new());
            serialize(&profile_key, &mut serializer).unwrap();
            let json = String::from_utf8(serializer.into_inner()).unwrap();
            assert_eq!(json, "\"a2FpanBxeGR2YWlhZWF1bG1zcm96Y2tqa2dicGpvd2M=\"");

            let mut deserializer = serde_json::Deserializer::from_slice(json.as_bytes());
            let profile_key2: ProfileKey = deserialize(&mut deserializer).unwrap();
            assert_eq!(profile_key.bytes, profile_key2.bytes);
        }
    }
}
