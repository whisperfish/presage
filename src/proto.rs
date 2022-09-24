#[allow(clippy::derive_partial_eq_without_eq)]

mod textsecure {
    include!(concat!(env!("OUT_DIR"), "/textsecure.rs"));
}

use std::str::FromStr;

use self::textsecure::AddressProto;
use self::textsecure::MetadataProto;
use crate::prelude::{PhoneNumber, ServiceAddress};
use libsignal_service::content::Metadata;
use libsignal_service::prelude::Content;
use libsignal_service::prelude::Uuid;

impl AddressProto {
    pub fn from_service(s: ServiceAddress) -> AddressProto {
        AddressProto {
            uuid: s.uuid.map(|u| u.as_bytes().to_vec()),
            e164: s.e164(),
        }
    }

    pub fn into_service(self) -> ServiceAddress {
        ServiceAddress {
            uuid: self
                .uuid
                .map(|u| Uuid::from_bytes(u.try_into().expect("Proto to have 16 bytes uuid"))),
            phonenumber: self.e164.and_then(|p| PhoneNumber::from_str(&p).ok()),
            relay: None,
        }
    }
}

impl MetadataProto {
    pub fn from_metadata(m: Metadata) -> MetadataProto {
        MetadataProto {
            address: Some(AddressProto::from_service(m.sender)),
            sender_device: m.sender_device.try_into().ok(),
            timestamp: m.timestamp.try_into().ok(),
            server_received_timestamp: None,
            server_delivered_timestamp: None,
            needs_receipt: Some(m.needs_receipt),
            server_guid: None,
            group_id: None,
            destination_uuid: None,
        }
    }

    pub fn into_metadata(self) -> Metadata {
        Metadata {
            sender: self
                .address
                .map(|a| a.into_service())
                .unwrap_or_else(|| ServiceAddress {
                    uuid: None,
                    phonenumber: None,
                    relay: None,
                }),
            sender_device: self
                .sender_device
                .and_then(|m| m.try_into().ok())
                .unwrap_or_default(),
            timestamp: self
                .timestamp
                .and_then(|m| m.try_into().ok())
                .unwrap_or_default(),
            needs_receipt: self.needs_receipt.unwrap_or_default(),
        }
    }
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ContentProto {
    #[prost(message, required, tag = "1")]
    metadata: MetadataProto,
    #[prost(message, required, tag = "2")]
    content: crate::prelude::proto::Content,
}

impl ContentProto {
    pub fn from_content(c: Content) -> ContentProto {
        ContentProto {
            metadata: MetadataProto::from_metadata(c.metadata),
            content: c.body.into_proto(),
        }
    }

    pub fn into_content(self) -> Content {
        content_from_proto(self.content, self.metadata.into_metadata())
            .expect("Content to have at least one type")
    }
}

/// TODO: From  libsignal_service
/// Converts a proto::Content into a public Content, including metadata.
pub(crate) fn content_from_proto(
    p: libsignal_service::proto::Content,
    metadata: Metadata,
) -> Option<libsignal_service::content::Content> {
    // The Java version also assumes only one content type at a time.
    // It's a bit sad that we cannot really match here, we've got no
    // r#type() method.
    // Allow the manual map (if let Some -> option.map(||)), because it
    // reduces the git diff when more types would be added.
    #[allow(clippy::manual_map)]
    if let Some(msg) = p.data_message {
        Some(libsignal_service::content::Content::from_body(
            msg, metadata,
        ))
    } else if let Some(msg) = p.sync_message {
        Some(libsignal_service::content::Content::from_body(
            msg, metadata,
        ))
    } else if let Some(msg) = p.call_message {
        Some(libsignal_service::content::Content::from_body(
            msg, metadata,
        ))
    } else if let Some(msg) = p.receipt_message {
        Some(libsignal_service::content::Content::from_body(
            msg, metadata,
        ))
    } else if let Some(msg) = p.typing_message {
        Some(libsignal_service::content::Content::from_body(
            msg, metadata,
        ))
    } else {
        None
    }
}
