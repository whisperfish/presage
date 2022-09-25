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

impl From<ServiceAddress> for AddressProto {
    fn from(s: ServiceAddress) -> Self {
        AddressProto {
            uuid: s.uuid.map(|u| u.as_bytes().to_vec()),
            e164: s.e164(),
        }
    }
}

impl Into<ServiceAddress> for AddressProto {
    fn into(self) -> ServiceAddress {
        ServiceAddress {
            uuid: self
                .uuid
                .map(|u| Uuid::from_bytes(u.try_into().expect("Proto to have 16 bytes uuid"))),
            phonenumber: self.e164.and_then(|p| PhoneNumber::from_str(&p).ok()),
            relay: None,
        }
    }
}

impl From<Metadata> for MetadataProto {
    fn from(m: Metadata) -> Self {
        MetadataProto {
            address: Some(m.sender.into()),
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
}

impl Into<Metadata> for MetadataProto {
    fn into(self) -> Metadata {
        Metadata {
            sender: self
                .address
                .map(|a| a.into())
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

impl From<Content> for ContentProto {
    fn from(c: Content) -> Self {
        ContentProto {
            metadata: c.metadata.into(),
            content: c.body.into_proto(),
        }
    }
}

#[derive(thiserror::Error, Debug)]
enum ContentProtoError {}

impl TryInto<Content> for ContentProto {
    type Error = crate::Error;

    fn try_into(self) -> Result<Content, Self::Error> {
        Content::from_proto(self.content, self.metadata.into())
            .ok_or(crate::Error::ContentMissingMessage)
    }
}
