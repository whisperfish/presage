#[allow(clippy::derive_partial_eq_without_eq)]

mod textsecure {
    include!(concat!(env!("OUT_DIR"), "/textsecure.rs"));
}

use std::str::FromStr;

use presage::libsignal_service::content::Content;
use presage::libsignal_service::content::ContentBody;
use presage::libsignal_service::content::Metadata;
use presage::libsignal_service::prelude::Uuid;
use presage::libsignal_service::proto;
use presage::libsignal_service::ServiceAddress;

use crate::SledStoreError;

use self::textsecure::AddressProto;
use self::textsecure::MetadataProto;

impl From<ServiceAddress> for AddressProto {
    fn from(s: ServiceAddress) -> Self {
        AddressProto {
            uuid: Some(s.uuid.as_bytes().to_vec()),
        }
    }
}

impl TryFrom<AddressProto> for ServiceAddress {
    type Error = SledStoreError;

    fn try_from(address: AddressProto) -> Result<Self, Self::Error> {
        address
            .uuid
            .and_then(|bytes| Some(Uuid::from_bytes(bytes.try_into().ok()?)))
            .ok_or_else(|| SledStoreError::NoUuid)
            .map(Self::new_aci)
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
            destination_uuid: Some(m.destination.uuid.to_string()),
        }
    }
}

impl TryFrom<MetadataProto> for Metadata {
    type Error = SledStoreError;

    fn try_from(metadata: MetadataProto) -> Result<Self, Self::Error> {
        Ok(Metadata {
            sender: metadata.address.ok_or(SledStoreError::NoUuid)?.try_into()?,
            destination: ServiceAddress::new_aci(match metadata.destination_uuid.as_deref() {
                Some(value) => value.parse().map_err(|_| SledStoreError::NoUuid),
                None => Ok(Uuid::nil()),
            }?),
            sender_device: metadata
                .sender_device
                .and_then(|m| m.try_into().ok())
                .unwrap_or_default(),
            server_guid: metadata
                .server_guid
                .and_then(|u| crate::Uuid::from_str(&u).ok()),
            timestamp: metadata
                .timestamp
                .and_then(|m| m.try_into().ok())
                .unwrap_or_default(),
            needs_receipt: metadata.needs_receipt.unwrap_or_default(),
            unidentified_sender: false,
        })
    }
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ContentProto {
    #[prost(message, required, tag = "1")]
    metadata: MetadataProto,
    #[prost(message, required, tag = "2")]
    content: proto::Content,
}

impl From<Content> for ContentProto {
    fn from(c: Content) -> Self {
        (c.metadata, c.body).into()
    }
}

impl From<(Metadata, ContentBody)> for ContentProto {
    fn from((metadata, content_body): (Metadata, ContentBody)) -> Self {
        ContentProto {
            metadata: metadata.into(),
            content: content_body.into_proto(),
        }
    }
}

impl TryInto<Content> for ContentProto {
    type Error = SledStoreError;

    fn try_into(self) -> Result<Content, Self::Error> {
        let metadata = self.metadata.try_into()?;
        Content::from_proto(self.content, metadata).map_err(|_| SledStoreError::UnsupportedContent)
    }
}
