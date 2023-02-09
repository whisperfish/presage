#[allow(clippy::derive_partial_eq_without_eq)]

mod textsecure {
    include!(concat!(env!("OUT_DIR"), "/textsecure.rs"));
}

use self::textsecure::AddressProto;
use self::textsecure::MetadataProto;
use crate::prelude::ServiceAddress;
use crate::Error;
use libsignal_service::content::ContentBody;
use libsignal_service::content::Metadata;
use libsignal_service::prelude::Content;
use libsignal_service::ParseServiceAddressError;

impl From<ServiceAddress> for AddressProto {
    fn from(s: ServiceAddress) -> Self {
        AddressProto {
            uuid: Some(s.uuid.as_bytes().to_vec()),
        }
    }
}

impl TryFrom<AddressProto> for ServiceAddress {
    type Error = ParseServiceAddressError;

    fn try_from(address: AddressProto) -> Result<Self, Self::Error> {
        address.uuid.as_deref().try_into()
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

impl TryFrom<MetadataProto> for Metadata {
    type Error = ParseServiceAddressError;

    fn try_from(metadata: MetadataProto) -> Result<Self, Self::Error> {
        Ok(Metadata {
            sender: metadata
                .address
                .ok_or(ParseServiceAddressError::NoUuid)?
                .try_into()?,
            sender_device: metadata
                .sender_device
                .and_then(|m| m.try_into().ok())
                .unwrap_or_default(),
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
    content: crate::prelude::proto::Content,
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

#[derive(thiserror::Error, Debug)]
enum ContentProtoError {}

impl TryInto<Content> for ContentProto {
    type Error = crate::Error;

    fn try_into(self) -> Result<Content, Self::Error> {
        Content::from_proto(self.content, self.metadata.try_into()?).map_err(Error::from)
    }
}
