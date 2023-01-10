use libsignal_service::{
    content::{ContentBody, DataMessage, SyncMessage},
    proto::sync_message::Sent,
    proto::GroupContextV2,
};

pub(crate) trait ContentBodyExt {
    fn group_v2(&self) -> Option<&GroupContextV2>;
}

impl ContentBodyExt for ContentBody {
    fn group_v2(&self) -> Option<&GroupContextV2> {
        match self {
            ContentBody::DataMessage(DataMessage {
                group_v2: Some(group_v2),
                ..
            })
            | ContentBody::SynchronizeMessage(SyncMessage {
                sent:
                    Some(Sent {
                        message:
                            Some(DataMessage {
                                group_v2: Some(group_v2),
                                ..
                            }),
                        ..
                    }),
                ..
            }) => Some(group_v2),
            _ => None,
        }
    }
}
