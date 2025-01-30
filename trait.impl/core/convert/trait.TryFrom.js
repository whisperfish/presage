(function() {
    var implementors = Object.fromEntries([["libsignal_protocol",[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;&amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.u8.html\">u8</a>]&gt; for <a class=\"struct\" href=\"libsignal_protocol/kem/struct.Key.html\" title=\"struct libsignal_protocol::kem::Key\">Key</a>&lt;<a class=\"enum\" href=\"libsignal_protocol/kem/enum.Public.html\" title=\"enum libsignal_protocol::kem::Public\">Public</a>&gt;"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;&amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.u8.html\">u8</a>]&gt; for <a class=\"struct\" href=\"libsignal_protocol/kem/struct.Key.html\" title=\"struct libsignal_protocol::kem::Key\">Key</a>&lt;<a class=\"enum\" href=\"libsignal_protocol/kem/enum.Secret.html\" title=\"enum libsignal_protocol::kem::Secret\">Secret</a>&gt;"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;&amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.u8.html\">u8</a>]&gt; for <a class=\"struct\" href=\"libsignal_protocol/struct.DecryptionErrorMessage.html\" title=\"struct libsignal_protocol::DecryptionErrorMessage\">DecryptionErrorMessage</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;&amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.u8.html\">u8</a>]&gt; for <a class=\"struct\" href=\"libsignal_protocol/struct.IdentityKey.html\" title=\"struct libsignal_protocol::IdentityKey\">IdentityKey</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;&amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.u8.html\">u8</a>]&gt; for <a class=\"struct\" href=\"libsignal_protocol/struct.IdentityKeyPair.html\" title=\"struct libsignal_protocol::IdentityKeyPair\">IdentityKeyPair</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;&amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.u8.html\">u8</a>]&gt; for <a class=\"struct\" href=\"libsignal_protocol/struct.PlaintextContent.html\" title=\"struct libsignal_protocol::PlaintextContent\">PlaintextContent</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;&amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.u8.html\">u8</a>]&gt; for <a class=\"struct\" href=\"libsignal_protocol/struct.PreKeySignalMessage.html\" title=\"struct libsignal_protocol::PreKeySignalMessage\">PreKeySignalMessage</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;&amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.u8.html\">u8</a>]&gt; for <a class=\"struct\" href=\"libsignal_protocol/struct.PrivateKey.html\" title=\"struct libsignal_protocol::PrivateKey\">PrivateKey</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;&amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.u8.html\">u8</a>]&gt; for <a class=\"struct\" href=\"libsignal_protocol/struct.PublicKey.html\" title=\"struct libsignal_protocol::PublicKey\">PublicKey</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;&amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.u8.html\">u8</a>]&gt; for <a class=\"struct\" href=\"libsignal_protocol/struct.SenderKeyDistributionMessage.html\" title=\"struct libsignal_protocol::SenderKeyDistributionMessage\">SenderKeyDistributionMessage</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;&amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.u8.html\">u8</a>]&gt; for <a class=\"struct\" href=\"libsignal_protocol/struct.SenderKeyMessage.html\" title=\"struct libsignal_protocol::SenderKeyMessage\">SenderKeyMessage</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;&amp;[<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.u8.html\">u8</a>]&gt; for <a class=\"struct\" href=\"libsignal_protocol/struct.SignalMessage.html\" title=\"struct libsignal_protocol::SignalMessage\">SignalMessage</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.u8.html\">u8</a>&gt; for <a class=\"enum\" href=\"libsignal_protocol/enum.CiphertextMessageType.html\" title=\"enum libsignal_protocol::CiphertextMessageType\">CiphertextMessageType</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.u8.html\">u8</a>&gt; for <a class=\"enum\" href=\"libsignal_protocol/kem/enum.KeyType.html\" title=\"enum libsignal_protocol::kem::KeyType\">KeyType</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"struct\" href=\"libsignal_protocol/struct.PreKeyBundleContent.html\" title=\"struct libsignal_protocol::PreKeyBundleContent\">PreKeyBundleContent</a>&gt; for <a class=\"struct\" href=\"libsignal_protocol/struct.PreKeyBundle.html\" title=\"struct libsignal_protocol::PreKeyBundle\">PreKeyBundle</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"struct\" href=\"libsignal_protocol/struct.PrivateKey.html\" title=\"struct libsignal_protocol::PrivateKey\">PrivateKey</a>&gt; for <a class=\"struct\" href=\"libsignal_protocol/struct.IdentityKeyPair.html\" title=\"struct libsignal_protocol::IdentityKeyPair\">IdentityKeyPair</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"struct\" href=\"libsignal_protocol/struct.PrivateKey.html\" title=\"struct libsignal_protocol::PrivateKey\">PrivateKey</a>&gt; for <a class=\"struct\" href=\"libsignal_protocol/struct.KeyPair.html\" title=\"struct libsignal_protocol::KeyPair\">KeyPair</a>"]]],["libsignal_service",[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;&amp;KyberPreKeyRecord&gt; for <a class=\"struct\" href=\"libsignal_service/pre_keys/struct.KyberPreKeyEntity.html\" title=\"struct libsignal_service::pre_keys::KyberPreKeyEntity\">KyberPreKeyEntity</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;&amp;SignedPreKeyRecord&gt; for <a class=\"struct\" href=\"libsignal_service/pre_keys/struct.SignedPreKeyEntity.html\" title=\"struct libsignal_service::pre_keys::SignedPreKeyEntity\">SignedPreKeyEntity</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.i32.html\">i32</a>&gt; for <a class=\"enum\" href=\"libsignal_service/groups_v2/enum.Role.html\" title=\"enum libsignal_service::groups_v2::Role\">Role</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.i32.html\">i32</a>&gt; for <a class=\"enum\" href=\"libsignal_service/proto/access_control/enum.AccessRequired.html\" title=\"enum libsignal_service::proto::access_control::AccessRequired\">AccessRequired</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.i32.html\">i32</a>&gt; for <a class=\"enum\" href=\"libsignal_service/proto/attachment_pointer/enum.Flags.html\" title=\"enum libsignal_service::proto::attachment_pointer::Flags\">Flags</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.i32.html\">i32</a>&gt; for <a class=\"enum\" href=\"libsignal_service/proto/body_range/enum.Style.html\" title=\"enum libsignal_service::proto::body_range::Style\">Style</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.i32.html\">i32</a>&gt; for <a class=\"enum\" href=\"libsignal_service/proto/call_message/hangup/enum.Type.html\" title=\"enum libsignal_service::proto::call_message::hangup::Type\">Type</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.i32.html\">i32</a>&gt; for <a class=\"enum\" href=\"libsignal_service/proto/call_message/offer/enum.Type.html\" title=\"enum libsignal_service::proto::call_message::offer::Type\">Type</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.i32.html\">i32</a>&gt; for <a class=\"enum\" href=\"libsignal_service/proto/call_message/opaque/enum.Urgency.html\" title=\"enum libsignal_service::proto::call_message::opaque::Urgency\">Urgency</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.i32.html\">i32</a>&gt; for <a class=\"enum\" href=\"libsignal_service/proto/data_message/contact/email/enum.Type.html\" title=\"enum libsignal_service::proto::data_message::contact::email::Type\">Type</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.i32.html\">i32</a>&gt; for <a class=\"enum\" href=\"libsignal_service/proto/data_message/contact/phone/enum.Type.html\" title=\"enum libsignal_service::proto::data_message::contact::phone::Type\">Type</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.i32.html\">i32</a>&gt; for <a class=\"enum\" href=\"libsignal_service/proto/data_message/contact/postal_address/enum.Type.html\" title=\"enum libsignal_service::proto::data_message::contact::postal_address::Type\">Type</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.i32.html\">i32</a>&gt; for <a class=\"enum\" href=\"libsignal_service/proto/data_message/enum.Flags.html\" title=\"enum libsignal_service::proto::data_message::Flags\">Flags</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.i32.html\">i32</a>&gt; for <a class=\"enum\" href=\"libsignal_service/proto/data_message/enum.ProtocolVersion.html\" title=\"enum libsignal_service::proto::data_message::ProtocolVersion\">ProtocolVersion</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.i32.html\">i32</a>&gt; for <a class=\"enum\" href=\"libsignal_service/proto/data_message/payment/activation/enum.Type.html\" title=\"enum libsignal_service::proto::data_message::payment::activation::Type\">Type</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.i32.html\">i32</a>&gt; for <a class=\"enum\" href=\"libsignal_service/proto/data_message/quote/enum.Type.html\" title=\"enum libsignal_service::proto::data_message::quote::Type\">Type</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.i32.html\">i32</a>&gt; for <a class=\"enum\" href=\"libsignal_service/proto/enum.ProvisioningVersion.html\" title=\"enum libsignal_service::proto::ProvisioningVersion\">ProvisioningVersion</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.i32.html\">i32</a>&gt; for <a class=\"enum\" href=\"libsignal_service/proto/envelope/enum.Type.html\" title=\"enum libsignal_service::proto::envelope::Type\">Type</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.i32.html\">i32</a>&gt; for <a class=\"enum\" href=\"libsignal_service/proto/group_context/enum.Type.html\" title=\"enum libsignal_service::proto::group_context::Type\">Type</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.i32.html\">i32</a>&gt; for <a class=\"enum\" href=\"libsignal_service/proto/member/enum.Role.html\" title=\"enum libsignal_service::proto::member::Role\">Role</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.i32.html\">i32</a>&gt; for <a class=\"enum\" href=\"libsignal_service/proto/receipt_message/enum.Type.html\" title=\"enum libsignal_service::proto::receipt_message::Type\">Type</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.i32.html\">i32</a>&gt; for <a class=\"enum\" href=\"libsignal_service/proto/sync_message/call_event/enum.Direction.html\" title=\"enum libsignal_service::proto::sync_message::call_event::Direction\">Direction</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.i32.html\">i32</a>&gt; for <a class=\"enum\" href=\"libsignal_service/proto/sync_message/call_event/enum.Event.html\" title=\"enum libsignal_service::proto::sync_message::call_event::Event\">Event</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.i32.html\">i32</a>&gt; for <a class=\"enum\" href=\"libsignal_service/proto/sync_message/call_event/enum.Type.html\" title=\"enum libsignal_service::proto::sync_message::call_event::Type\">Type</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.i32.html\">i32</a>&gt; for <a class=\"enum\" href=\"libsignal_service/proto/sync_message/call_link_update/enum.Type.html\" title=\"enum libsignal_service::proto::sync_message::call_link_update::Type\">Type</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.i32.html\">i32</a>&gt; for <a class=\"enum\" href=\"libsignal_service/proto/sync_message/call_log_event/enum.Type.html\" title=\"enum libsignal_service::proto::sync_message::call_log_event::Type\">Type</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.i32.html\">i32</a>&gt; for <a class=\"enum\" href=\"libsignal_service/proto/sync_message/fetch_latest/enum.Type.html\" title=\"enum libsignal_service::proto::sync_message::fetch_latest::Type\">Type</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.i32.html\">i32</a>&gt; for <a class=\"enum\" href=\"libsignal_service/proto/sync_message/message_request_response/enum.Type.html\" title=\"enum libsignal_service::proto::sync_message::message_request_response::Type\">Type</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.i32.html\">i32</a>&gt; for <a class=\"enum\" href=\"libsignal_service/proto/sync_message/request/enum.Type.html\" title=\"enum libsignal_service::proto::sync_message::request::Type\">Type</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.i32.html\">i32</a>&gt; for <a class=\"enum\" href=\"libsignal_service/proto/sync_message/sticker_pack_operation/enum.Type.html\" title=\"enum libsignal_service::proto::sync_message::sticker_pack_operation::Type\">Type</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.i32.html\">i32</a>&gt; for <a class=\"enum\" href=\"libsignal_service/proto/text_attachment/enum.Style.html\" title=\"enum libsignal_service::proto::text_attachment::Style\">Style</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.i32.html\">i32</a>&gt; for <a class=\"enum\" href=\"libsignal_service/proto/typing_message/enum.Action.html\" title=\"enum libsignal_service::proto::typing_message::Action\">Action</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.i32.html\">i32</a>&gt; for <a class=\"enum\" href=\"libsignal_service/proto/unidentified_sender_message/message/enum.ContentHint.html\" title=\"enum libsignal_service::proto::unidentified_sender_message::message::ContentHint\">ContentHint</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.i32.html\">i32</a>&gt; for <a class=\"enum\" href=\"libsignal_service/proto/unidentified_sender_message/message/enum.Type.html\" title=\"enum libsignal_service::proto::unidentified_sender_message::message::Type\">Type</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.i32.html\">i32</a>&gt; for <a class=\"enum\" href=\"libsignal_service/proto/verified/enum.State.html\" title=\"enum libsignal_service::proto::verified::State\">State</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.i32.html\">i32</a>&gt; for <a class=\"enum\" href=\"libsignal_service/proto/web_socket_message/enum.Type.html\" title=\"enum libsignal_service::proto::web_socket_message::Type\">Type</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"struct\" href=\"libsignal_service/proto/struct.AccessControl.html\" title=\"struct libsignal_service::proto::AccessControl\">AccessControl</a>&gt; for <a class=\"struct\" href=\"libsignal_service/groups_v2/struct.AccessControl.html\" title=\"struct libsignal_service::groups_v2::AccessControl\">AccessControl</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;KyberPreKeyRecord&gt; for <a class=\"struct\" href=\"libsignal_service/pre_keys/struct.KyberPreKeyEntity.html\" title=\"struct libsignal_service::pre_keys::KyberPreKeyEntity\">KyberPreKeyEntity</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;PreKeyRecord&gt; for <a class=\"struct\" href=\"libsignal_service/pre_keys/struct.PreKeyEntity.html\" title=\"struct libsignal_service::pre_keys::PreKeyEntity\">PreKeyEntity</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;SignedPreKeyRecord&gt; for <a class=\"struct\" href=\"libsignal_service/pre_keys/struct.SignedPreKeyEntity.html\" title=\"struct libsignal_service::pre_keys::SignedPreKeyEntity\">SignedPreKeyEntity</a>"]]],["presage",[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;&amp;<a class=\"struct\" href=\"libsignal_service/content/struct.Content.html\" title=\"struct libsignal_service::content::Content\">Content</a>&gt; for <a class=\"enum\" href=\"presage/store/enum.Thread.html\" title=\"enum presage::store::Thread\">Thread</a>"]]],["zkgroup",[["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.u64.html\">u64</a>&gt; for <a class=\"enum\" href=\"zkgroup/api/backups/enum.BackupLevel.html\" title=\"enum zkgroup::api::backups::BackupLevel\">BackupLevel</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.u8.html\">u8</a>&gt; for <a class=\"enum\" href=\"zkgroup/api/auth/auth_credential_with_pni/enum.AuthCredentialWithPniVersion.html\" title=\"enum zkgroup::api::auth::auth_credential_with_pni::AuthCredentialWithPniVersion\">AuthCredentialWithPniVersion</a>"],["impl <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.u8.html\">u8</a>&gt; for <a class=\"enum\" href=\"zkgroup/api/backups/enum.BackupLevel.html\" title=\"enum zkgroup::api::backups::BackupLevel\">BackupLevel</a>"],["impl&lt;const C: <a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.u8.html\">u8</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/1.84.0/core/convert/trait.TryFrom.html\" title=\"trait core::convert::TryFrom\">TryFrom</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/1.84.0/std/primitive.u8.html\">u8</a>&gt; for <a class=\"struct\" href=\"zkgroup/common/serialization/struct.VersionByte.html\" title=\"struct zkgroup::common::serialization::VersionByte\">VersionByte</a>&lt;C&gt;"]]]]);
    if (window.register_implementors) {
        window.register_implementors(implementors);
    } else {
        window.pending_implementors = implementors;
    }
})()
//{"start":57,"fragment_lengths":[7369,16864,430,1827]}