/// Whether to trust or reject new identities
#[derive(Debug, Clone)]
pub enum OnNewIdentity {
    Reject,
    Trust,
}
