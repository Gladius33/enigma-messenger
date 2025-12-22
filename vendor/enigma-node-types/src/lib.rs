mod codec;
mod error;
mod identity;
mod node;
mod presence;
mod relay;
mod user_id;

pub use crate::codec::{from_json_str, to_json_string};
pub use crate::error::{EnigmaNodeTypesError, Result};
pub use crate::identity::{
    signed_payload, CheckUserResponse, EnvelopePubKey, PublicIdentity, RegisterRequest,
    RegisterResponse, ResolveRequest, ResolveResponse, SyncRequest, SyncResponse,
    MAX_IDENTITY_CIPHERTEXT,
};
pub use crate::node::{NodeInfo, NodesPayload};
pub use crate::presence::Presence;
pub use crate::relay::{
    OpaqueAttachmentChunk, OpaqueMessage, OpaqueSignaling, RelayAckRequest, RelayAckResponse,
    RelayEnvelope, RelayKind, RelayPullResponse, RelayPushRequest, RelayPushResponse,
};
pub use crate::user_id::{normalize_username, UserId};
pub use enigma_api::identity_envelope::{
    canonical_handle, compute_blind_index, BlindIndex, IdentityEnvelope, KeyId,
    RegistryEnvelopePublicKey,
};

#[cfg(test)]
mod tests;
