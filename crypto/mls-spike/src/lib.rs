//! Evaluation-only MLS application receiver using supported state APIs.
//!
//! Requires a single writer, atomic GroupStateStorage writes, and side-effect-free
//! crypto/identity/rule providers while processing. This is not a durable inbox,
//! membership transaction system, or anti-rollback solution.
use mls_rs::{
    client_builder::MlsConfig,
    error::MlsError,
    group::{ApplicationMessageDescription, Group, ReceivedMessage},
    mls_rs_codec::MlsDecode,
    Client, MlsMessage,
};

const MAX_PACKET_BYTES: usize = 1_048_576;

/// Intentionally carries no packet, decrypted content, keys, or provider errors.
#[derive(Debug, PartialEq, Eq)]
pub enum ReceiveError {
    InvalidPacket,
    AuthenticationFailed,
    NotApplicationMessage,
    PolicyRejected,
    /// Storage may have committed: discard this receiver and reconcile/reopen.
    PersistenceUncertain,
    /// A previous persistence error made further use unsafe.
    Unavailable,
}

/// One sequential owner of one established group's application receive state.
///
/// Cloning temporarily duplicates current secrets. Never clone/persist checkpoints
/// as a general rollback mechanism. Do not access the same storage with another
/// writer. Successful state persistence precedes release of the plaintext; inbox
/// durability and app/state atomicity still require a real transactional backend.
pub struct ApplicationReceiver<C: MlsConfig> {
    group: Group<C>,
    unavailable: bool,
}

impl<C: MlsConfig> ApplicationReceiver<C> {
    /// Save an established group once (including join cleanup), then reload using
    /// public APIs. The client must be the group's actual configured client.
    pub fn initialize(client: &Client<C>, mut group: Group<C>) -> Result<Self, MlsError> {
        group.write_to_storage()?;
        Self::open(client, group.group_id())
    }

    /// Reopen the last trusted saved state. Caller must enforce single ownership
    /// and a fresh, rollback-protected store; this function cannot verify either.
    pub fn open(client: &Client<C>, group_id: &[u8]) -> Result<Self, MlsError> {
        Ok(Self {
            group: client.load_group(group_id)?,
            unavailable: false,
        })
    }

    /// Stage decode/authentication and pure application policy validation. Only
    /// an accepted application packet is saved and published. Non-application
    /// packets need a separate reviewed membership/control transaction path.
    ///
    /// The predicate must have no externally visible side effects. Returning false
    /// rejects without advancing state. Never log its plaintext argument.
    pub fn receive(
        &mut self,
        packet: &[u8],
        accept: impl FnOnce(&ApplicationMessageDescription) -> bool,
    ) -> Result<ApplicationMessageDescription, ReceiveError> {
        if self.unavailable {
            return Err(ReceiveError::Unavailable);
        }
        if packet.is_empty() || packet.len() > MAX_PACKET_BYTES {
            return Err(ReceiveError::InvalidPacket);
        }
        let mut cursor = packet;
        let message =
            MlsMessage::mls_decode(&mut cursor).map_err(|_| ReceiveError::InvalidPacket)?;
        if !cursor.is_empty() {
            return Err(ReceiveError::InvalidPacket);
        }
        let mut candidate = self.group.clone();
        let event = match candidate
            .process_incoming_message(message)
            .map_err(|_| ReceiveError::AuthenticationFailed)?
        {
            ReceivedMessage::ApplicationMessage(event) => event,
            _ => return Err(ReceiveError::NotApplicationMessage),
        };
        if !accept(&event) {
            return Err(ReceiveError::PolicyRejected);
        }
        // Generic storage errors can mean before-write, partial-write or after-
        // commit failure. Never retry from the stale in-memory state after one.
        self.unavailable = true;
        candidate
            .write_to_storage()
            .map_err(|_| ReceiveError::PersistenceUncertain)?;
        self.group = candidate;
        self.unavailable = false;
        Ok(event)
    }
}

/// Stateless native snapshot bridge for the synthetic development proof.
pub mod native_bridge;
