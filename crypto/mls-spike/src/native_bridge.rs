//! Secret snapshots are caller-owned LOCAL state, never network envelopes.
//! No persistence occurs: native code atomically commits snapshot + inbox.
use crate::ApplicationReceiver;
use base64ct::{Base64, Encoding};
use mls_rs::{
    client_builder::{BaseConfig, WithCryptoProvider, WithGroupStateStorage, WithIdentityProvider},
    group::Group,
    identity::{basic::BasicCredential, CredentialType, SigningIdentity},
    mls_rs_codec::{MlsDecode, MlsEncode},
    time::MlsTime,
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, ExtensionList, GroupStateStorage,
    IdentityProvider,
};
use mls_rs_core::{
    crypto::SignatureSecretKey,
    error::IntoAnyError,
    group::{EpochRecord, GroupState},
    identity::MemberValidationContext,
};
use mls_rs_crypto_awslc::AwsLcCryptoProvider;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    ptr,
    sync::{Arc, Mutex},
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const MAX_CALL_BYTES: usize = 16 * 1024 * 1024;
const MAX_SNAPSHOT_BYTES: usize = 8 * 1024 * 1024;
const MAX_PACKET_BYTES: usize = 1024 * 1024;
mod enrollment;

type BridgeConfig = WithCryptoProvider<
    AwsLcCryptoProvider,
    WithIdentityProvider<Pins, WithGroupStateStorage<Store, BaseConfig>>,
>;

const SUITE: CipherSuite = CipherSuite::CURVE25519_AES128;

#[derive(Debug)]
pub struct BridgeRejected;
impl IntoAnyError for BridgeRejected {}
type Result<T> = std::result::Result<T, BridgeRejected>;

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(tag = "op", rename_all = "lowercase", deny_unknown_fields)]
enum Command {
    Fixture {},
    Enrollmentprepare {
        #[serde(rename = "devicePublicKey")]
        device_public_key: String,
        #[serde(rename = "approverPublicKey")]
        approver_public_key: String,
        now: u64,
    },
    Enrollmentcomplete {
        #[serde(rename = "pendingId")]
        pending_id: String,
        #[serde(rename = "groupId")]
        group_id: String,
        #[serde(rename = "keyPackage")]
        key_package: String,
        #[serde(rename = "requestSignature")]
        request_signature: String,
        #[serde(rename = "approvalSignature")]
        approval_signature: String,
        now: u64,
    },
    Enrollmentcancel {
        #[serde(rename = "pendingId")]
        pending_id: String,
    },
    Receive {
        snapshot: String,
        packet: String,
    },
}
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct SavedEpoch {
    id: u64,
    data: String,
}
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    version: u32,
    group_id: String,
    own_identity: String,
    own_secret: String,
    sender_identity: String,
    state: String,
    epochs: Vec<SavedEpoch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authorization: Option<enrollment::Binding>,
}
#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
struct FixtureReply {
    snapshot: String,
    packets: Vec<String>,
    expected: Vec<String>,
}
#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
struct ReceiveReply {
    snapshot: String,
    plaintext: String,
    sender_index: u32,
}

#[derive(Clone)]
struct Pins(Vec<SigningIdentity>);
impl Pins {
    fn check(&self, id: &SigningIdentity) -> Result<()> {
        if self.0.contains(id) {
            Ok(())
        } else {
            Err(BridgeRejected)
        }
    }
}
impl IdentityProvider for Pins {
    type Error = BridgeRejected;
    fn validate_member(
        &self,
        id: &SigningIdentity,
        _: Option<MlsTime>,
        _: MemberValidationContext<'_>,
    ) -> Result<()> {
        self.check(id)
    }
    fn validate_external_sender(
        &self,
        _: &SigningIdentity,
        _: Option<MlsTime>,
        _: Option<&ExtensionList>,
    ) -> Result<()> {
        Err(BridgeRejected)
    }
    fn identity(&self, id: &SigningIdentity, _: &ExtensionList) -> Result<Vec<u8>> {
        self.check(id)?;
        Ok(id
            .credential
            .as_basic()
            .ok_or(BridgeRejected)?
            .identifier
            .to_vec())
    }
    fn valid_successor(
        &self,
        old: &SigningIdentity,
        new: &SigningIdentity,
        _: &ExtensionList,
    ) -> Result<bool> {
        self.check(old)?;
        self.check(new)?;
        Ok(old == new)
    }
    fn supported_types(&self) -> Vec<CredentialType> {
        vec![CredentialType::BASIC]
    }
}
#[derive(Clone, Default)]
struct Stored {
    state: Option<GroupState>,
    epochs: BTreeMap<u64, EpochRecord>,
}
#[derive(Clone, Default)]
struct Store(Arc<Mutex<Stored>>);
impl GroupStateStorage for Store {
    type Error = BridgeRejected;
    fn state(&self, id: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let stored = self.0.lock().map_err(|_| BridgeRejected)?;
        Ok(stored
            .state
            .as_ref()
            .filter(|s| s.id == id)
            .map(|s| s.data.clone()))
    }
    fn epoch(&self, id: &[u8], epoch: u64) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let stored = self.0.lock().map_err(|_| BridgeRejected)?;
        if stored.state.as_ref().is_none_or(|s| s.id != id) {
            return Ok(None);
        }
        Ok(stored.epochs.get(&epoch).map(|e| e.data.clone()))
    }
    fn max_epoch_id(&self, id: &[u8]) -> Result<Option<u64>> {
        let stored = self.0.lock().map_err(|_| BridgeRejected)?;
        if stored.state.as_ref().is_none_or(|s| s.id != id) {
            return Ok(None);
        }
        Ok(stored.epochs.keys().next_back().copied())
    }
    fn write(
        &mut self,
        state: GroupState,
        inserts: Vec<EpochRecord>,
        updates: Vec<EpochRecord>,
    ) -> Result<()> {
        let mut stored = self.0.lock().map_err(|_| BridgeRejected)?;
        if stored.state.as_ref().is_some_and(|s| s.id != state.id) {
            return Err(BridgeRejected);
        }
        stored.state = Some(state);
        for epoch in inserts.into_iter().chain(updates) {
            stored.epochs.insert(epoch.id, epoch);
        }
        // Match the upstream default bound; never archive every past epoch.
        while stored.epochs.len() > 3 {
            stored.epochs.pop_first();
        }
        Ok(())
    }
}
fn encode(bytes: impl AsRef<[u8]>) -> String {
    Base64::encode_string(bytes.as_ref())
}
fn decode(input: &str, max: usize) -> Result<Zeroizing<Vec<u8>>> {
    if input.len() > max.div_ceil(3) * 4 {
        return Err(BridgeRejected);
    }
    let bytes = Zeroizing::new(Base64::decode_vec(input).map_err(|_| BridgeRejected)?);
    if bytes.len() > max {
        return Err(BridgeRejected);
    }
    Ok(bytes)
}
fn identity(input: &str) -> Result<SigningIdentity> {
    let bytes = decode(input, 4096)?;
    let mut cursor = bytes.as_slice();
    let id = SigningIdentity::mls_decode(&mut cursor).map_err(|_| BridgeRejected)?;
    if !cursor.is_empty() {
        return Err(BridgeRejected);
    }
    Ok(id)
}
fn encode_identity(id: &SigningIdentity) -> Result<String> {
    Ok(encode(id.mls_encode_to_vec().map_err(|_| BridgeRejected)?))
}
fn make_device(name: &[u8]) -> Result<(SigningIdentity, SignatureSecretKey)> {
    let crypto = AwsLcCryptoProvider::default();
    let suite = crypto.cipher_suite_provider(SUITE).ok_or(BridgeRejected)?;
    let (secret, public) = suite.signature_key_generate().map_err(|_| BridgeRejected)?;
    Ok((
        SigningIdentity::new(
            BasicCredential::new(name.to_vec()).into_credential(),
            public,
        ),
        secret,
    ))
}
fn client(
    id: SigningIdentity,
    secret: SignatureSecretKey,
    pins: Pins,
    store: Store,
) -> Client<BridgeConfig> {
    Client::builder()
        .identity_provider(pins)
        .group_state_storage(store)
        .crypto_provider(AwsLcCryptoProvider::default())
        .signing_identity(id, secret, SUITE)
        .build()
}
fn export(snapshot: &mut Snapshot, store: &Store) -> Result<String> {
    let stored = store.0.lock().map_err(|_| BridgeRejected)?;
    let state = stored.state.as_ref().ok_or(BridgeRejected)?;
    snapshot.state.zeroize();
    snapshot.state = encode(&state.data);
    snapshot.epochs.clear();
    for epoch in stored.epochs.values() {
        snapshot.epochs.push(SavedEpoch {
            id: epoch.id,
            data: encode(&epoch.data),
        });
    }
    let bytes = Zeroizing::new(serde_json::to_vec(snapshot).map_err(|_| BridgeRejected)?);
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err(BridgeRejected);
    }
    Ok(encode(&bytes))
}
fn fixture() -> Result<Zeroizing<Vec<u8>>> {
    let (alice_id, alice_secret) = make_device(b"synthetic-alice/device-a")?;
    let (bob_id, bob_secret) = make_device(b"synthetic-bob/device-b")?;
    let pins = Pins(vec![alice_id.clone(), bob_id.clone()]);
    let alice = client(
        alice_id.clone(),
        alice_secret,
        pins.clone(),
        Store::default(),
    );
    let store = Store::default();
    let bob = client(bob_id.clone(), bob_secret.clone(), pins, store.clone());
    let mut sender = alice
        .group_builder()
        .map_err(|_| BridgeRejected)?
        .build()
        .map_err(|_| BridgeRejected)?;
    let package = bob
        .generate_key_package_message(Default::default(), Default::default(), None)
        .map_err(|_| BridgeRejected)?;
    let commit = sender
        .commit_builder()
        .add_member(package)
        .map_err(|_| BridgeRejected)?
        .build()
        .map_err(|_| BridgeRejected)?;
    sender.apply_pending_commit().map_err(|_| BridgeRejected)?;
    let (receiver, _) = bob
        .join_group(None, &commit.welcome_messages[0], None)
        .map_err(|_| BridgeRejected)?;
    finish_fixture(sender, receiver, alice_id, bob_id, bob_secret, store, None)
}
fn finish_fixture(
    mut sender: Group<BridgeConfig>,
    mut receiver: Group<BridgeConfig>,
    alice_id: SigningIdentity,
    bob_id: SigningIdentity,
    bob_secret: SignatureSecretKey,
    store: Store,
    authorization: Option<enrollment::Binding>,
) -> Result<Zeroizing<Vec<u8>>> {
    receiver.write_to_storage().map_err(|_| BridgeRejected)?;
    let mut snapshot = Snapshot {
        version: 1,
        group_id: encode(receiver.group_id()),
        own_identity: encode_identity(&bob_id)?,
        own_secret: encode(bob_secret.as_bytes()),
        sender_identity: encode_identity(&alice_id)?,
        state: String::new(),
        epochs: vec![],
        authorization,
    };
    let mut reply = FixtureReply {
        snapshot: String::new(),
        packets: vec![],
        expected: vec![],
    };
    for event in [
        br#"{"v":1,"eventId":"native-synthetic-1","type":"availability.set"}"#.as_slice(),
        br#"{"v":1,"eventId":"native-synthetic-2","type":"session.accept"}"#.as_slice(),
    ] {
        let message = sender
            .encrypt_application_message(event, vec![])
            .map_err(|_| BridgeRejected)?;
        reply
            .packets
            .push(encode(message.to_bytes().map_err(|_| BridgeRejected)?));
        reply.expected.push(encode(event));
        if reply.packets.len() == 1 {
            // Preserve a real delayed prior-epoch packet in the fixture. No app
            // packet is consumed; snapshot includes both current and prior state.
            let update = sender
                .commit_builder()
                .build()
                .map_err(|_| BridgeRejected)?;
            sender.apply_pending_commit().map_err(|_| BridgeRejected)?;
            receiver
                .process_incoming_message(update.commit_message)
                .map_err(|_| BridgeRejected)?;
            receiver.write_to_storage().map_err(|_| BridgeRejected)?;
        }
    }
    reply.snapshot = export(&mut snapshot, &store)?;
    serialize(&reply)
}
fn receive(snapshot: &str, packet: &str) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = decode(snapshot, MAX_SNAPSHOT_BYTES)?;
    let mut snapshot: Snapshot = serde_json::from_slice(&bytes).map_err(|_| BridgeRejected)?;
    if snapshot.version != 1 || snapshot.epochs.len() > 3 {
        return Err(BridgeRejected);
    }
    let own = identity(&snapshot.own_identity)?;
    let sender = identity(&snapshot.sender_identity)?;
    if let Some(binding) = &snapshot.authorization {
        enrollment::verify_snapshot(binding, &snapshot.group_id, &own, &sender)?;
    }
    if own == sender {
        return Err(BridgeRejected);
    }
    let secret = SignatureSecretKey::new_slice(&decode(&snapshot.own_secret, 128)?);
    let suite = AwsLcCryptoProvider::default()
        .cipher_suite_provider(SUITE)
        .ok_or(BridgeRejected)?;
    if suite
        .signature_key_derive_public(&secret)
        .map_err(|_| BridgeRejected)?
        != own.signature_key
    {
        return Err(BridgeRejected);
    }
    let group_id = decode(&snapshot.group_id, 256)?;
    let mut stored = Stored {
        state: Some(GroupState {
            id: group_id.to_vec(),
            data: decode(&snapshot.state, MAX_SNAPSHOT_BYTES)?,
        }),
        epochs: BTreeMap::new(),
    };
    for epoch in &snapshot.epochs {
        if stored
            .epochs
            .insert(
                epoch.id,
                EpochRecord::new(epoch.id, decode(&epoch.data, MAX_SNAPSHOT_BYTES)?),
            )
            .is_some()
        {
            return Err(BridgeRejected);
        }
    }
    let store = Store(Arc::new(Mutex::new(stored)));
    let client = client(
        own.clone(),
        secret,
        Pins(vec![own.clone(), sender.clone()]),
        store.clone(),
    );
    let group = client.load_group(&group_id).map_err(|_| BridgeRejected)?;
    if group.group_id() != group_id.as_slice()
        || group.cipher_suite() != SUITE
        || group
            .current_member_signing_identity()
            .map_err(|_| BridgeRejected)?
            != &own
        || group.roster().members().len() != 2
    {
        return Err(BridgeRejected);
    }
    let sender_member = group
        .roster()
        .members()
        .into_iter()
        .find(|m| m.signing_identity == sender)
        .ok_or(BridgeRejected)?;
    let sender_index = sender_member.index;
    drop(group);
    let mut receiver = ApplicationReceiver::open(&client, &group_id).map_err(|_| BridgeRejected)?;
    let packet = decode(packet, MAX_PACKET_BYTES)?;
    let event = receiver
        .receive(&packet, |event| event.sender_index == sender_index)
        .map_err(|_| BridgeRejected)?;
    let reply = ReceiveReply {
        snapshot: export(&mut snapshot, &store)?,
        plaintext: encode(event.data()),
        sender_index: event.sender_index,
    };
    serialize(&reply)
}
fn serialize(value: &impl Serialize) -> Result<Zeroizing<Vec<u8>>> {
    let output = Zeroizing::new(serde_json::to_vec(value).map_err(|_| BridgeRejected)?);
    if output.len() > MAX_CALL_BYTES {
        return Err(BridgeRejected);
    }
    Ok(output)
}
/// In-memory API. Input/output contain secret state and must never be logged.
pub fn call(input: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if input.is_empty() || input.len() > MAX_CALL_BYTES {
        return Err(BridgeRejected);
    }
    let command: Command = serde_json::from_slice(input).map_err(|_| BridgeRejected)?;
    match &command {
        Command::Fixture {} => fixture(),
        Command::Receive { snapshot, packet } => receive(snapshot, packet),
        Command::Enrollmentprepare {
            device_public_key,
            approver_public_key,
            now,
        } => enrollment::prepare(device_public_key, approver_public_key, *now),
        Command::Enrollmentcomplete {
            pending_id,
            group_id,
            key_package,
            request_signature,
            approval_signature,
            now,
        } => enrollment::complete(
            pending_id,
            group_id,
            key_package,
            request_signature,
            approval_signature,
            *now,
        ),
        Command::Enrollmentcancel { pending_id } => enrollment::cancel(pending_id),
    }
}

/// C ABI for local native callers. No detailed error crosses this boundary.
///
/// # Safety
/// Input must be valid/readable for input_len, and output pointers must be valid,
/// writable, aligned, nonoverlapping and not alias input. See the C header.
#[no_mangle]
pub unsafe extern "C" fn squadtime_mls_call(
    input: *const u8,
    input_len: usize,
    output: *mut *mut u8,
    output_len: *mut usize,
) -> i32 {
    if output.is_null() || output_len.is_null() {
        return 2;
    }
    unsafe {
        *output = ptr::null_mut();
        *output_len = 0;
    }
    if input.is_null() || input_len == 0 || input_len > MAX_CALL_BYTES {
        return 2;
    }
    let input = unsafe { std::slice::from_raw_parts(input, input_len) };
    match std::panic::catch_unwind(|| call(input)) {
        Ok(Ok(mut bytes)) => {
            let allocation = std::mem::take(&mut *bytes).into_boxed_slice();
            let len = allocation.len();
            let raw = Box::into_raw(allocation).cast::<u8>();
            unsafe {
                *output = raw;
                *output_len = len;
            }
            0
        }
        _ => 1,
    }
}
/// Zeroize and free exactly one output allocation.
///
/// # Safety
/// Pointer/length must be exactly a live allocation returned by squadtime_mls_call,
/// used once with no concurrent access. NULL/0 is a no-op.
#[no_mangle]
pub unsafe extern "C" fn squadtime_mls_free(output: *mut u8, output_len: usize) {
    if output.is_null() {
        return;
    }
    let mut allocation =
        unsafe { Box::from_raw(ptr::slice_from_raw_parts_mut(output, output_len)) };
    allocation.zeroize();
}
