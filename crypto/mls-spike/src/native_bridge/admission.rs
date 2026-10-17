//! Independent state machines: no registry, shared participant object or filesystem.
//! Every successor remains a candidate until the caller atomically persists it.
use super::enrollment::{digest, provider, signature, validate_public};
use super::*;
use mls_rs::{storage_provider::in_memory::InMemoryKeyPackageStorage, MlsMessage};
use mls_rs_core::key_package::KeyPackageData;
const STATE_MAX: usize = 512 * 1024;
const OUTBOX_MAX: usize = 128 * 1024;
const MAX_NOW: u64 = 9_007_199_254_740_991;
const TTL: u64 = 300;
const PROBE: &[u8] =
    br#"{"v":1,"eventId":"independent-admission-probe","type":"availability.set"}"#;

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(tag = "op", rename_all_fields = "camelCase", deny_unknown_fields)]
enum Command {
    #[serde(rename = "admissioncreateadmin")]
    CreateAdmin { admin_public_key: String, now: u64 },
    #[serde(rename = "admissionpublishinvitation")]
    PublishInvitation {
        state: String,
        signature: String,
        now: u64,
    },
    #[serde(rename = "admissioncreatejoiner")]
    CreateJoiner {
        invitation: String,
        trusted_admin_public_key: String,
        device_public_key: String,
        now: u64,
    },
    #[serde(rename = "admissionpublishrequest")]
    PublishRequest {
        state: String,
        signature: String,
        now: u64,
    },
    #[serde(rename = "admissioninspectrequest")]
    InspectRequest {
        state: String,
        request: String,
        trusted_device_public_key: String,
        now: u64,
    },
    #[serde(rename = "admissionadmit")]
    Admit {
        state: String,
        request: String,
        trusted_device_public_key: String,
        approval_signature: String,
        now: u64,
    },
    #[serde(rename = "admissionjoin")]
    Join {
        state: String,
        welcome: String,
        now: u64,
    },
    #[serde(rename = "admissionresume")]
    Resume { state: String },
    #[serde(rename = "admissionreceive")]
    Receive { state: String, packet: String },
}
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Invitation {
    version: u32,
    invitation_id: String,
    group_id: String,
    admin_identity: String,
    admin_public_key: String,
    issued_at: u64,
    expires_at: u64,
    signature: String,
}
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    version: u32,
    request_id: String,
    invitation: String,
    key_package: String,
    joiner_identity: String,
    device_public_key: String,
    issued_at: u64,
    expires_at: u64,
    signature: String,
}
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Welcome {
    version: u32,
    request: String,
    approval_signature: String,
    welcome: String,
    probe: String,
}
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Package {
    id: String,
    data: String,
}
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct State {
    version: u32,
    role: String,
    phase: String,
    native_key: String,
    trusted_admin_key: String,
    trusted_device_key: String,
    invitation: String,
    request: String,
    approval_signature: String,
    own_identity: String,
    own_secret: String,
    snapshot: String,
    packages: Vec<Package>,
    outbox: String,
}
#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
struct DraftReply {
    state: String,
    transcript: String,
}
#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
struct Transition {
    state: String,
    outbox: String,
    kind: String,
}
#[derive(Serialize)]
struct ResumeReply<'a> {
    outbox: &'a str,
    kind: &'a str,
}
#[derive(Serialize)]
struct Transcript {
    transcript: String,
}
#[derive(Serialize, Zeroize, ZeroizeOnDrop)]
#[serde(rename_all = "camelCase")]
struct Received {
    state: String,
    plaintext: String,
    sender_index: u32,
}
fn pack<T: Serialize>(value: &T, max: usize) -> Result<String> {
    let bytes = Zeroizing::new(serde_json::to_vec(value).map_err(|_| BridgeRejected)?);
    if bytes.len() > max {
        return Err(BridgeRejected);
    }
    Ok(encode(&bytes))
}
fn unpack<T: for<'de> Deserialize<'de>>(value: &str, max: usize) -> Result<T> {
    serde_json::from_slice(&decode(value, max)?).map_err(|_| BridgeRejected)
}
fn state(value: &str) -> Result<State> {
    let state: State = unpack(value, STATE_MAX)?;
    if state.version != 1
        || !["admin", "joiner"].contains(&state.role.as_str())
        || state.packages.len() > 1
    {
        return Err(BridgeRejected);
    }
    if (state.role == "admin" && state.native_key != state.trusted_admin_key)
        || (state.role == "joiner" && state.native_key != state.trusted_device_key)
    {
        return Err(BridgeRejected);
    }
    validate_public(&state.native_key)?;
    validate_public(&state.trusted_admin_key)?;
    Ok(state)
}
fn require(state: &State, role: &str, phase: &str) -> Result<()> {
    if state.role != role || state.phase != phase {
        return Err(BridgeRejected);
    }
    Ok(())
}
fn clock(now: u64) -> Result<()> {
    if now > MAX_NOW {
        Err(BridgeRejected)
    } else {
        Ok(())
    }
}
fn window(issued: u64, expires: u64, now: u64) -> Result<()> {
    clock(now)?;
    if issued > now || now >= expires {
        return Err(BridgeRejected);
    }
    Ok(())
}
fn challenge(value: &str) -> Result<()> {
    let bytes = decode(value, 32)?;
    if bytes.len() != 32 || encode(&bytes) != value {
        return Err(BridgeRejected);
    }
    Ok(())
}
fn message(bytes: &[u8]) -> Result<MlsMessage> {
    let mut cursor = bytes;
    let message = MlsMessage::mls_decode(&mut cursor).map_err(|_| BridgeRejected)?;
    if !cursor.is_empty() {
        return Err(BridgeRejected);
    }
    Ok(message)
}
fn random() -> Result<String> {
    Ok(encode(
        provider()?
            .random_bytes_vec(32)
            .map_err(|_| BridgeRejected)?,
    ))
}
fn verify(key: &str, sig: &str, bytes: &[u8]) -> Result<()> {
    provider()?
        .verify(&validate_public(key)?, &signature(sig)?, bytes)
        .map_err(|_| BridgeRejected)
}
impl Invitation {
    fn transcript(&self) -> Result<String> {
        Ok(format!(
            "squadtime-mls-invitation-v1\n{}\n{}\n{}\n{}\n{}\n{}\n",
            self.invitation_id,
            self.group_id,
            digest(&decode(&self.admin_identity, 4096)?)?,
            self.admin_public_key,
            self.issued_at,
            self.expires_at
        ))
    }
    fn validate(&self, pin: &str, signed: bool) -> Result<()> {
        challenge(&self.invitation_id)?;
        let group = decode(&self.group_id, 256)?;
        if self.version != 1
            || group.is_empty()
            || self.admin_public_key != pin
            || self.issued_at.checked_add(TTL) != Some(self.expires_at)
            || self.expires_at > MAX_NOW
        {
            return Err(BridgeRejected);
        }
        identity(&self.admin_identity)?;
        validate_public(pin)?;
        if signed {
            verify(pin, &self.signature, self.transcript()?.as_bytes())?
        }
        Ok(())
    }
}
impl Request {
    fn transcript(&self, invite: &Invitation) -> Result<String> {
        Ok(format!(
            "squadtime-mls-admission-request-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
            self.request_id,
            digest(&decode(&self.invitation, OUTBOX_MAX)?)?,
            invite.group_id,
            digest(&decode(&self.key_package, 32 * 1024)?)?,
            digest(&decode(&self.joiner_identity, 4096)?)?,
            digest(&decode(&invite.admin_identity, 4096)?)?,
            self.device_public_key,
            invite.admin_public_key,
            self.issued_at,
            self.expires_at
        ))
    }
    fn approval(&self, invite: &Invitation) -> Result<String> {
        Ok(format!(
            "squadtime-mls-admission-approval-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
            self.request_id,
            digest(self.transcript(invite)?.as_bytes())?,
            digest(&decode(&self.invitation, OUTBOX_MAX)?)?,
            invite.group_id,
            digest(&decode(&invite.admin_identity, 4096)?)?,
            self.device_public_key,
            invite.admin_public_key,
            self.expires_at
        ))
    }
    fn validate(&self, invite: &Invitation, pin: &str, signed: bool) -> Result<()> {
        challenge(&self.request_id)?;
        if self.version != 1
            || self.device_public_key != pin
            || pin == invite.admin_public_key
            || self.issued_at < invite.issued_at
            || self.issued_at >= self.expires_at
            || self.expires_at != invite.expires_at
        {
            return Err(BridgeRejected);
        }
        validate_public(pin)?;
        identity(&self.joiner_identity)?;
        let package = decode(&self.key_package, 32 * 1024)?;
        let parsed = message(&package)?
            .into_key_package()
            .ok_or(BridgeRejected)?;
        if parsed.cipher_suite() != SUITE
            || parsed.version() != mls_rs::ProtocolVersion::MLS_10
            || parsed.signing_identity() != &identity(&self.joiner_identity)?
        {
            return Err(BridgeRejected);
        }
        if signed {
            verify(pin, &self.signature, self.transcript(invite)?.as_bytes())?
        }
        Ok(())
    }
}
fn saved_group(
    group: &mut Group<BridgeConfig>,
    store: &Store,
    own: &SigningIdentity,
    secret: &SignatureSecretKey,
    peer: Option<&SigningIdentity>,
) -> Result<String> {
    group.write_to_storage().map_err(|_| BridgeRejected)?;
    let mut saved = Snapshot {
        version: 1,
        group_id: encode(group.group_id()),
        own_identity: encode_identity(own)?,
        own_secret: encode(secret.as_bytes()),
        sender_identity: peer.map(encode_identity).transpose()?.unwrap_or_default(),
        state: String::new(),
        epochs: vec![],
        authorization: None,
    };
    export(&mut saved, store)
}
fn restore_group(
    state: &State,
    peer: Option<&SigningIdentity>,
) -> Result<(Group<BridgeConfig>, Store)> {
    let saved: Snapshot = unpack(&state.snapshot, MAX_SNAPSHOT_BYTES)?;
    let own = identity(&state.own_identity)?;
    let secret = SignatureSecretKey::new_slice(&decode(&state.own_secret, 128)?);
    let suite = AwsLcCryptoProvider::default()
        .cipher_suite_provider(SUITE)
        .ok_or(BridgeRejected)?;
    if saved.version != 1
        || saved.own_identity != state.own_identity
        || saved.own_secret != state.own_secret
        || suite
            .signature_key_derive_public(&secret)
            .map_err(|_| BridgeRejected)?
            != own.signature_key
        || saved.epochs.len() > 3
    {
        return Err(BridgeRejected);
    }
    let id = decode(&saved.group_id, 256)?;
    let mut data = Stored {
        state: Some(GroupState {
            id: id.to_vec(),
            data: decode(&saved.state, MAX_SNAPSHOT_BYTES)?,
        }),
        epochs: BTreeMap::new(),
    };
    for epoch in &saved.epochs {
        if data
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
    let store = Store(Arc::new(Mutex::new(data)));
    let mut pins = vec![own.clone()];
    if let Some(peer) = peer {
        pins.push(peer.clone())
    }
    let client = client(own.clone(), secret, Pins(pins), store.clone());
    let group = client.load_group(&id).map_err(|_| BridgeRejected)?;
    if group.cipher_suite() != SUITE
        || group
            .current_member_signing_identity()
            .map_err(|_| BridgeRejected)?
            != &own
        || group.group_id() != id.as_slice()
    {
        return Err(BridgeRejected);
    }
    Ok((group, store))
}
fn transition(state: &State) -> Result<Zeroizing<Vec<u8>>> {
    serialize(&Transition {
        state: pack(state, STATE_MAX)?,
        outbox: state.outbox.clone(),
        kind: state.phase.clone(),
    })
}
fn create_admin(key: &str, now: u64) -> Result<Zeroizing<Vec<u8>>> {
    if now > MAX_NOW - TTL {
        return Err(BridgeRejected);
    }
    validate_public(key)?;
    let (own, secret) = make_device(b"independent-admin/device-a")?;
    let store = Store::default();
    let client = client(
        own.clone(),
        secret.clone(),
        Pins(vec![own.clone()]),
        store.clone(),
    );
    let mut group = client
        .group_builder()
        .map_err(|_| BridgeRejected)?
        .build()
        .map_err(|_| BridgeRejected)?;
    let invitation = Invitation {
        version: 1,
        invitation_id: random()?,
        group_id: encode(group.group_id()),
        admin_identity: encode_identity(&own)?,
        admin_public_key: key.to_owned(),
        issued_at: now,
        expires_at: now + TTL,
        signature: String::new(),
    };
    let state = State {
        version: 1,
        role: "admin".into(),
        phase: "draft".into(),
        native_key: key.into(),
        trusted_admin_key: key.into(),
        trusted_device_key: String::new(),
        invitation: pack(&invitation, OUTBOX_MAX)?,
        request: String::new(),
        approval_signature: String::new(),
        own_identity: encode_identity(&own)?,
        own_secret: encode(secret.as_bytes()),
        snapshot: saved_group(&mut group, &store, &own, &secret, None)?,
        packages: vec![],
        outbox: String::new(),
    };
    serialize(&DraftReply {
        state: pack(&state, STATE_MAX)?,
        transcript: encode(invitation.transcript()?),
    })
}
fn publish_invitation(value: &str, sig: &str, now: u64) -> Result<Zeroizing<Vec<u8>>> {
    let mut state = state(value)?;
    require(&state, "admin", "draft")?;
    let mut invitation: Invitation = unpack(&state.invitation, OUTBOX_MAX)?;
    invitation.validate(&state.trusted_admin_key, false)?;
    window(invitation.issued_at, invitation.expires_at, now)?;
    verify(&state.native_key, sig, invitation.transcript()?.as_bytes())?;
    invitation.signature = sig.into();
    state.invitation = pack(&invitation, OUTBOX_MAX)?;
    state.outbox = state.invitation.clone();
    state.phase = "invitation".into();
    transition(&state)
}
fn create_joiner(
    invitation_wire: &str,
    pin: &str,
    key: &str,
    now: u64,
) -> Result<Zeroizing<Vec<u8>>> {
    let invitation: Invitation = unpack(invitation_wire, OUTBOX_MAX)?;
    invitation.validate(pin, true)?;
    window(invitation.issued_at, invitation.expires_at, now)?;
    validate_public(key)?;
    if key == pin {
        return Err(BridgeRejected);
    }
    let (own, secret) = make_device(b"independent-joiner/device-b")?;
    let admin = identity(&invitation.admin_identity)?;
    let packages = InMemoryKeyPackageStorage::new();
    let client: Client<BridgeConfig> = Client::builder()
        .identity_provider(Pins(vec![own.clone(), admin]))
        .group_state_storage(Store::default())
        .key_package_repo(packages.clone())
        .crypto_provider(AwsLcCryptoProvider::default())
        .signing_identity(own.clone(), secret.clone(), SUITE)
        .build();
    let package = client
        .generate_key_package_message(Default::default(), Default::default(), None)
        .map_err(|_| BridgeRejected)?;
    let request = Request {
        version: 1,
        request_id: random()?,
        invitation: invitation_wire.into(),
        key_package: encode(package.to_bytes().map_err(|_| BridgeRejected)?),
        joiner_identity: encode_identity(&own)?,
        device_public_key: key.into(),
        issued_at: now,
        expires_at: invitation.expires_at,
        signature: String::new(),
    };
    let saved = packages
        .key_packages()
        .into_iter()
        .map(|(id, data)| {
            Ok(Package {
                id: encode(id),
                data: encode(Zeroizing::new(
                    data.mls_encode_to_vec().map_err(|_| BridgeRejected)?,
                )),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let state = State {
        version: 1,
        role: "joiner".into(),
        phase: "draft".into(),
        native_key: key.into(),
        trusted_admin_key: pin.into(),
        trusted_device_key: key.into(),
        invitation: invitation_wire.into(),
        request: pack(&request, OUTBOX_MAX)?,
        approval_signature: String::new(),
        own_identity: encode_identity(&own)?,
        own_secret: encode(secret.as_bytes()),
        snapshot: String::new(),
        packages: saved,
        outbox: String::new(),
    };
    serialize(&DraftReply {
        state: pack(&state, STATE_MAX)?,
        transcript: encode(request.transcript(&invitation)?),
    })
}
fn publish_request(value: &str, sig: &str, now: u64) -> Result<Zeroizing<Vec<u8>>> {
    let mut state = state(value)?;
    require(&state, "joiner", "draft")?;
    let invitation: Invitation = unpack(&state.invitation, OUTBOX_MAX)?;
    invitation.validate(&state.trusted_admin_key, true)?;
    let mut request: Request = unpack(&state.request, OUTBOX_MAX)?;
    request.validate(&invitation, &state.native_key, false)?;
    window(request.issued_at, request.expires_at, now)?;
    verify(
        &state.native_key,
        sig,
        request.transcript(&invitation)?.as_bytes(),
    )?;
    request.signature = sig.into();
    state.request = pack(&request, OUTBOX_MAX)?;
    state.outbox = state.request.clone();
    state.phase = "request".into();
    transition(&state)
}
fn checked_request(
    state: &State,
    wire: &str,
    pin: &str,
    now: u64,
) -> Result<(Invitation, Request)> {
    require(state, "admin", "invitation")?;
    let request: Request = unpack(wire, OUTBOX_MAX)?;
    if request.invitation != state.invitation {
        return Err(BridgeRejected);
    }
    let invitation: Invitation = unpack(&state.invitation, OUTBOX_MAX)?;
    invitation.validate(&state.trusted_admin_key, true)?;
    if invitation.admin_identity != state.own_identity {
        return Err(BridgeRejected);
    }
    request.validate(&invitation, pin, true)?;
    window(request.issued_at, request.expires_at, now)?;
    Ok((invitation, request))
}
fn inspect(value: &str, wire: &str, pin: &str, now: u64) -> Result<Zeroizing<Vec<u8>>> {
    let state = state(value)?;
    let (invitation, request) = checked_request(&state, wire, pin, now)?;
    serialize(&Transcript {
        transcript: encode(request.approval(&invitation)?),
    })
}
fn admit(value: &str, wire: &str, pin: &str, sig: &str, now: u64) -> Result<Zeroizing<Vec<u8>>> {
    let mut state = state(value)?;
    let (invitation, request) = checked_request(&state, wire, pin, now)?;
    verify(
        &state.native_key,
        sig,
        request.approval(&invitation)?.as_bytes(),
    )?;
    let own = identity(&state.own_identity)?;
    let peer = identity(&request.joiner_identity)?;
    let (mut group, store) = restore_group(&state, Some(&peer))?;
    if group.roster().members().len() != 1 || encode(group.group_id()) != invitation.group_id {
        return Err(BridgeRejected);
    }
    let package = message(&decode(&request.key_package, 32 * 1024)?)?;
    let commit = group
        .commit_builder()
        .add_member(package)
        .map_err(|_| BridgeRejected)?
        .build()
        .map_err(|_| BridgeRejected)?;
    group.apply_pending_commit().map_err(|_| BridgeRejected)?;
    if group.roster().members().len() != 2 {
        return Err(BridgeRejected);
    }
    let probe = group
        .encrypt_application_message(PROBE, vec![])
        .map_err(|_| BridgeRejected)?;
    let welcome = Welcome {
        version: 1,
        request: wire.into(),
        approval_signature: sig.into(),
        welcome: encode(
            commit.welcome_messages[0]
                .to_bytes()
                .map_err(|_| BridgeRejected)?,
        ),
        probe: encode(probe.to_bytes().map_err(|_| BridgeRejected)?),
    };
    let secret = SignatureSecretKey::new_slice(&decode(&state.own_secret, 128)?);
    state.snapshot = saved_group(&mut group, &store, &own, &secret, Some(&peer))?;
    state.request = wire.into();
    state.approval_signature = sig.into();
    state.trusted_device_key = pin.into();
    state.outbox = pack(&welcome, OUTBOX_MAX)?;
    state.phase = "welcome".into();
    transition(&state)
}
fn join(value: &str, wire: &str, now: u64) -> Result<Zeroizing<Vec<u8>>> {
    clock(now)?;
    let mut state = state(value)?;
    require(&state, "joiner", "request")?;
    let welcome: Welcome = unpack(wire, OUTBOX_MAX)?;
    if welcome.version != 1 || welcome.request != state.request {
        return Err(BridgeRejected);
    }
    let invitation: Invitation = unpack(&state.invitation, OUTBOX_MAX)?;
    invitation.validate(&state.trusted_admin_key, true)?;
    let request: Request = unpack(&state.request, OUTBOX_MAX)?;
    if request.invitation != state.invitation
        || request.joiner_identity != state.own_identity
        || now < request.issued_at
    {
        return Err(BridgeRejected);
    }
    request.validate(&invitation, &state.native_key, true)?;
    verify(
        &state.trusted_admin_key,
        &welcome.approval_signature,
        request.approval(&invitation)?.as_bytes(),
    )?;
    let own = identity(&state.own_identity)?;
    let admin = identity(&invitation.admin_identity)?;
    let secret = SignatureSecretKey::new_slice(&decode(&state.own_secret, 128)?);
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
    let packages = InMemoryKeyPackageStorage::new();
    for package in &state.packages {
        let bytes = decode(&package.data, 64 * 1024)?;
        let mut cursor = bytes.as_slice();
        let data = KeyPackageData::mls_decode(&mut cursor).map_err(|_| BridgeRejected)?;
        if !cursor.is_empty() {
            return Err(BridgeRejected);
        }
        packages.insert(decode(&package.id, 128)?.to_vec(), data);
    }
    let store = Store::default();
    let client: Client<BridgeConfig> = Client::builder()
        .identity_provider(Pins(vec![own.clone(), admin.clone()]))
        .group_state_storage(store.clone())
        .key_package_repo(packages)
        .crypto_provider(AwsLcCryptoProvider::default())
        .signing_identity(own.clone(), secret.clone(), SUITE)
        .build();
    let packet = message(&decode(&welcome.welcome, 64 * 1024)?)?;
    let (mut group, info) = client
        .join_group(None, &packet, None)
        .map_err(|_| BridgeRejected)?;
    if encode(group.group_id()) != invitation.group_id
        || group
            .current_member_signing_identity()
            .map_err(|_| BridgeRejected)?
            != &own
        || group
            .member_at_index(info.sender)
            .ok_or(BridgeRejected)?
            .signing_identity
            != admin
        || group.roster().members().len() != 2
    {
        return Err(BridgeRejected);
    }
    state.snapshot = saved_group(&mut group, &store, &own, &secret, Some(&admin))?;
    state.approval_signature = welcome.approval_signature.clone();
    state.packages.clear();
    state.phase = "joined".into();
    state.outbox.clear();
    transition(&state)
}
fn terminal(state: &State) -> Result<()> {
    if !((state.role == "admin" && state.phase == "welcome")
        || (state.role == "joiner" && state.phase == "joined"))
    {
        return Err(BridgeRejected);
    }
    let invitation: Invitation = unpack(&state.invitation, OUTBOX_MAX)?;
    invitation.validate(&state.trusted_admin_key, true)?;
    let request: Request = unpack(&state.request, OUTBOX_MAX)?;
    if request.invitation != state.invitation {
        return Err(BridgeRejected);
    }
    request.validate(&invitation, &state.trusted_device_key, true)?;
    verify(
        &state.trusted_admin_key,
        &state.approval_signature,
        request.approval(&invitation)?.as_bytes(),
    )?;
    let snapshot: Snapshot = unpack(&state.snapshot, MAX_SNAPSHOT_BYTES)?;
    let (own, peer) = if state.role == "admin" {
        (&invitation.admin_identity, &request.joiner_identity)
    } else {
        (&request.joiner_identity, &invitation.admin_identity)
    };
    if snapshot.version != 1
        || snapshot.own_secret != state.own_secret
        || snapshot.group_id != invitation.group_id
        || &snapshot.own_identity != own
        || &snapshot.sender_identity != peer
        || &state.own_identity != own
    {
        return Err(BridgeRejected);
    }
    Ok(())
}
fn resume(value: &str) -> Result<Zeroizing<Vec<u8>>> {
    let state = state(value)?;
    match (state.role.as_str(), state.phase.as_str()) {
        ("admin", "invitation") => {
            let invite: Invitation = unpack(&state.invitation, OUTBOX_MAX)?;
            invite.validate(&state.trusted_admin_key, true)?;
            if state.outbox != state.invitation {
                return Err(BridgeRejected);
            }
        }
        ("joiner", "request") => {
            let invite: Invitation = unpack(&state.invitation, OUTBOX_MAX)?;
            invite.validate(&state.trusted_admin_key, true)?;
            let request: Request = unpack(&state.request, OUTBOX_MAX)?;
            request.validate(&invite, &state.native_key, true)?;
            if state.outbox != state.request {
                return Err(BridgeRejected);
            }
        }
        ("admin", "welcome") => {
            terminal(&state)?;
            let outbox: Welcome = unpack(&state.outbox, OUTBOX_MAX)?;
            if outbox.version != 1
                || outbox.request != state.request
                || outbox.approval_signature != state.approval_signature
            {
                return Err(BridgeRejected);
            }
        }
        ("joiner", "joined") => {
            terminal(&state)?;
            if !state.outbox.is_empty() {
                return Err(BridgeRejected);
            }
        }
        _ => return Err(BridgeRejected),
    }
    serialize(&ResumeReply {
        outbox: &state.outbox,
        kind: &state.phase,
    })
}
fn receive(value: &str, packet: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut state = state(value)?;
    terminal(&state)?;
    let result = super::receive(&state.snapshot, packet)?;
    #[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
    #[serde(rename_all = "camelCase")]
    struct Reply {
        snapshot: String,
        plaintext: String,
        sender_index: u32,
    }
    let reply: Reply = serde_json::from_slice(&result).map_err(|_| BridgeRejected)?;
    state.snapshot = reply.snapshot.clone();
    serialize(&Received {
        state: pack(&state, STATE_MAX)?,
        plaintext: reply.plaintext.clone(),
        sender_index: reply.sender_index,
    })
}
pub(super) fn dispatch(input: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let command: Command = serde_json::from_slice(input).map_err(|_| BridgeRejected)?;
    match &command {
        Command::CreateAdmin {
            admin_public_key,
            now,
        } => create_admin(admin_public_key, *now),
        Command::PublishInvitation {
            state,
            signature,
            now,
        } => publish_invitation(state, signature, *now),
        Command::CreateJoiner {
            invitation,
            trusted_admin_public_key,
            device_public_key,
            now,
        } => create_joiner(
            invitation,
            trusted_admin_public_key,
            device_public_key,
            *now,
        ),
        Command::PublishRequest {
            state,
            signature,
            now,
        } => publish_request(state, signature, *now),
        Command::InspectRequest {
            state,
            request,
            trusted_device_public_key,
            now,
        } => inspect(state, request, trusted_device_public_key, *now),
        Command::Admit {
            state,
            request,
            trusted_device_public_key,
            approval_signature,
            now,
        } => admit(
            state,
            request,
            trusted_device_public_key,
            approval_signature,
            *now,
        ),
        Command::Join {
            state,
            welcome,
            now,
        } => join(state, welcome, *now),
        Command::Resume { state } => resume(state),
        Command::Receive { state, packet } => receive(state, packet),
    }
}
