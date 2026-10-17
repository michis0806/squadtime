//! A LOCAL single-process enrollment binding proof, not network onboarding.
use super::*;
use mls_rs::{storage_provider::in_memory::InMemoryKeyPackageStorage, MlsMessage};
use mls_rs_core::{
    crypto::{HpkePublicKey, SignaturePublicKey},
    key_package::KeyPackageData,
};
use std::sync::OnceLock;
const MAX_NOW: u64 = 9_007_199_254_740_991;
const TTL: u64 = 300;
const MAX_PENDING: usize = 16;

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub(super) struct Binding {
    pending_id: String,
    group_id: String,
    key_package_digest: String,
    joiner_identity_digest: String,
    admin_identity_digest: String,
    device_public_key: String,
    approver_public_key: String,
    issued_at: u64,
    expires_at: u64,
    request_signature: String,
    approval_signature: String,
}
impl Binding {
    fn request(&self) -> String {
        format!(
            "squadtime-mls-device-request-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
            self.pending_id,
            self.group_id,
            self.key_package_digest,
            self.joiner_identity_digest,
            self.admin_identity_digest,
            self.device_public_key,
            self.approver_public_key,
            self.issued_at,
            self.expires_at
        )
    }
    fn approval(&self) -> Result<String> {
        Ok(format!(
            "squadtime-mls-device-approval-v1\n{}\n{}\n{}\n",
            self.pending_id,
            digest(self.request().as_bytes())?,
            self.approver_public_key
        ))
    }
}
struct Pending {
    binding: Binding,
    admin_group: Group<BridgeConfig>,
    admin_id: SigningIdentity,
    joiner_id: SigningIdentity,
    joiner_secret: SignatureSecretKey,
    packages: Vec<(Vec<u8>, KeyPackageData)>,
    package: MlsMessage,
}
fn pending() -> &'static Mutex<BTreeMap<String, Pending>> {
    static PENDING: OnceLock<Mutex<BTreeMap<String, Pending>>> = OnceLock::new();
    PENDING.get_or_init(|| Mutex::new(BTreeMap::new()))
}
fn provider() -> Result<<AwsLcCryptoProvider as CryptoProvider>::CipherSuiteProvider> {
    AwsLcCryptoProvider::default()
        .cipher_suite_provider(CipherSuite::P256_AES128)
        .ok_or(BridgeRejected)
}
fn digest(bytes: &[u8]) -> Result<String> {
    let hashed = provider()?.hash(bytes).map_err(|_| BridgeRejected)?;
    Ok(hashed.iter().map(|byte| format!("{byte:02x}")).collect())
}
fn validate_public(key: &str) -> Result<SignaturePublicKey> {
    let bytes = decode(key, 65)?;
    if bytes.len() != 65 || bytes[0] != 4 || encode(&bytes) != key {
        return Err(BridgeRejected);
    }
    provider()?
        .kem_public_key_validate(&HpkePublicKey::from(bytes.to_vec()))
        .map_err(|_| BridgeRejected)?;
    Ok(SignaturePublicKey::from(bytes.to_vec()))
}
// Strict ASN.1 DER framing for two P-256 positive INTEGER scalars. AWS-LC
// still performs the actual ECDSA verification. High-S is intentionally allowed.
fn signature(value: &str) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = decode(value, 72)?;
    if bytes.len() < 8 || bytes[0] != 0x30 || bytes[1] as usize != bytes.len() - 2 {
        return Err(BridgeRejected);
    }
    const ORDER: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc,
        0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
    ];
    let mut cursor = 2;
    for _ in 0..2 {
        if cursor + 2 > bytes.len() || bytes[cursor] != 2 {
            return Err(BridgeRejected);
        }
        let count = bytes[cursor + 1] as usize;
        cursor += 2;
        if count == 0 || count > 33 || cursor + count > bytes.len() {
            return Err(BridgeRejected);
        }
        let integer = &bytes[cursor..cursor + count];
        if integer[0] & 0x80 != 0 || (count > 1 && integer[0] == 0 && integer[1] & 0x80 == 0) {
            return Err(BridgeRejected);
        }
        let scalar = if integer[0] == 0 {
            &integer[1..]
        } else {
            integer
        };
        if scalar.len() > 32
            || scalar.iter().all(|byte| *byte == 0)
            || (scalar.len() == 32 && scalar >= ORDER.as_slice())
        {
            return Err(BridgeRejected);
        }
        cursor += count;
    }
    if cursor != bytes.len() {
        return Err(BridgeRejected);
    }
    Ok(bytes)
}
fn verify(binding: &Binding) -> Result<()> {
    let device = validate_public(&binding.device_public_key)?;
    let approver = validate_public(&binding.approver_public_key)?;
    if device == approver
        || binding.expires_at > MAX_NOW
        || binding.issued_at.checked_add(TTL) != Some(binding.expires_at)
    {
        return Err(BridgeRejected);
    }
    provider()?
        .verify(
            &device,
            &signature(&binding.request_signature)?,
            binding.request().as_bytes(),
        )
        .map_err(|_| BridgeRejected)?;
    provider()?
        .verify(
            &approver,
            &signature(&binding.approval_signature)?,
            binding.approval()?.as_bytes(),
        )
        .map_err(|_| BridgeRejected)?;
    Ok(())
}
pub(super) fn verify_snapshot(
    binding: &Binding,
    group: &str,
    own: &SigningIdentity,
    sender: &SigningIdentity,
) -> Result<()> {
    if binding.group_id != group
        || binding.joiner_identity_digest
            != digest(&own.mls_encode_to_vec().map_err(|_| BridgeRejected)?)?
        || binding.admin_identity_digest
            != digest(&sender.mls_encode_to_vec().map_err(|_| BridgeRejected)?)?
    {
        return Err(BridgeRejected);
    }
    verify(binding)
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PreparedReply {
    pending_id: String,
    group_id: String,
    key_package: String,
    request: String,
    approval: String,
}
pub(super) fn prepare(device: &str, approver: &str, now: u64) -> Result<Zeroizing<Vec<u8>>> {
    if now > MAX_NOW - TTL {
        return Err(BridgeRejected);
    }
    validate_public(device)?;
    validate_public(approver)?;
    if device == approver {
        return Err(BridgeRejected);
    }
    let mut records = pending().lock().map_err(|_| BridgeRejected)?;
    records.retain(|_, pending| pending.binding.expires_at > now);
    if records.len() >= MAX_PENDING {
        return Err(BridgeRejected);
    }
    let (admin_id, admin_secret) = make_device(b"synthetic-approved-admin/device-a")?;
    let (joiner_id, joiner_secret) = make_device(b"synthetic-approved-joiner/device-b")?;
    let pins = Pins(vec![admin_id.clone(), joiner_id.clone()]);
    let admin = client(
        admin_id.clone(),
        admin_secret,
        pins.clone(),
        Store::default(),
    );
    let admin_group = admin
        .group_builder()
        .map_err(|_| BridgeRejected)?
        .build()
        .map_err(|_| BridgeRejected)?;
    let package_store = InMemoryKeyPackageStorage::new();
    let joiner: Client<BridgeConfig> = Client::builder()
        .identity_provider(pins)
        .group_state_storage(Store::default())
        .key_package_repo(package_store.clone())
        .crypto_provider(AwsLcCryptoProvider::default())
        .signing_identity(joiner_id.clone(), joiner_secret.clone(), SUITE)
        .build();
    let package = joiner
        .generate_key_package_message(Default::default(), Default::default(), None)
        .map_err(|_| BridgeRejected)?;
    let package_bytes = package.to_bytes().map_err(|_| BridgeRejected)?;
    let id = encode(
        provider()?
            .random_bytes_vec(32)
            .map_err(|_| BridgeRejected)?,
    );
    if records.contains_key(&id) {
        return Err(BridgeRejected);
    }
    let binding = Binding {
        pending_id: id.clone(),
        group_id: encode(admin_group.group_id()),
        key_package_digest: digest(&package_bytes)?,
        joiner_identity_digest: digest(
            &joiner_id.mls_encode_to_vec().map_err(|_| BridgeRejected)?,
        )?,
        admin_identity_digest: digest(&admin_id.mls_encode_to_vec().map_err(|_| BridgeRejected)?)?,
        device_public_key: device.to_string(),
        approver_public_key: approver.to_string(),
        issued_at: now,
        expires_at: now + TTL,
        request_signature: String::new(),
        approval_signature: String::new(),
    };
    let reply = PreparedReply {
        pending_id: id.clone(),
        group_id: binding.group_id.clone(),
        key_package: encode(package_bytes),
        request: encode(binding.request()),
        approval: encode(binding.approval()?),
    };
    let serialized = serialize(&reply)?;
    records.insert(
        id,
        Pending {
            binding,
            admin_group,
            admin_id,
            joiner_id,
            joiner_secret,
            packages: package_store.key_packages(),
            package,
        },
    );
    Ok(serialized)
}
pub(super) fn complete(
    id: &str,
    group: &str,
    package: &str,
    request_signature: &str,
    approval_signature: &str,
    now: u64,
) -> Result<Zeroizing<Vec<u8>>> {
    if now > MAX_NOW {
        return Err(BridgeRejected);
    }
    let mut records = pending().lock().map_err(|_| BridgeRejected)?;
    records.retain(|_, pending| pending.binding.expires_at > now);
    let prepared = records.get(id).ok_or(BridgeRejected)?;
    if now < prepared.binding.issued_at
        || group != prepared.binding.group_id
        || decode(package, MAX_PACKET_BYTES)?.as_slice()
            != prepared.package.to_bytes().map_err(|_| BridgeRejected)?
    {
        return Err(BridgeRejected);
    }
    let mut binding = prepared.binding.clone();
    binding.request_signature = request_signature.to_string();
    binding.approval_signature = approval_signature.to_string();
    verify(&binding)?;
    // Everything mutable is staged independently. The native signatures are
    // checked BEFORE the actual MLS Add, not converted into a caller boolean.
    let mut admin_group = prepared.admin_group.clone();
    let commit = admin_group
        .commit_builder()
        .add_member(prepared.package.clone())
        .map_err(|_| BridgeRejected)?
        .build()
        .map_err(|_| BridgeRejected)?;
    admin_group
        .apply_pending_commit()
        .map_err(|_| BridgeRejected)?;
    let package_store = InMemoryKeyPackageStorage::new();
    for (id, package) in &prepared.packages {
        package_store.insert(id.clone(), package.clone());
    }
    let store = Store::default();
    let joiner: Client<BridgeConfig> = Client::builder()
        .identity_provider(Pins(vec![
            prepared.admin_id.clone(),
            prepared.joiner_id.clone(),
        ]))
        .group_state_storage(store.clone())
        .key_package_repo(package_store)
        .crypto_provider(AwsLcCryptoProvider::default())
        .signing_identity(
            prepared.joiner_id.clone(),
            prepared.joiner_secret.clone(),
            SUITE,
        )
        .build();
    let (receiver, info) = joiner
        .join_group(None, &commit.welcome_messages[0], None)
        .map_err(|_| BridgeRejected)?;
    if receiver.group_id() != prepared.admin_group.group_id()
        || receiver.roster().members().len() != 2
        || receiver
            .current_member_signing_identity()
            .map_err(|_| BridgeRejected)?
            != &prepared.joiner_id
        || receiver
            .member_at_index(info.sender)
            .ok_or(BridgeRejected)?
            .signing_identity
            != prepared.admin_id
    {
        return Err(BridgeRejected);
    }
    let result = finish_fixture(
        admin_group,
        receiver,
        prepared.admin_id.clone(),
        prepared.joiner_id.clone(),
        prepared.joiner_secret.clone(),
        store,
        Some(binding),
    )?;
    records.remove(id);
    Ok(result)
}
pub(super) fn cancel(id: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut records = pending().lock().map_err(|_| BridgeRejected)?;
    if records.remove(id).is_none() {
        return Err(BridgeRejected);
    }
    Ok(Zeroizing::new(b"{\"cancelled\":true}".to_vec()))
}
