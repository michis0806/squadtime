//! Independent serialized clients. No participant object/registry is shared by ops.
use base64ct::{Base64, Encoding};
use mls_rs::{CipherSuite, CipherSuiteProvider, CryptoProvider};
use mls_rs_core::crypto::SignatureSecretKey;
use mls_rs_crypto_awslc::AwsLcCryptoProvider;
use serde_json::{json, Value};
use squadtime_mls_spike::native_bridge::call;
use zeroize::Zeroizing;
const NOW: u64 = 1_700_000_000;
const PROBE: &[u8] =
    br#"{"v":1,"eventId":"independent-admission-probe","type":"availability.set"}"#;
struct Key {
    secret: SignatureSecretKey,
    public: String,
}
fn key() -> Key {
    let suite = AwsLcCryptoProvider::default()
        .cipher_suite_provider(CipherSuite::P256_AES128)
        .unwrap();
    let (secret, public) = suite.signature_key_generate().unwrap();
    Key {
        secret,
        public: Base64::encode_string(public.as_ref()),
    }
}
fn sign(key: &Key, transcript: &Value) -> String {
    let suite = AwsLcCryptoProvider::default()
        .cipher_suite_provider(CipherSuite::P256_AES128)
        .unwrap();
    let bytes = Base64::decode_vec(transcript.as_str().unwrap()).unwrap();
    Base64::encode_string(&suite.sign(&key.secret, &bytes).unwrap())
}
fn invoke(value: Value) -> Result<Value, ()> {
    let input = Zeroizing::new(serde_json::to_vec(&value).unwrap());
    let output = call(&input).map_err(|_| ())?;
    serde_json::from_slice(&output).map_err(|_| ())
}
fn unpack(value: &Value) -> Value {
    let bytes = Zeroizing::new(Base64::decode_vec(value.as_str().unwrap()).unwrap());
    serde_json::from_slice(&bytes).unwrap()
}
fn pack(value: &Value) -> Value {
    let bytes = Zeroizing::new(serde_json::to_vec(value).unwrap());
    Value::String(Base64::encode_string(&bytes))
}
struct Flow {
    admin: Key,
    device: Key,
    owner: Value,
    joiner: Value,
    approval: Value,
}
fn flow() -> Flow {
    let admin = key();
    let device = key();
    let draft =
        invoke(json!({"op":"admissioncreateadmin","adminPublicKey":admin.public,"now":NOW}))
            .unwrap();
    assert_eq!(
        Base64::decode_vec(draft["transcript"].as_str().unwrap())
            .unwrap()
            .iter()
            .filter(|b| **b == b'\n')
            .count(),
        7
    );
    let owner=invoke(json!({"op":"admissionpublishinvitation","state":draft["state"],"signature":sign(&admin,&draft["transcript"]),"now":NOW})).unwrap();
    let draft=invoke(json!({"op":"admissioncreatejoiner","invitation":owner["outbox"],"trustedAdminPublicKey":admin.public,"devicePublicKey":device.public,"now":NOW+1})).unwrap();
    assert_eq!(
        Base64::decode_vec(draft["transcript"].as_str().unwrap())
            .unwrap()
            .iter()
            .filter(|b| **b == b'\n')
            .count(),
        11
    );
    let joiner=invoke(json!({"op":"admissionpublishrequest","state":draft["state"],"signature":sign(&device,&draft["transcript"]),"now":NOW+1})).unwrap();
    let approval=invoke(json!({"op":"admissioninspectrequest","state":owner["state"],"request":joiner["outbox"],"trustedDevicePublicKey":device.public,"now":NOW+2})).unwrap();
    assert_eq!(
        Base64::decode_vec(approval["transcript"].as_str().unwrap())
            .unwrap()
            .iter()
            .filter(|b| **b == b'\n')
            .count(),
        9
    );
    Flow {
        admin,
        device,
        owner,
        joiner,
        approval,
    }
}
fn admit(flow: &Flow) -> Value {
    invoke(json!({"op":"admissionadmit","state":flow.owner["state"],"request":flow.joiner["outbox"],"trustedDevicePublicKey":flow.device.public,"approvalSignature":sign(&flow.admin,&flow.approval["transcript"]),"now":NOW+2})).unwrap()
}
#[test]
fn independent_state_reopen_exact_outbox_delayed_join_and_durable_candidate_receive() {
    let f = flow();
    let admitted = admit(&f);
    assert!(admitted["kind"] == "welcome");
    assert!(admitted.get("snapshot").is_none());
    for _ in 0..3 {
        let resumed = invoke(json!({"op":"admissionresume","state":admitted["state"]})).unwrap();
        assert!(resumed["outbox"] == admitted["outbox"] && resumed["kind"] == "welcome");
    }
    let wire = unpack(&admitted["outbox"]);
    let joined=invoke(json!({"op":"admissionjoin","state":f.joiner["state"],"welcome":admitted["outbox"],"now":NOW+600})).expect("delayed authorized Welcome rejected");
    assert!(joined["kind"] == "joined" && joined["outbox"] == "");
    assert!(joined.get("snapshot").is_none());
    let received =
        invoke(json!({"op":"admissionreceive","state":joined["state"],"packet":wire["probe"]}))
            .expect("independently joined client failed to decrypt probe");
    let plaintext =
        Zeroizing::new(Base64::decode_vec(received["plaintext"].as_str().unwrap()).unwrap());
    assert!(plaintext.as_slice() == PROBE);
    assert!(received["senderIndex"].as_u64().is_some());
    assert!(invoke(
        json!({"op":"admissionreceive","state":received["state"],"packet":wire["probe"]})
    )
    .is_err());
    let resumed = invoke(json!({"op":"admissionresume","state":received["state"]})).unwrap();
    assert!(resumed["outbox"] == "" && resumed["kind"] == "joined");
    // A caller must atomically save this successor WITH its inbox; bridge alone
    // intentionally does not consume the original caller-owned state.
    assert!(invoke(
        json!({"op":"admissionreceive","state":joined["state"],"packet":wire["probe"]})
    )
    .is_ok());
}
#[test]
fn missing_approval_wrong_native_pins_and_substituted_request_fail_without_consuming_state() {
    let f = flow();
    let attacker = key();
    assert!(invoke(json!({"op":"admissioncreatejoiner","invitation":f.owner["outbox"],"trustedAdminPublicKey":attacker.public,"devicePublicKey":f.device.public,"now":NOW+1})).is_err());
    assert!(invoke(json!({"op":"admissioninspectrequest","state":f.owner["state"],"request":f.joiner["outbox"],"trustedDevicePublicKey":attacker.public,"now":NOW+2})).is_err());
    let mut request = unpack(&f.joiner["outbox"]);
    request["keyPackage"] = Value::String("AA==".into());
    assert!(invoke(json!({"op":"admissioninspectrequest","state":f.owner["state"],"request":pack(&request),"trustedDevicePublicKey":f.device.public,"now":NOW+2})).is_err());
    for signature in ["".to_owned(), sign(&attacker, &f.approval["transcript"])] {
        assert!(invoke(json!({"op":"admissionadmit","state":f.owner["state"],"request":f.joiner["outbox"],"trustedDevicePublicKey":f.device.public,"approvalSignature":signature,"now":NOW+2})).is_err());
    }
    assert!(admit(&f)["kind"] == "welcome");
}
#[test]
fn consumed_phases_wrong_group_welcome_and_replaced_requests_are_rejected() {
    let a = flow();
    let b = flow();
    let admitted = admit(&a);
    let unrelated = admit(&b);
    assert!(invoke(json!({"op":"admissionjoin","state":a.joiner["state"],"welcome":unrelated["outbox"],"now":NOW+3})).is_err());
    let mut mismatched = unpack(&admitted["outbox"]);
    mismatched["welcome"] = unpack(&unrelated["outbox"])["welcome"].clone();
    assert!(invoke(json!({"op":"admissionjoin","state":a.joiner["state"],"welcome":pack(&mismatched),"now":NOW+3})).is_err());
    let joined=invoke(json!({"op":"admissionjoin","state":a.joiner["state"],"welcome":admitted["outbox"],"now":NOW+3})).unwrap();
    assert!(invoke(json!({"op":"admissionjoin","state":joined["state"],"welcome":admitted["outbox"],"now":NOW+3})).is_err());
    assert!(invoke(json!({"op":"admissionadmit","state":admitted["state"],"request":a.joiner["outbox"],"trustedDevicePublicKey":a.device.public,"approvalSignature":sign(&a.admin,&a.approval["transcript"]),"now":NOW+3})).is_err());
    assert!(invoke(json!({"op":"admissioninspectrequest","state":a.owner["state"],"request":b.joiner["outbox"],"trustedDevicePublicKey":b.device.public,"now":NOW+2})).is_err());
}
#[test]
fn authentication_failure_keeps_original_serialized_candidate_retryable_and_expiry_gates_admit() {
    let f = flow();
    let admitted = admit(&f);
    let wire = unpack(&admitted["outbox"]);
    let joined=invoke(json!({"op":"admissionjoin","state":f.joiner["state"],"welcome":admitted["outbox"],"now":NOW+3})).unwrap();
    let mut corrupted = Base64::decode_vec(wire["probe"].as_str().unwrap()).unwrap();
    *corrupted.last_mut().unwrap() ^= 1;
    assert!(invoke(json!({"op":"admissionreceive","state":joined["state"],"packet":Base64::encode_string(&corrupted)})).is_err());
    assert!(invoke(
        json!({"op":"admissionreceive","state":joined["state"],"packet":wire["probe"]})
    )
    .is_ok());
    assert!(invoke(json!({"op":"admissionadmit","state":f.owner["state"],"request":f.joiner["outbox"],"trustedDevicePublicKey":f.device.public,"approvalSignature":sign(&f.admin,&f.approval["transcript"]),"now":NOW+300})).is_err());
    assert!(invoke(
        json!({"op":"admissionreceive","state":f.joiner["state"],"packet":wire["probe"]})
    )
    .is_err());
}

fn digest(bytes: &[u8]) -> String {
    let suite = AwsLcCryptoProvider::default()
        .cipher_suite_provider(CipherSuite::P256_AES128)
        .unwrap();
    suite
        .hash(bytes)
        .unwrap()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn request_transcript(request: &Value) -> Value {
    let invite = unpack(&request["invitation"]);
    let bytes = |field: &Value| Base64::decode_vec(field.as_str().unwrap()).unwrap();
    Value::String(Base64::encode_string(
        format!(
            "squadtime-mls-admission-request-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
            request["requestId"].as_str().unwrap(),
            digest(&bytes(&request["invitation"])),
            invite["groupId"].as_str().unwrap(),
            digest(&bytes(&request["keyPackage"])),
            digest(&bytes(&request["joinerIdentity"])),
            digest(&bytes(&invite["adminIdentity"])),
            request["devicePublicKey"].as_str().unwrap(),
            invite["adminPublicKey"].as_str().unwrap(),
            request["issuedAt"].as_u64().unwrap(),
            request["expiresAt"].as_u64().unwrap()
        )
        .as_bytes(),
    ))
}
#[test]
fn native_signed_alien_key_package_identity_and_trailing_wire_bytes_reject() {
    let a = flow();
    let b = flow();
    let original = unpack(&a.joiner["outbox"]);
    let alien = unpack(&b.joiner["outbox"])["keyPackage"].clone();
    let mut trailed = Base64::decode_vec(original["keyPackage"].as_str().unwrap()).unwrap();
    trailed.push(0);
    for package in [alien, Value::String(Base64::encode_string(&trailed))] {
        let mut modified = original.clone();
        modified["keyPackage"] = package;
        modified["signature"] = Value::String(sign(&a.device, &request_transcript(&modified)));
        assert!(invoke(json!({"op":"admissioninspectrequest","state":a.owner["state"],"request":pack(&modified),"trustedDevicePublicKey":a.device.public,"now":NOW+2})).is_err());
    }
    let admitted = admit(&a);
    let mut welcome = unpack(&admitted["outbox"]);
    let mut bytes = Base64::decode_vec(welcome["welcome"].as_str().unwrap()).unwrap();
    bytes.push(0);
    welcome["welcome"] = Value::String(Base64::encode_string(&bytes));
    assert!(invoke(
        json!({"op":"admissionjoin","state":a.joiner["state"],"welcome":pack(&welcome),"now":NOW+3})
    )
    .is_err());
    let joined=invoke(json!({"op":"admissionjoin","state":a.joiner["state"],"welcome":admitted["outbox"],"now":NOW+3})).unwrap();
    let probe = unpack(&admitted["outbox"])["probe"].clone();
    let mut bytes = Base64::decode_vec(probe.as_str().unwrap()).unwrap();
    bytes.push(0);
    assert!(invoke(json!({"op":"admissionreceive","state":joined["state"],"packet":Base64::encode_string(&bytes)})).is_err());
    assert!(
        invoke(json!({"op":"admissionreceive","state":joined["state"],"packet":probe})).is_ok()
    );
}
