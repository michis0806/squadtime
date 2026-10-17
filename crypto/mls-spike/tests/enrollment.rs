//! LOCAL single-process P-256-to-MLS binding tests, never network enrollment.
use base64ct::{Base64, Encoding};
use mls_rs::{CipherSuite, CipherSuiteProvider, CryptoProvider};
use mls_rs_core::crypto::SignatureSecretKey;
use mls_rs_crypto_awslc::AwsLcCryptoProvider;
use serde_json::{json, Value};
use squadtime_mls_spike::native_bridge::call;
use std::sync::Mutex;
use zeroize::Zeroizing;
static SERIAL: Mutex<()> = Mutex::new(());
const NOW: u64 = 1_700_000_000;
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
fn invoke(value: Value) -> Result<Value, ()> {
    let bytes = Zeroizing::new(serde_json::to_vec(&value).unwrap());
    let output = call(&bytes).map_err(|_| ())?;
    serde_json::from_slice(&output).map_err(|_| ())
}
fn prepare(device: &Key, approver: &Key, now: u64) -> Value {
    invoke(json!({"op":"enrollmentprepare","devicePublicKey":device.public,"approverPublicKey":approver.public,"now":now})).expect("local prepare failed")
}
fn sign(key: &Key, text: &Value) -> String {
    let bytes = Base64::decode_vec(text.as_str().unwrap()).unwrap();
    let suite = AwsLcCryptoProvider::default()
        .cipher_suite_provider(CipherSuite::P256_AES128)
        .unwrap();
    Base64::encode_string(&suite.sign(&key.secret, &bytes).unwrap())
}
fn completion(prepared: &Value, device: &Key, approver: &Key, now: u64) -> Value {
    json!({"op":"enrollmentcomplete","pendingId":prepared["pendingId"],"groupId":prepared["groupId"],"keyPackage":prepared["keyPackage"],
        "requestSignature":sign(device,&prepared["request"]),"approvalSignature":sign(approver,&prepared["approval"]),"now":now})
}
fn cancel(prepared: &Value) -> Result<Value, ()> {
    invoke(json!({"op":"enrollmentcancel","pendingId":prepared["pendingId"]}))
}
#[test]
fn real_p256_admission_yields_working_mls_snapshot_and_one_shot_completion() {
    let _guard = SERIAL.lock().unwrap();
    let device = key();
    let approver = key();
    let prepared = prepare(&device, &approver, NOW);
    let request = Base64::decode_vec(prepared["request"].as_str().unwrap()).unwrap();
    let text = std::str::from_utf8(&request).unwrap();
    assert_eq!(text.split('\n').count(), 11);
    assert!(text.ends_with('\n'));
    assert!(text.starts_with("squadtime-mls-device-request-v1\n"));
    let command = completion(&prepared, &device, &approver, NOW + 1);
    let result = invoke(command.clone()).expect("valid cryptographic enrollment failed");
    assert!(invoke(command).is_err());
    assert!(cancel(&prepared).is_err());
    let first =
        invoke(json!({"op":"receive","snapshot":result["snapshot"],"packet":result["packets"][0]}))
            .expect("enrolled receiver failed");
    assert!(first["plaintext"] == result["expected"][0]);
    let second =
        invoke(json!({"op":"receive","snapshot":first["snapshot"],"packet":result["packets"][1]}))
            .unwrap();
    assert!(second["plaintext"] == result["expected"][1]);
    assert!(invoke(
        json!({"op":"receive","snapshot":second["snapshot"],"packet":result["packets"][0]})
    )
    .is_err());
    // Retained signatures bind the saved MLS identities/group, not just a boolean.
    let raw = Zeroizing::new(Base64::decode_vec(result["snapshot"].as_str().unwrap()).unwrap());
    let mut snapshot: Value = serde_json::from_slice(&raw).unwrap();
    assert!(snapshot["authorization"].is_object());
    let original = snapshot.clone();
    for (field, replacement) in [
        ("admin_identity_digest", Value::String("00".repeat(32))),
        ("group_id", Value::String(Base64::encode_string(&[0u8; 32]))),
        (
            "approval_signature",
            Value::String(Base64::encode_string(&[0u8; 64])),
        ),
    ] {
        snapshot = original.clone();
        snapshot["authorization"][field] = replacement;
        let raw = Zeroizing::new(serde_json::to_vec(&snapshot).unwrap());
        assert!(invoke(json!({"op":"receive","snapshot":Base64::encode_string(&raw),"packet":result["packets"][0]})).is_err());
    }
    let advanced =
        Zeroizing::new(Base64::decode_vec(second["snapshot"].as_str().unwrap()).unwrap());
    let advanced: Value = serde_json::from_slice(&advanced).unwrap();
    assert!(advanced["authorization"] == original["authorization"]);
}
#[test]
fn substituted_key_package_group_request_and_approver_are_rejected_without_consumption() {
    let _guard = SERIAL.lock().unwrap();
    let device = key();
    let approver = key();
    let attacker = key();
    let prepared = prepare(&device, &approver, NOW);
    let unrelated = prepare(&device, &approver, NOW);
    let valid = completion(&prepared, &device, &approver, NOW + 1);
    for (field, value) in [
        ("groupId", unrelated["groupId"].clone()),
        ("keyPackage", unrelated["keyPackage"].clone()),
        (
            "requestSignature",
            Value::String(sign(&attacker, &prepared["request"])),
        ),
        (
            "approvalSignature",
            Value::String(sign(&attacker, &prepared["approval"])),
        ),
        (
            "approvalSignature",
            Value::String(sign(&approver, &unrelated["approval"])),
        ),
    ] {
        let mut modified = valid.clone();
        modified[field] = value;
        assert!(invoke(modified).is_err());
    }
    assert!(invoke(valid).is_ok());
    assert!(cancel(&unrelated).is_ok());
}
#[test]
fn expiry_cancellation_and_invalid_native_public_keys_fail_closed() {
    let _guard = SERIAL.lock().unwrap();
    let device = key();
    let approver = key();
    let prepared = prepare(&device, &approver, NOW);
    assert!(invoke(completion(&prepared, &device, &approver, NOW - 1)).is_err());
    assert!(cancel(&prepared).is_ok());
    assert!(invoke(completion(&prepared, &device, &approver, NOW + 1)).is_err());
    let expired = prepare(&device, &approver, NOW);
    assert!(invoke(completion(&expired, &device, &approver, NOW + 300)).is_err());
    assert!(invoke(completion(&expired, &device, &approver, NOW + 1)).is_err());
    let mut invalid = vec![0u8; 65];
    invalid[0] = 4;
    assert!(invoke(json!({"op":"enrollmentprepare","devicePublicKey":Base64::encode_string(&invalid),"approverPublicKey":approver.public,"now":NOW})).is_err());
    assert!(invoke(json!({"op":"enrollmentprepare","devicePublicKey":device.public,"approverPublicKey":device.public,"now":NOW})).is_err());
}
#[test]
fn pending_contexts_are_bounded_and_explicitly_cancelled() {
    let _guard = SERIAL.lock().unwrap();
    let device = key();
    let approver = key();
    let contexts: Vec<_> = (0..16).map(|_| prepare(&device, &approver, NOW)).collect();
    assert!(invoke(json!({"op":"enrollmentprepare","devicePublicKey":device.public,"approverPublicKey":approver.public,"now":NOW})).is_err());
    for context in contexts {
        assert!(cancel(&context).is_ok());
    }
    let fresh = prepare(&device, &approver, NOW);
    assert!(cancel(&fresh).is_ok());
}

#[test]
fn malformed_der_and_concurrent_completion_are_rejected_without_reusing_admission() {
    let _guard = SERIAL.lock().unwrap();
    let device = key();
    let approver = key();
    let prepared = prepare(&device, &approver, NOW);
    let valid = completion(&prepared, &device, &approver, NOW + 1);
    let mut trailing = Base64::decode_vec(valid["approvalSignature"].as_str().unwrap()).unwrap();
    trailing.push(0);
    let mut overlong = vec![0x30, 0x81, trailing[1]];
    overlong.extend_from_slice(&trailing[2..trailing.len() - 1]);
    for bytes in [
        trailing,
        overlong,
        vec![0x30, 7, 2, 2, 0, 1, 2, 1, 1],
        vec![0x30, 6, 2, 1, 0, 2, 1, 1],
        vec![0x30, 6, 2, 1, 0x80, 2, 1, 1],
    ] {
        let mut modified = valid.clone();
        modified["approvalSignature"] = Value::String(Base64::encode_string(&bytes));
        assert!(invoke(modified).is_err());
    }
    let left = valid.clone();
    let right = valid;
    let a = std::thread::spawn(move || invoke(left).is_ok());
    let b = std::thread::spawn(move || invoke(right).is_ok());
    assert_eq!(
        usize::from(a.join().unwrap()) + usize::from(b.join().unwrap()),
        1
    );
}
