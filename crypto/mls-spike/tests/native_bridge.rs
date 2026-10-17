//! Only synthetic bridge inputs. Never print serialized fixture values/snapshots.
use base64ct::{Base64, Encoding};
use serde_json::{json, Value};
use squadtime_mls_spike::native_bridge::{
    call, squadtime_mls_call, squadtime_mls_free, MAX_CALL_BYTES,
};
use zeroize::Zeroizing;

fn encode(bytes: impl AsRef<[u8]>) -> String {
    Base64::encode_string(bytes.as_ref())
}
fn fixture() -> Value {
    let bytes = call(br#"{"op":"fixture"}"#).expect("synthetic fixture rejected");
    serde_json::from_slice(&bytes).expect("invalid bridge response shape")
}
fn receive(snapshot: &Value, packet: &Value) -> Result<Value, ()> {
    let input = Zeroizing::new(
        serde_json::to_vec(&json!({"op":"receive","snapshot":snapshot,"packet":packet})).unwrap(),
    );
    let bytes = call(&input).map_err(|_| ())?;
    serde_json::from_slice(&bytes).map_err(|_| ())
}
#[test]
fn opaque_snapshot_reopens_real_prior_and_current_epoch_packets_and_rejects_replay() {
    let fixture = fixture();
    let first =
        receive(&fixture["snapshot"], &fixture["packets"][0]).expect("prior-epoch packet rejected");
    assert!(first["plaintext"] == fixture["expected"][0]);
    assert!(first["senderIndex"].as_u64().is_some());
    assert!(receive(&first["snapshot"], &fixture["packets"][0]).is_err());
    let second =
        receive(&first["snapshot"], &fixture["packets"][1]).expect("current-epoch packet rejected");
    assert!(second["plaintext"] == fixture["expected"][1]);
    assert!(second["senderIndex"] == first["senderIndex"]);
    assert!(receive(&second["snapshot"], &fixture["packets"][1]).is_err());
    assert!(receive(&second["snapshot"], &fixture["packets"][0]).is_err());
}
#[test]
fn rejection_returns_no_candidate_and_authentic_retry_from_original_snapshot_succeeds() {
    let fixture = fixture();
    let mut tampered = Base64::decode_vec(fixture["packets"][0].as_str().unwrap()).unwrap();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(receive(&fixture["snapshot"], &Value::String(encode(&tampered))).is_err());
    assert!(receive(&fixture["snapshot"], &fixture["packets"][0]).is_ok());
    // Wrong group and pinned sender cannot be changed by supplying a relay packet.
    let unrelated = fixture_other();
    assert!(receive(&fixture["snapshot"], &unrelated["packets"][0]).is_err());
}
fn fixture_other() -> Value {
    fixture()
}
#[test]
fn malformed_commands_snapshot_and_unknown_fields_are_rejected() {
    for command in [
        b"".as_slice(),
        b"not-json",
        b"\xff",
        br#"{"op":"fixture","unexpected":true}"#,
        br#"{"op":"unknown"}"#,
        br#"{"op":"receive","snapshot":"AA==","packet":"AA=="}"#,
        br#"{"op":"receive","snapshot":"!","packet":"!"}"#,
    ] {
        assert!(call(command).is_err());
    }
    assert!(call(&vec![b' '; MAX_CALL_BYTES + 1]).is_err());
    let fixture = fixture();
    let raw = Zeroizing::new(Base64::decode_vec(fixture["snapshot"].as_str().unwrap()).unwrap());
    let mut state: Value = serde_json::from_slice(&raw).unwrap();
    state["version"] = json!(999);
    let invalid = Value::String(encode(Zeroizing::new(serde_json::to_vec(&state).unwrap())));
    assert!(receive(&invalid, &fixture["packets"][0]).is_err());
}
#[test]
fn reordered_packets_preserve_prior_epoch_replay_state() {
    let fixture = fixture();
    let second = receive(&fixture["snapshot"], &fixture["packets"][1]).unwrap();
    let first = receive(&second["snapshot"], &fixture["packets"][0]).unwrap();
    assert!(first["plaintext"] == fixture["expected"][0]);
    assert!(receive(&first["snapshot"], &fixture["packets"][1]).is_err());
}
#[test]
fn c_abi_transfers_exact_buffer_ownership_and_resets_failure_outputs() {
    let input = br#"{"op":"fixture"}"#;
    let mut output = std::ptr::null_mut();
    let mut len = 0;
    // SAFETY: valid nonaliasing input and output slots; allocation freed exactly once.
    unsafe {
        assert_eq!(
            squadtime_mls_call(input.as_ptr(), input.len(), &mut output, &mut len),
            0
        );
        assert!(!output.is_null() && len > 0 && len <= MAX_CALL_BYTES);
        let copied = Zeroizing::new(std::slice::from_raw_parts(output, len).to_vec());
        squadtime_mls_free(output, len);
        let parsed: Value = serde_json::from_slice(&copied).unwrap();
        assert!(parsed["snapshot"].is_string());
        assert!(parsed["packets"].as_array().is_some_and(|v| v.len() == 2));
        // Output slots are overwritten even when their old values are nonzero.
        output = std::ptr::dangling_mut();
        len = usize::MAX;
        let bad = b"malformed";
        assert_eq!(
            squadtime_mls_call(bad.as_ptr(), bad.len(), &mut output, &mut len),
            1
        );
        assert!(output.is_null() && len == 0);
        assert_eq!(
            squadtime_mls_call(std::ptr::null(), 1, &mut output, &mut len),
            2
        );
        assert!(output.is_null() && len == 0);
        assert_eq!(
            squadtime_mls_call(input.as_ptr(), input.len(), std::ptr::null_mut(), &mut len),
            2
        );
        squadtime_mls_free(std::ptr::null_mut(), 0);
    }
}
