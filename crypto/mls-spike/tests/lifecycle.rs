use mls_rs::{error::MlsError, group::ReceivedMessage, MlsMessage};
#[path = "../support/mod.rs"]
mod support;
use support::{ApprovedDevices, Device};

const EVENT: &[u8] = br#"{"v":1,"type":"availability.set","eventId":"event-1","start":"2026-10-21T15:00:00Z","durationMinutes":60}"#;

/// All simulated network traffic is serialized and decoded; no shared group keys.
fn wire(message: &MlsMessage) -> Result<MlsMessage, MlsError> {
    MlsMessage::from_bytes(&message.to_bytes()?)
}
fn assert_event(message: ReceivedMessage, expected: &[u8], sender: u32) {
    match message {
        ReceivedMessage::ApplicationMessage(event) => {
            assert_eq!(event.data(), expected);
            assert_eq!(event.sender_index, sender);
        }
        _ => panic!("expected an authenticated application message"),
    }
}

#[test]
fn welcome_event_roundtrip_and_removed_device_cannot_read_future_epoch() -> Result<(), MlsError> {
    let alice = Device::new("account-a/device-a");
    let bob = Device::new("account-b/device-b");
    let carol = Device::new("account-c/device-c");
    let approved = ApprovedDevices(vec![
        alice.identity.clone(),
        bob.identity.clone(),
        carol.identity.clone(),
    ]);
    let alice = alice.client(approved.clone());
    let bob = bob.client(approved.clone());
    let carol = carol.client(approved);
    let mut alice_group = alice.group_builder()?.build()?;
    let bob_package =
        bob.generate_key_package_message(Default::default(), Default::default(), None)?;
    let carol_package =
        carol.generate_key_package_message(Default::default(), Default::default(), None)?;
    let commit = alice_group
        .commit_builder()
        .add_member(wire(&bob_package)?)?
        .add_member(wire(&carol_package)?)?
        .build()?;
    // Simulate delivery-service acceptance before advancing local state.
    alice_group.apply_pending_commit()?;
    let (mut bob_group, _) = bob.join_group(None, &wire(&commit.welcome_messages[0])?, None)?;
    let (mut carol_group, _) = carol.join_group(None, &wire(&commit.welcome_messages[0])?, None)?;
    assert_eq!(alice_group.roster().members().len(), 3);
    assert_eq!(alice_group.current_epoch(), bob_group.current_epoch());
    let alice_index = alice_group.current_member_index();
    let encrypted = alice_group.encrypt_application_message(EVENT, Default::default())?;
    let bytes = encrypted.to_bytes()?;
    assert!(!bytes.windows(EVENT.len()).any(|window| window == EVENT));
    assert_event(
        bob_group.process_incoming_message(wire(&encrypted)?)?,
        EVENT,
        alice_index,
    );
    assert_event(
        carol_group.process_incoming_message(wire(&encrypted)?)?,
        EVENT,
        alice_index,
    );
    // A second member can send; the authenticated sender comes from MLS.
    let reply = bob_group.encrypt_application_message(b"session.accept", Default::default())?;
    assert_event(
        alice_group.process_incoming_message(wire(&reply)?)?,
        b"session.accept",
        bob_group.current_member_index(),
    );

    let previous_epoch = bob_group.current_epoch();
    let removal = alice_group
        .commit_builder()
        .remove_member(bob_group.current_member_index())?
        .build()?;
    alice_group.apply_pending_commit()?;
    carol_group.process_incoming_message(wire(&removal.commit_message)?)?;
    assert!(alice_group.current_epoch() > previous_epoch);
    assert_eq!(alice_group.roster().members().len(), 2);
    let future =
        alice_group.encrypt_application_message(b"private-after-removal", Default::default())?;
    assert_event(
        carol_group.process_incoming_message(wire(&future)?)?,
        b"private-after-removal",
        alice_index,
    );
    // Even withholding the removal commit cannot let an old epoch decrypt a new one.
    assert!(bob_group.process_incoming_message(wire(&future)?).is_err());
    let _ = bob_group.process_incoming_message(wire(&removal.commit_message)?);
    assert!(bob_group.process_incoming_message(wire(&future)?).is_err());
    Ok(())
}

#[test]
fn altered_ciphertext_and_replay_are_rejected() -> Result<(), MlsError> {
    let alice = Device::new("account-a/device-a");
    let bob = Device::new("account-b/device-b");
    let approved = ApprovedDevices(vec![alice.identity.clone(), bob.identity.clone()]);
    let alice = alice.client(approved.clone());
    let bob = bob.client(approved);
    let mut group = alice.group_builder()?.build()?;
    let package = bob.generate_key_package_message(Default::default(), Default::default(), None)?;
    let commit = group
        .commit_builder()
        .add_member(wire(&package)?)?
        .build()?;
    group.apply_pending_commit()?;
    let (mut joined, _) = bob.join_group(None, &wire(&commit.welcome_messages[0])?, None)?;
    let encrypted = group.encrypt_application_message(EVENT, Default::default())?;
    let mut corrupted = encrypted.to_bytes()?;
    *corrupted.last_mut().unwrap() ^= 0x01;
    let rejected = match MlsMessage::from_bytes(&corrupted) {
        Ok(message) => joined.process_incoming_message(message).is_err(),
        Err(_) => true,
    };
    assert!(rejected);
    // This library consumes the ratchet generation on failed authentication.
    // A retry of that generation fails closed (KeyMissing); verify a fresh
    // generation works, and document the availability consequence.
    assert!(matches!(
        joined.process_incoming_message(wire(&encrypted)?),
        Err(MlsError::KeyMissing(0))
    ));
    let fresh = group.encrypt_application_message(EVENT, Default::default())?;
    assert_event(
        joined.process_incoming_message(wire(&fresh)?)?,
        EVENT,
        group.current_member_index(),
    );
    assert!(joined.process_incoming_message(wire(&fresh)?).is_err());
    Ok(())
}

#[test]
fn server_cannot_substitute_a_new_key_under_an_approved_device_identifier() -> Result<(), MlsError>
{
    let alice = Device::new("account-a/device-a");
    let bob = Device::new("account-b/device-b");
    let impostor = Device::new("account-b/device-b");
    assert_ne!(bob.identity.signature_key, impostor.identity.signature_key);
    let approved = ApprovedDevices(vec![alice.identity.clone(), bob.identity.clone()]);
    let alice_client = alice.client(approved.clone());
    // Attacker trusts itself, but Alice's local registry still pins Bob's real key.
    let attacker = impostor.client(ApprovedDevices(vec![impostor.identity.clone()]));
    let forged =
        attacker.generate_key_package_message(Default::default(), Default::default(), None)?;
    let mut group = alice_client.group_builder()?.build()?;
    let attempt = group
        .commit_builder()
        .add_member(wire(&forged)?)
        .and_then(|builder| builder.build());
    assert!(attempt.is_err());
    assert_eq!(group.roster().members().len(), 1);
    // Prove rejection is key-specific: the approved device with the same ID works.
    let bob = bob.client(approved);
    let valid = bob.generate_key_package_message(Default::default(), Default::default(), None)?;
    let commit = group.commit_builder().add_member(wire(&valid)?)?.build()?;
    group.apply_pending_commit()?;
    bob.join_group(None, &wire(&commit.welcome_messages[0])?, None)?;
    Ok(())
}
