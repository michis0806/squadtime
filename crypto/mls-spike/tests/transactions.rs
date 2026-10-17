//! Regression tests over real MLS state using supported storage APIs.
use mls_rs::{
    client_builder::MlsConfig, error::MlsError,
    storage_provider::in_memory::InMemoryGroupStateStorage, Client, Group, GroupStateStorage,
};
use mls_rs_core::{
    error::IntoAnyError,
    group::{EpochRecord, GroupState},
};
use squadtime_mls_spike::{ApplicationReceiver, ReceiveError};
use std::sync::{
    atomic::{AtomicU8, AtomicUsize, Ordering},
    Arc,
};
use zeroize::Zeroizing;
#[path = "../support/mod.rs"]
mod support;
use support::{ApprovedDevices, Device};

#[derive(Debug)]
struct InjectedWriteError;
impl IntoAnyError for InjectedWriteError {}

/// No disk writes: saved opaque snapshots survive client/receiver reconstruction.
/// Modes explicitly model a failure before or AFTER an atomic storage write.
#[derive(Clone, Default)]
struct ObservedStorage {
    inner: InMemoryGroupStateStorage,
    failure: Arc<AtomicU8>,
    writes: Arc<AtomicUsize>,
}
impl GroupStateStorage for ObservedStorage {
    type Error = InjectedWriteError;
    fn state(&self, id: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        Ok(self.inner.state(id).unwrap())
    }
    fn epoch(&self, id: &[u8], epoch: u64) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        Ok(self.inner.epoch(id, epoch).unwrap())
    }
    fn max_epoch_id(&self, id: &[u8]) -> Result<Option<u64>, Self::Error> {
        Ok(self.inner.max_epoch_id(id).unwrap())
    }
    fn write(
        &mut self,
        state: GroupState,
        inserts: Vec<EpochRecord>,
        updates: Vec<EpochRecord>,
    ) -> Result<(), Self::Error> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        let failure = self.failure.swap(0, Ordering::SeqCst);
        if failure == 1 {
            return Err(InjectedWriteError);
        }
        self.inner.write(state, inserts, updates).unwrap();
        if failure == 2 {
            return Err(InjectedWriteError);
        }
        Ok(())
    }
}
struct Fixture<A: MlsConfig, B: MlsConfig> {
    sender: Group<A>,
    client: Client<B>,
    receiver: ApplicationReceiver<B>,
    id: Vec<u8>,
    storage: ObservedStorage,
}
fn fixture() -> Result<Fixture<impl MlsConfig, impl MlsConfig>, MlsError> {
    let alice = Device::new("synthetic-account-a/device-a");
    let bob = Device::new("synthetic-account-b/device-b");
    let approved = ApprovedDevices(vec![alice.identity.clone(), bob.identity.clone()]);
    let alice = alice.client(approved.clone());
    let storage = ObservedStorage::default();
    let bob = bob.client_with_storage(approved, storage.clone());
    let mut sender = alice.group_builder()?.build()?;
    let package = bob.generate_key_package_message(Default::default(), Default::default(), None)?;
    let commit = sender.commit_builder().add_member(package)?.build()?;
    sender.apply_pending_commit()?;
    let (recipient, _) = bob.join_group(None, &commit.welcome_messages[0], None)?;
    let id = recipient.group_id().to_vec();
    let receiver = ApplicationReceiver::initialize(&bob, recipient)?;
    Ok(Fixture {
        sender,
        client: bob,
        receiver,
        id,
        storage,
    })
}

#[test]
fn rejected_packets_leave_checkpoint_unchanged_and_authentic_retry_succeeds() -> Result<(), MlsError>
{
    let mut f = fixture()?;
    let packet = f
        .sender
        .encrypt_application_message(b"synthetic-event", vec![])?
        .to_bytes()?;
    let before = f.storage.state(&f.id).unwrap();
    let writes_before = f.storage.writes.load(Ordering::SeqCst);
    let mut tampered = packet.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(matches!(
        f.receiver.receive(&tampered, |_| true),
        Err(ReceiveError::AuthenticationFailed)
    ));
    assert!(matches!(
        f.receiver.receive(&[], |_| true),
        Err(ReceiveError::InvalidPacket)
    ));
    assert!(matches!(
        f.receiver.receive(&[0xff; 12], |_| true),
        Err(ReceiveError::InvalidPacket)
    ));
    assert!(f.storage.state(&f.id).unwrap() == before);
    assert_eq!(f.storage.writes.load(Ordering::SeqCst), writes_before);
    let sender_index = f.sender.current_member_index();
    let event = f
        .receiver
        .receive(&packet, |event| event.sender_index == sender_index)
        .unwrap();
    assert!(event.data() == b"synthetic-event");
    assert!(f.storage.state(&f.id).unwrap() != before);
    assert!(matches!(
        f.receiver.receive(&packet, |_| true),
        Err(ReceiveError::AuthenticationFailed)
    ));
    Ok(())
}

#[test]
fn application_policy_rejection_does_not_consume_authenticated_packet() -> Result<(), MlsError> {
    let mut f = fixture()?;
    let packet = f
        .sender
        .encrypt_application_message(b"synthetic-policy-event", vec![])?
        .to_bytes()?;
    let before = f.storage.state(&f.id).unwrap();
    assert!(matches!(
        f.receiver.receive(&packet, |_| false),
        Err(ReceiveError::PolicyRejected)
    ));
    assert!(f.storage.state(&f.id).unwrap() == before);
    assert!(f.receiver.receive(&packet, |_| true).is_ok());
    assert!(f.receiver.receive(&packet, |_| true).is_err());
    Ok(())
}

#[test]
fn control_packets_require_separate_transaction_path() -> Result<(), MlsError> {
    let mut f = fixture()?;
    let before = f.storage.state(&f.id).unwrap();
    let mut alternative_sender = f.sender.clone();
    let control = alternative_sender
        .commit_builder()
        .build()?
        .commit_message
        .to_bytes()?;
    assert!(matches!(
        f.receiver.receive(&control, |_| true),
        Err(ReceiveError::NotApplicationMessage)
    ));
    assert!(f.storage.state(&f.id).unwrap() == before);
    // Original epoch is still usable; the candidate control epoch was discarded.
    let packet = f
        .sender
        .encrypt_application_message(b"original-epoch", vec![])?
        .to_bytes()?;
    assert!(f.receiver.receive(&packet, |_| true).is_ok());
    Ok(())
}

#[test]
fn saved_state_survives_receiver_loss_and_rejects_already_accepted_packet() -> Result<(), MlsError>
{
    let mut f = fixture()?;
    let packet = f
        .sender
        .encrypt_application_message(b"synthetic-reload-event", vec![])?
        .to_bytes()?;
    let mut tampered = packet.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(f.receiver.receive(&tampered, |_| true).is_err());
    drop(f.receiver);
    // Simulated pre-commit crash: latest saved state can receive original packet.
    let mut reopened = ApplicationReceiver::open(&f.client, &f.id)?;
    assert!(reopened.receive(&packet, |_| true).is_ok());
    drop(reopened);
    // Simulated post-commit/pre-delivery crash: replay stays rejected on reload.
    let mut reopened = ApplicationReceiver::open(&f.client, &f.id)?;
    assert!(reopened.receive(&packet, |_| true).is_err());
    let next = f
        .sender
        .encrypt_application_message(b"next-event", vec![])?
        .to_bytes()?;
    assert!(reopened.receive(&next, |_| true).is_ok());
    Ok(())
}

#[test]
fn write_errors_poison_receiver_and_reload_observes_actual_commit_result() -> Result<(), MlsError> {
    for failure_mode in [1, 2] {
        let mut f = fixture()?;
        let packet = f
            .sender
            .encrypt_application_message(b"synthetic-storage-event", vec![])?
            .to_bytes()?;
        let before = f.storage.state(&f.id).unwrap();
        f.storage.failure.store(failure_mode, Ordering::SeqCst);
        assert!(matches!(
            f.receiver.receive(&packet, |_| true),
            Err(ReceiveError::PersistenceUncertain)
        ));
        assert!(matches!(
            f.receiver.receive(&packet, |_| true),
            Err(ReceiveError::Unavailable)
        ));
        assert_eq!(f.storage.state(&f.id).unwrap() == before, failure_mode == 1);
        drop(f.receiver);
        // Only safe here because test storage is atomic and is the trusted latest
        // checkpoint. Real partial writes require reconciliation, not blind retry.
        let mut reopened = ApplicationReceiver::open(&f.client, &f.id)?;
        assert_eq!(
            reopened.receive(&packet, |_| true).is_ok(),
            failure_mode == 1
        );
    }
    Ok(())
}

#[test]
fn prior_epoch_lazy_state_is_unchanged_on_tamper_and_persisted_on_accept() -> Result<(), MlsError> {
    let mut f = fixture()?;
    let old_epoch = f.sender.current_epoch();
    let delayed = f
        .sender
        .encrypt_application_message(b"delayed-synthetic-event", vec![])?
        .to_bytes()?;
    let control = f.sender.commit_builder().build()?;
    f.sender.apply_pending_commit()?;
    drop(f.receiver);
    // Test setup advances membership via the raw public API. The application-only
    // adapter deliberately does not authorize or expose this control operation.
    let mut recipient = f.client.load_group(&f.id)?;
    recipient.process_incoming_message(control.commit_message)?;
    recipient.write_to_storage()?;
    drop(recipient);
    let before = f.storage.epoch(&f.id, old_epoch).unwrap();
    assert!(before.is_some());
    let mut receiver = ApplicationReceiver::open(&f.client, &f.id)?;
    let mut tampered = delayed.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(receiver.receive(&tampered, |_| true).is_err());
    assert!(f.storage.epoch(&f.id, old_epoch).unwrap() == before);
    assert!(receiver.receive(&delayed, |_| true).is_ok());
    assert!(f.storage.epoch(&f.id, old_epoch).unwrap() != before);
    drop(receiver);
    let mut reopened = ApplicationReceiver::open(&f.client, &f.id)?;
    assert!(reopened.receive(&delayed, |_| true).is_err());
    Ok(())
}
