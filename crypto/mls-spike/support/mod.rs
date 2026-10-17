//! Disposable protocol proof only. The pinned registry models prior out-of-band
//! device approval; it does not implement account authentication or recovery.
use mls_rs::{
    client_builder::MlsConfig,
    identity::{basic::BasicCredential, CredentialType, SigningIdentity},
    time::MlsTime,
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, ExtensionList, IdentityProvider,
};
use mls_rs_core::{
    crypto::SignatureSecretKey, error::IntoAnyError, identity::MemberValidationContext,
};
use mls_rs_crypto_awslc::AwsLcCryptoProvider;

const SUITE: CipherSuite = CipherSuite::CURVE25519_AES128;

#[derive(Debug)]
pub struct UnapprovedDevice;
impl IntoAnyError for UnapprovedDevice {}

/// Exact credential AND signing-key pins, supplied locally by trusted approval.
/// This is intentionally separate from the untrusted delivery service.
#[derive(Clone)]
pub struct ApprovedDevices(pub Vec<SigningIdentity>);
impl ApprovedDevices {
    fn check(&self, id: &SigningIdentity) -> Result<(), UnapprovedDevice> {
        self.0.contains(id).then_some(()).ok_or(UnapprovedDevice)
    }
}
impl IdentityProvider for ApprovedDevices {
    type Error = UnapprovedDevice;
    fn validate_member(
        &self,
        id: &SigningIdentity,
        _: Option<MlsTime>,
        _: MemberValidationContext<'_>,
    ) -> Result<(), Self::Error> {
        self.check(id)
    }
    fn validate_external_sender(
        &self,
        _: &SigningIdentity,
        _: Option<MlsTime>,
        _: Option<&ExtensionList>,
    ) -> Result<(), Self::Error> {
        // No server/bot/external sender is authorized in this proof.
        Err(UnapprovedDevice)
    }
    fn identity(&self, id: &SigningIdentity, _: &ExtensionList) -> Result<Vec<u8>, Self::Error> {
        self.check(id)?;
        Ok(id
            .credential
            .as_basic()
            .ok_or(UnapprovedDevice)?
            .identifier
            .to_vec())
    }
    fn valid_successor(
        &self,
        predecessor: &SigningIdentity,
        successor: &SigningIdentity,
        _: &ExtensionList,
    ) -> Result<bool, Self::Error> {
        self.check(predecessor)?;
        self.check(successor)?;
        // Normal MLS leaf updates retain the pinned identity. Device replacement
        // must be an explicit add/remove, never a silent key takeover.
        Ok(predecessor == successor)
    }
    fn supported_types(&self) -> Vec<CredentialType> {
        vec![CredentialType::BASIC]
    }
}

pub struct Device {
    pub identity: SigningIdentity,
    secret: SignatureSecretKey,
}
impl Device {
    pub fn new(device_id: &str) -> Self {
        let crypto = AwsLcCryptoProvider::default();
        let suite = crypto.cipher_suite_provider(SUITE).unwrap();
        let (secret, public) = suite.signature_key_generate().unwrap();
        let credential = BasicCredential::new(device_id.as_bytes().to_vec());
        Self {
            identity: SigningIdentity::new(credential.into_credential(), public),
            secret,
        }
    }
    pub fn client(&self, approved: ApprovedDevices) -> Client<impl MlsConfig> {
        self.client_with_storage(
            approved,
            mls_rs::storage_provider::in_memory::InMemoryGroupStateStorage::new(),
        )
    }
    pub fn client_with_storage<S: mls_rs::GroupStateStorage + Clone + 'static>(
        &self,
        approved: ApprovedDevices,
        storage: S,
    ) -> Client<impl MlsConfig> {
        Client::builder()
            .group_state_storage(storage)
            .identity_provider(approved)
            .crypto_provider(AwsLcCryptoProvider::default())
            .signing_identity(self.identity.clone(), self.secret.clone(), SUITE)
            .build()
    }
}
