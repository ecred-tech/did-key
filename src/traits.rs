use crate::didcore::{Config, Document,  VerificationMethod};
// /// Return OwnPair bytes


pub trait KeyLoader {
    fn generate_keys() -> Self;
    fn from_secret_key(private_key: String) -> Self;
}

pub trait DIDCore {
    fn get_verification_methods(&self, config: Config, controller: &str) -> Vec<VerificationMethod>;
    fn get_did_document(&self, config: Config) -> Document;
}

pub trait Fingerprint {
    fn fingerprint(&self) -> String;
}