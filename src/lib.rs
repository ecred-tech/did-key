mod secp256k1;
mod traits;
mod didcore;

use crate::{secp256k1::Secp256k1Key,
            traits::KeyLoader};

use json_patch::PatchOperation;


#[derive(Debug)]
pub enum Error {
    SignatureError,
    ResolutionFailed,
    InvalidKey,
    EncodeError,
    DecodeError,
    Unknown(String),
}

#[derive(Debug)]
pub struct AsymmetricKey<P, S> {
    public_key: P,
    secret_key: Option<S>,
}

#[derive(Debug)]
pub enum KeyPairs {
    Secp256k1(Secp256k1Key),
}

pub type DIDKey = KeyPairs;

#[derive(Debug)]
pub struct PatchedKeyPair {
    key_pair: KeyPairs,
    patches: Option<Vec<PatchOperation>>,
}

impl PatchedKeyPair {
    fn new(key_pair: KeyPairs) -> PatchedKeyPair {
        PatchedKeyPair {
            key_pair: key_pair,
            patches: None,
        }
    }
}


pub fn generate<T: KeyLoader + Into<KeyPairs>>() -> PatchedKeyPair {
    PatchedKeyPair::new(T::generate_keys().into())
}


#[cfg(test)]
pub mod test {
    use super::*;
    use crate::*;

#[test]
fn test_generate_new_key() {
    let key = generate::<Secp256k1Key>();
    let message = b"secret message";

    let public_key = match key.key_pair {
        KeyPairs::Secp256k1(ref secp256k1_key) => secp256k1_key.public_key.clone(),
    };
    
    println!("Public key: {:?}", public_key);
    //println!("{}", key.fingerprint());

    // let signature = key.sign(message);
    // let valid = key.verify(message, &signature);

    // matches!(valid, Ok(()));
    }
}