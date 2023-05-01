use std::{str::FromStr, fmt::format};

use crate::{
            didcore::{*},
            traits::{KeyLoader, Fingerprint, DIDCore },
            AsymmetricKey , KeyPairs };   

use secp256k1::rand::rngs::OsRng;
use secp256k1::{Secp256k1, SecretKey, PublicKey,KeyPair};


pub type Secp256k1Key = AsymmetricKey<PublicKey, SecretKey>;




impl KeyLoader for Secp256k1Key {
    fn generate_keys()-> Self{
        let secp =  Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);
        
        Secp256k1Key { 
            public_key: public_key,
            secret_key: Some(secret_key),
        }
    }

    fn from_secret_key(sk: String)-> Self{
        let secp =  Secp256k1::new();
        let key = SecretKey::from_str( &*sk).unwrap();
        let key = KeyPair::from_secret_key(&secp, &key);
        
        return  Secp256k1Key {
            secret_key: Some(key.secret_key()),
            public_key: key.public_key() ,
        }
    }

}

impl Fingerprint for Secp256k1Key {
    fn fingerprint(&self) -> String {
        
        let serialize_key = self.public_key.serialize();
       
        format!("z{}", (bs58::encode(serialize_key).into_string()) )
        
    }
}

impl DIDCore for Secp256k1Key{
    fn get_verification_methods(&self, config: Config, controller: &str) -> Vec<VerificationMethod> {
        let pk = self.public_key.serialize();    

        vec![
                VerificationMethod{
                    id: format!("{}#{}", controller, self.fingerprint()),
                    key_type: match config.use_jose_format {
                        false => "EcdsaSecp256k1VerificationKey2019".into(),
                        true => "JsonWebKey2020".into(),
                    },
                    controller: controller.to_string(),
                    public_key: Some(match config.use_jose_format {
                        false => KeyFormat::Base58(bs58::encode(self.public_key.serialize()).into_string()),
                        true => KeyFormat::JWK(JWK {
                            key_type: "EC".into(),
                            curve: "secp256k1".into(),
                            x: Some(base64::encode_config(&pk[1..33], base64::URL_SAFE_NO_PAD)),
                            y: Some(base64::encode_config(&pk[33..65], base64::URL_SAFE_NO_PAD)),
                            ..Default::default()
                        }),
                    }),
                    private_key: match config.serialize_secrets {
                        true => self.secret_key.as_ref().map(|_| match config.use_jose_format {
                            false => KeyFormat::Base58(bs58::encode(self.private_key_bytes()).into_string()),
                            true => KeyFormat::JWK(JWK {
                                key_type: "EC".into(),
                                curve: "secp256k1".into(),
                                x: Some(base64::encode_config(&pk[1..33], base64::URL_SAFE_NO_PAD)),
                                y: Some(base64::encode_config(&pk[33..65], base64::URL_SAFE_NO_PAD)),
                                d: Some(base64::encode_config(self.private_key_bytes(), base64::URL_SAFE_NO_PAD)),
                                ..Default::default()
                            }),
                        }),
                        false => None,
                    },
                    ..Default::default()
                }   
            ]
    }

    fn get_did_document(&self, config: Config) -> Document {
        let fingerprint = self.fingerprint();
        let controller = format!("did:key:{}", fingerprint.clone());   
        let vm = self.get_verification_methods(config, &controller); 

        Document { 
            context: "https://www.w3.org/ns/did/v1".to_string(), 
            id: controller.to_string(), 
            assertion_method: Some(vm.iter().map(|x| x.id.to_string()).collect()), 
            authentication: Some(vec![vm[0].id.clone()]), 
            capability_delegation:  Some(vec![vm[0].id.clone()]), 
            capability_invocation: Some(vec![vm[0].id.clone()]), 
            key_agreement: Some(vec![vm[0].id.clone()]), 
            verification_method: vm 
        }
    }
}

impl From<Secp256k1Key> for KeyPairs {
    fn from(key_pair: Secp256k1Key) -> Self {
        KeyPairs::Secp256k1(key_pair)
        
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn test_print_public_key() {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&[1; 32]).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    
        println!("Public key: {:?}", public_key);
    }

    #[test]
    fn test_print_fingerprint() {

        let secp = Secp256k1Key::generate_keys();
        println!("fingerprint: {}",secp.fingerprint());
    }
}





