use k256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug)]
pub enum KeypairError {
    GenerationError,
    SignatureError,
    VerificationError,
    SerializationError,
}

impl fmt::Display for KeypairError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            KeypairError::GenerationError => write!(f, "Key generation failed"),
            KeypairError::SignatureError => write!(f, "Invalid signature"),
            KeypairError::VerificationError => write!(f, "Signature verification failed"),
            KeypairError::SerializationError => write!(f, "Serialization failed"),
        }
    }
}

impl std::error::Error for KeypairError {}

#[derive(Clone, Serialize, Deserialize)]
pub struct Keypair {
    #[serde(with = "signing_key_serde")]
    signing_key: SigningKey,
}

mod signing_key_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(key: &SigningKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&key.to_bytes())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SigningKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("Invalid key length"));
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&bytes);
        SigningKey::from_bytes((&key_bytes).into())
            .map_err(|_| serde::de::Error::custom("Invalid signing key"))
    }
}

impl Keypair {
    pub fn generate() -> Result<Self, KeypairError> {
        let signing_key = SigningKey::random(&mut OsRng);
        Ok(Keypair { signing_key })
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, KeypairError> {
        let signing_key =
            SigningKey::from_bytes(bytes.into()).map_err(|_| KeypairError::GenerationError)?;
        Ok(Keypair { signing_key })
    }

    pub fn from_secret_key(secret_key: &[u8]) -> Result<Self, KeypairError> {
        if secret_key.len() != 32 {
            return Err(KeypairError::GenerationError);
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(secret_key);
        Self::from_bytes(&bytes)
    }

    pub fn from_hex(hex: &str) -> Result<Self, KeypairError> {
        let bytes = hex::decode(hex).map_err(|_| KeypairError::SerializationError)?;
        if bytes.len() != 32 {
            return Err(KeypairError::GenerationError);
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&bytes);
        Self::from_bytes(&key_bytes)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes().into()
    }

    pub fn secret_key_bytes(&self) -> [u8; 32] {
        self.to_bytes()
    }

    pub fn secret_key_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    pub fn public_key(&self) -> VerifyingKey {
        *self.signing_key.verifying_key()
    }

    /// Returns the 33-byte SEC1 compressed public key
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key().to_encoded_point(true).as_bytes().to_vec()
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let sig: Signature = self.signing_key.sign(message);
        sig.to_bytes().to_vec()
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), KeypairError> {
        if signature.len() != 64 {
            return Err(KeypairError::SignatureError);
        }
        let sig = Signature::from_slice(signature).map_err(|_| KeypairError::SignatureError)?;
        self.public_key()
            .verify(message, &sig)
            .map_err(|_| KeypairError::VerificationError)
    }

    pub fn verify_with_public_key(
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), KeypairError> {
        verify_signature(public_key, message, signature)
    }
}

pub fn verify_signature(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), KeypairError> {
    if public_key.len() != 33 {
        return Err(KeypairError::VerificationError);
    }
    if signature.len() != 64 {
        return Err(KeypairError::SignatureError);
    }

    let verifying_key =
        VerifyingKey::from_sec1_bytes(public_key).map_err(|_| KeypairError::VerificationError)?;
    let sig = Signature::from_slice(signature).map_err(|_| KeypairError::SignatureError)?;

    verifying_key
        .verify(message, &sig)
        .map_err(|_| KeypairError::VerificationError)
}

pub fn keypair_from_seed(seed: &[u8]) -> Result<Keypair, KeypairError> {
    if seed.len() < 32 {
        return Err(KeypairError::GenerationError);
    }

    let mut secret_bytes = [0u8; 32];
    secret_bytes.copy_from_slice(&seed[..32]);

    Keypair::from_bytes(&secret_bytes)
}
