// Based on `matrix-sdk-store-encryption` (License Apache-2.0)
#![allow(deprecated)]

use blake3::{derive_key, Hash};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{AeadCore, KeyInit, XChaCha20Poly1305, XNonce};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::{rand_core, rng, RngCore};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use zeroize::{Zeroize, Zeroizing};

const VERSION: u8 = 1;
const KDF_SALT_SIZE: usize = 32;
const XNONCE_SIZE: usize = 24;
const KDF_ROUNDS: u32 = 200_000;

/// Hashes keys and encrypts/decrypts values
///
/// Allows to encrypt/decrypt data in a key/value store. Can be exported as bytes encrypted by a
/// passphrase, and imported back from bytes.
#[derive(Zeroize)]
#[zeroize(drop)]
#[deprecated(since = "0.2.0", note = "presage-store-cipher is deprecated")]
pub struct StoreCipher {
    encryption_key: Box<[u8; 32]>,
    mac_key_seed: Box<[u8; 32]>,
}

impl StoreCipher {
    pub fn new() -> Self {
        let mut rng = rng();
        let mut store_cipher = Self::zero();
        rng.fill_bytes(store_cipher.encryption_key.as_mut_slice());
        rng.fill_bytes(store_cipher.mac_key_seed.as_mut_slice());
        store_cipher
    }

    pub fn export(&self, passphrase: &str) -> Result<Vec<u8>, StoreCipherError> {
        self.export_inner(passphrase, KDF_ROUNDS)
    }

    pub fn insecure_export_fast_for_testing(
        &self,
        passphrase: &str,
    ) -> Result<Vec<u8>, StoreCipherError> {
        self.export_inner(passphrase, 1000)
    }

    pub(crate) fn export_inner(
        &self,
        passphrase: &str,
        rounds: u32,
    ) -> Result<Vec<u8>, StoreCipherError> {
        let mut rng = rng();
        let mut salt = [0u8; KDF_SALT_SIZE];
        rng.fill_bytes(&mut salt);

        let key = StoreCipher::expand_key(passphrase, &salt, rounds);
        let key = chacha20poly1305::Key::from(key);
        let cipher = XChaCha20Poly1305::new(&key);

        let rng = Rng06Shiv(&mut rng);
        let nonce = XChaCha20Poly1305::generate_nonce(rng);

        let mut keys = Zeroizing::new([0u8; 64]);
        keys[0..32].copy_from_slice(&*self.encryption_key);
        keys[32..64].copy_from_slice(&*self.mac_key_seed);

        let ciphertext = cipher.encrypt(&nonce, keys.as_slice())?;

        let store_cipher = EncryptedStoreCipher {
            kdf_info: KdfInfo::Pbkdf2ToChaCha20Poly1305 { rounds, salt },
            ciphertext_info: CipherTextInfo::ChaCha20Poly1305 {
                nonce: nonce.as_slice().try_into().expect("invalid array len"),
                ciphertext,
            },
        };
        Ok(serde_json::to_vec(&store_cipher)?)
    }

    pub fn import(passphrase: &str, encrypted: &[u8]) -> Result<Self, StoreCipherError> {
        let encrypted: EncryptedStoreCipher = serde_json::from_slice(encrypted)?;
        let key = match encrypted.kdf_info {
            KdfInfo::Pbkdf2ToChaCha20Poly1305 {
                rounds,
                salt: kdf_salt,
            } => Self::expand_key(passphrase, &kdf_salt, rounds),
        };

        let key = chacha20poly1305::Key::from(key);

        let decrypted = match encrypted.ciphertext_info {
            CipherTextInfo::ChaCha20Poly1305 { nonce, ciphertext } => {
                let cipher = XChaCha20Poly1305::new(&key);
                let nonce = XNonce::from_slice(&nonce);
                Zeroizing::new(cipher.decrypt(nonce, &*ciphertext)?)
            }
        };

        if decrypted.len() != 64 {
            return Err(StoreCipherError::Length(64, decrypted.len()));
        }

        let mut store_cipher = Self::zero();
        store_cipher
            .encryption_key
            .copy_from_slice(&decrypted[0..32]);
        store_cipher
            .mac_key_seed
            .copy_from_slice(&decrypted[32..64]);
        Ok(store_cipher)
    }

    fn expand_key(passphrase: &str, salt: &[u8], rounds: u32) -> [u8; 32] {
        let mut key = [0u8; 32];
        pbkdf2::<Hmac<Sha256>>(passphrase.as_bytes(), salt, rounds, &mut key)
            .expect("invalid length");
        key
    }

    pub fn encrypt_value(&self, value: &impl Serialize) -> Result<Vec<u8>, StoreCipherError> {
        Ok(serde_json::to_vec(&self.encrypt_value_typed(value)?)?)
    }

    fn encrypt_value_typed(
        &self,
        value: &impl Serialize,
    ) -> Result<EncryptedValue, StoreCipherError> {
        let data = serde_json::to_vec(value)?;
        self.encrypt_value_data(data)
    }

    fn encrypt_value_data(&self, mut data: Vec<u8>) -> Result<EncryptedValue, StoreCipherError> {
        let mut rng = rng();
        let rng = Rng06Shiv(&mut rng);
        let nonce = XChaCha20Poly1305::generate_nonce(rng);
        let cipher = XChaCha20Poly1305::new(self.encryption_key());

        let ciphertext = cipher.encrypt(&nonce, &*data)?;

        data.zeroize();
        Ok(EncryptedValue {
            version: VERSION,
            ciphertext,
            nonce: nonce.as_slice().try_into().expect("invalid array len"),
        })
    }

    pub fn decrypt_value<T: DeserializeOwned>(&self, value: &[u8]) -> Result<T, StoreCipherError> {
        let value: EncryptedValue = serde_json::from_slice(value)?;
        self.decrypt_value_typed(value)
    }

    fn decrypt_value_typed<T: DeserializeOwned>(
        &self,
        value: EncryptedValue,
    ) -> Result<T, StoreCipherError> {
        let mut plaintext = self.decrypt_value_data(value)?;
        let ret = serde_json::from_slice(&plaintext);
        plaintext.zeroize();
        Ok(ret?)
    }

    fn decrypt_value_data(&self, value: EncryptedValue) -> Result<Vec<u8>, StoreCipherError> {
        if value.version != VERSION {
            return Err(StoreCipherError::Version(VERSION, value.version));
        }

        let cipher = XChaCha20Poly1305::new(self.encryption_key());
        let nonce = XNonce::from_slice(&value.nonce);
        Ok(cipher.decrypt(nonce, &*value.ciphertext)?)
    }

    pub fn hash_key(&self, table_name: &str, key: &[u8]) -> [u8; 32] {
        let mac_key = self.get_mac_key_for_table(table_name);
        mac_key.mac(key).into()
    }

    fn get_mac_key_for_table(&self, table_name: &str) -> MacKey {
        let mut key = MacKey(Box::new([0u8; 32]));
        let output = Zeroizing::new(derive_key(table_name, &*self.mac_key_seed));
        key.0.copy_from_slice(&*output);
        key
    }

    fn encryption_key(&self) -> &chacha20poly1305::Key {
        chacha20poly1305::Key::from_slice(&*self.encryption_key)
    }

    fn zero() -> StoreCipher {
        Self {
            encryption_key: Box::new([0; 32]),
            mac_key_seed: Box::new([0; 32]),
        }
    }
}

#[derive(Zeroize)]
#[zeroize(drop)]
struct MacKey(Box<[u8; 32]>);

impl MacKey {
    fn mac(&self, input: &[u8]) -> Hash {
        blake3::keyed_hash(&self.0, input)
    }
}

impl Default for StoreCipher {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct EncryptedValue {
    version: u8,
    ciphertext: Vec<u8>,
    nonce: [u8; XNONCE_SIZE],
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
enum KdfInfo {
    Pbkdf2ToChaCha20Poly1305 {
        rounds: u32,
        salt: [u8; KDF_SALT_SIZE],
    },
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
enum CipherTextInfo {
    ChaCha20Poly1305 {
        nonce: [u8; XNONCE_SIZE],
        ciphertext: Vec<u8>,
    },
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct EncryptedStoreCipher {
    pub kdf_info: KdfInfo,
    pub ciphertext_info: CipherTextInfo,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreCipherError {
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
    #[error("unsupported data version, expected {0}, got {1}")]
    Version(u8, u8),
    #[error(transparent)]
    Encryption(#[from] chacha20poly1305::aead::Error),
    #[error("invalid ciphertext length, expected {0}, got {1}")]
    Length(usize, usize),
}

struct Rng06Shiv<'a, T>(&'a mut T);

impl<T: rand_core::RngCore> rand_core_06::RngCore for Rng06Shiv<'_, T> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_06::Error> {
        self.0.fill_bytes(dest);
        Ok(())
    }
}

impl<T: rand_core::CryptoRng> rand_core_06::CryptoRng for Rng06Shiv<'_, T> {}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::*;

    #[test]
    fn test_export_import() -> Result<(), StoreCipherError> {
        let passphrase = "The first rule of Fight Club is: you do not talk about Fight Club.";
        let store_cipher = StoreCipher::new();

        let value = json!({"name": "Tyler Durden"});
        let encrypted_value = store_cipher.encrypt_value(&value)?;

        let encrypted = store_cipher.insecure_export_fast_for_testing(passphrase)?;
        let decrypted = StoreCipher::import(passphrase, &encrypted)?;

        assert_eq!(store_cipher.encryption_key, decrypted.encryption_key);

        let decrypted_value: Value = decrypted.decrypt_value(&encrypted_value)?;
        assert_eq!(value, decrypted_value);

        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt() -> Result<(), StoreCipherError> {
        let store_cipher = StoreCipher::new();

        let value = json!({"name": "Tyler Durden"});
        let encrypted_value = store_cipher.encrypt_value(&value)?;
        let decrypted_value: Value = store_cipher.decrypt_value(&encrypted_value)?;
        assert_eq!(value, decrypted_value);

        Ok(())
    }

    #[test]
    fn test_hash_key() {
        let store_cipher = StoreCipher::new();
        let k1 = store_cipher.hash_key("movie", b"Fight Club");
        let k2 = store_cipher.hash_key("movie", b"Fight Club");
        assert_eq!(k1, k2);
        let k3 = store_cipher.hash_key("movie", b"Fifth Element");
        assert_ne!(k1, k3);
        let k4 = store_cipher.hash_key("film", b"Fight Club");
        assert_ne!(k1, k4);
        assert_ne!(k3, k4);
    }
}
