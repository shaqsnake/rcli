use std::{fs, io::Read, path::Path, vec};

use crate::{get_reader, process_genpass, TextSignFormat};
use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

pub trait TextSigner {
    /// Sign the input and return the signature
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>>;
}

pub trait TextVerifier {
    /// Verify the signature of the input
    fn verify(&self, reader: impl Read, sig: &[u8]) -> Result<bool>;
}

pub trait TextCipher {
    /// Encrypt the input and return the encrypted data
    fn encrypt(&self, reader: &mut dyn Read) -> Result<Vec<u8>>;

    /// Decrypt the input and return the decrypted data
    fn decrypt(&self, reader: &mut dyn Read) -> Result<Vec<u8>>;
}

pub trait KeyLoader {
    fn load(path: &str) -> Result<Self>
    where
        Self: Sized;
}

pub trait KeyGenerator {
    fn generate() -> Result<Vec<Vec<u8>>>;
}

pub struct Blake3 {
    key: [u8; 32],
}

pub struct Ed25519Signer {
    key: SigningKey,
}

pub struct Ed25519Verifier {
    key: VerifyingKey,
}

pub struct ChaCha20Poly1305Cipher {
    key: chacha20poly1305::Key,
    nonce: chacha20poly1305::Nonce,
}

impl TextSigner for Blake3 {
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        Ok(blake3::keyed_hash(&self.key, &buf).as_bytes().to_vec())
    }
}

impl TextVerifier for Blake3 {
    fn verify(&self, mut reader: impl Read, sig: &[u8]) -> Result<bool> {
        let mut buf: Vec<u8> = Vec::new();
        reader.read_to_end(&mut buf)?;
        Ok(blake3::keyed_hash(&self.key, &buf).as_bytes() == sig)
    }
}

impl Blake3 {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    pub fn try_new(key: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();
        let key = (&key[..32]).try_into()?;
        Ok(Self::new(key))
    }
}

impl KeyLoader for Blake3 {
    fn load(path: &str) -> Result<Self> {
        let key = fs::read(path)?;
        Self::try_new(key)
    }
}

impl KeyGenerator for Blake3 {
    fn generate() -> Result<Vec<Vec<u8>>> {
        let key = process_genpass(32, true, true, true, true)?;
        Ok(vec![key.as_bytes().to_vec()])
    }
}

impl TextSigner for Ed25519Signer {
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        Ok(self.key.sign(&buf).to_bytes().to_vec())
    }
}

impl TextVerifier for Ed25519Verifier {
    fn verify(&self, mut reader: impl Read, sig: &[u8]) -> Result<bool> {
        let mut buf: Vec<u8> = Vec::new();
        reader.read_to_end(&mut buf)?;
        let sig = Signature::from_bytes(sig.try_into()?);
        Ok(self.key.verify(&buf, &sig).is_ok())
    }
}

impl Ed25519Signer {
    pub fn new(key: SigningKey) -> Self {
        Self { key }
    }

    pub fn try_new(key: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();
        let key = SigningKey::from_bytes(&key.try_into()?);
        Ok(Self::new(key))
    }
}

impl KeyLoader for Ed25519Signer {
    fn load(path: &str) -> Result<Self> {
        println!("path: {:?}", path);
        let key = fs::read(path)?;
        Self::try_new(key)
    }
}

impl KeyGenerator for Ed25519Signer {
    fn generate() -> Result<Vec<Vec<u8>>> {
        let mut csprng = OsRng;
        let sk = SigningKey::generate(&mut csprng);
        let pk = sk.verifying_key().to_bytes().to_vec();
        let sk = sk.as_bytes().to_vec();
        Ok(vec![sk, pk])
    }
}

impl Ed25519Verifier {
    pub fn new(key: VerifyingKey) -> Self {
        Self { key }
    }

    pub fn try_new(key: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();
        let key = VerifyingKey::from_bytes(&key.try_into()?)?;
        Ok(Self::new(key))
    }
}

impl KeyLoader for Ed25519Verifier {
    fn load(path: &str) -> Result<Self> {
        let key = fs::read(path)?;
        Self::try_new(key)
    }
}

impl ChaCha20Poly1305Cipher {
    pub fn new(key: chacha20poly1305::Key, nonce: chacha20poly1305::Nonce) -> Self {
        Self { key, nonce }
    }

    pub fn try_new(key: impl AsRef<[u8]>, nonce: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();
        let nonce = nonce.as_ref();
        let key = chacha20poly1305::Key::from_slice(key);
        let nonce = chacha20poly1305::Nonce::from_slice(nonce);
        Ok(Self::new(*key, *nonce))
    }
}

impl TextCipher for ChaCha20Poly1305Cipher {
    fn encrypt(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let cipher = ChaCha20Poly1305::new(&self.key);
        // cipher.encrypt_in_place(&self.nonce, b"", &mut buf)
        let encrypted = cipher.encrypt(&self.nonce, buf.as_slice()).unwrap();
        let encrypted: String = URL_SAFE_NO_PAD.encode(encrypted);
        Ok(encrypted.into_bytes())
    }

    fn decrypt(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;

        let cipher = ChaCha20Poly1305::new(&self.key);
        let buf = URL_SAFE_NO_PAD.decode(&buf)?;
        // cipher.decrypt_in_place(&self.nonce, b"", &mut buf);
        let decrypted = cipher.decrypt(&self.nonce, buf.as_slice()).unwrap();
        Ok(decrypted)
    }
}

impl KeyLoader for ChaCha20Poly1305Cipher {
    fn load(path: &str) -> Result<Self> {
        let combined_key = fs::read(path)?;
        let combined_key = combined_key.as_slice();
        let key: [u8; 32] = combined_key[..32].try_into()?;
        let nonce: [u8; 12] = combined_key[32..44].try_into()?;
        Self::try_new(key, nonce)
    }
}

impl KeyGenerator for ChaCha20Poly1305Cipher {
    fn generate() -> Result<Vec<Vec<u8>>> {
        let key = ChaCha20Poly1305::generate_key(&mut OsRng);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        Ok(vec![key.to_vec(), nonce.to_vec()])
    }
}

pub fn process_text_sign(input: &str, key: &str, format: TextSignFormat) -> Result<String> {
    let mut reader = get_reader(input)?;

    let signed = match format {
        TextSignFormat::Blake3 => {
            let signer = Blake3::load(key)?;
            signer.sign(&mut reader)?
        }
        TextSignFormat::Ed25519 => {
            let signer = Ed25519Signer::load(key)?;
            signer.sign(&mut reader)?
        }
        _ => anyhow::bail!("Unsupported format {}", format),
    };

    let signed = URL_SAFE_NO_PAD.encode(signed);
    Ok(signed)
}

pub fn process_text_verify(
    input: &str,
    key: &str,
    format: TextSignFormat,
    sig: &str,
) -> Result<bool> {
    let mut reader = get_reader(input)?;

    let sig = URL_SAFE_NO_PAD.decode(sig)?;
    let verified = match format {
        TextSignFormat::Blake3 => {
            let verifier = Blake3::load(key)?;
            verifier.verify(&mut reader, &sig)?
        }
        TextSignFormat::Ed25519 => {
            let verifier = Ed25519Verifier::load(key)?;
            verifier.verify(&mut reader, &sig)?
        }
        _ => anyhow::bail!("Unsupported format {}", format),
    };

    Ok(verified)
}

pub fn process_text_encrypt(input: &str, key: &str, format: TextSignFormat) -> Result<String> {
    let mut reader = get_reader(input)?;

    let encrypted = match format {
        TextSignFormat::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305Cipher::load(key)?;
            cipher.encrypt(&mut reader)?
        }
        _ => anyhow::bail!("Unsupported format {}", format),
    };

    Ok(String::from_utf8(encrypted)?)
}

pub fn process_text_decrypt(input: &str, key: &str, format: TextSignFormat) -> Result<String> {
    let mut reader = get_reader(input)?;

    let decrypted = match format {
        TextSignFormat::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305Cipher::load(key)?;
            cipher.decrypt(&mut reader)?
        }
        _ => anyhow::bail!("Unsupported format {}", format),
    };

    Ok(String::from_utf8(decrypted)?)
}

pub fn process_text_generate(format: TextSignFormat, output: &Path) -> Result<()> {
    match format {
        TextSignFormat::Blake3 => {
            let key = Blake3::generate()?;
            let path = output.join("blake3.txt");
            fs::write(path, &key[0])?;
        }
        TextSignFormat::Ed25519 => {
            let key = Ed25519Signer::generate()?;
            fs::write(output.join("ed25519.sk"), &key[0])?;
            fs::write(output.join("ed25519.pk"), &key[1])?;
        }
        TextSignFormat::ChaCha20Poly1305 => {
            let key = ChaCha20Poly1305Cipher::generate()?;
            let mut combined_key = Vec::new();
            combined_key.extend(&key[0]);
            combined_key.extend(&key[1]);
            fs::write(output.join("chacha20poly1305.txt"), &combined_key)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_sign_verify() -> Result<()> {
        let blake3 = Blake3::load("fixtures/blake3.txt")?;
        let reader = b"Hello World!";
        let sig = blake3.sign(&mut &reader[..])?;
        assert!(blake3.verify(&mut &reader[..], &sig)?);

        Ok(())
    }

    #[test]
    fn test_ed25519_sign_verify() -> Result<()> {
        let signer = Ed25519Signer::load("fixtures/ed25519.sk")?;
        let verifier = Ed25519Verifier::load("fixtures/ed25519.pk")?;

        let reader = b"Hello World!";
        let sig = signer.sign(&mut &reader[..])?;
        assert!(verifier.verify(&mut &reader[..], &sig)?);

        Ok(())
    }

    #[test]
    fn test_chacha20poly1305_encrypt_decrypt() -> Result<()> {
        let cipher: ChaCha20Poly1305Cipher =
            ChaCha20Poly1305Cipher::load("fixtures/chacha20poly1305.txt")?;
        let reader = b"Hello World!";
        let encrypted = cipher.encrypt(&mut &reader[..])?;
        let decrypted = cipher.decrypt(&mut &encrypted[..])?;
        assert_eq!(reader, decrypted.as_slice());

        Ok(())
    }
}
