//! Envelope encryption for the SQLite secret store.
//!
//! A random 256-bit data key (DEK) encrypts every row with AES-256-GCM. A
//! key-encryption key (KEK), read from `[storage] kek_source`, wraps the DEK,
//! and only the wrapped DEK is stored. Rotating the KEK re-wraps the DEK; no
//! row is re-encrypted.
//!
//! Each row's AAD is its path and version, so a ciphertext copied to another
//! path, or given another version number, fails to decrypt. This protects a
//! stolen database file or backup. It does not protect against someone who
//! controls the host running rustguac, which can read the KEK.

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const KEY_LEN: usize = 32;

/// AAD for the wrapped DEK, so a row ciphertext can never pass as one.
const DEK_AAD: &[u8] = b"rustguac-dek-v1";

/// A 256-bit key: the KEK, or the unwrapped DEK.
pub struct Key {
    bytes: Zeroizing<[u8; KEY_LEN]>,
}

impl Key {
    pub fn generate() -> Result<Self, String> {
        let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
        SystemRandom::new()
            .fill(bytes.as_mut())
            .map_err(|_| "no system randomness".to_string())?;
        Ok(Self { bytes })
    }

    /// Parse a key written as 64 hex digits or as base64 of 32 bytes
    /// (surrounding whitespace ignored), e.g. `openssl rand -hex 32`.
    pub fn parse(text: &str) -> Result<Self, String> {
        use base64::Engine as _;
        let text = text.trim();
        let decoded = Zeroizing::new(if text.len() == 2 * KEY_LEN {
            hex::decode(text).map_err(|_| "KEK is not valid hex".to_string())?
        } else {
            base64::engine::general_purpose::STANDARD
                .decode(text)
                .map_err(|_| "KEK is neither 64 hex digits nor base64".to_string())?
        });
        if decoded.len() != KEY_LEN {
            return Err(format!(
                "KEK must be {} bytes, got {}",
                KEY_LEN,
                decoded.len()
            ));
        }
        let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
        bytes.copy_from_slice(&decoded);
        Ok(Self { bytes })
    }

    /// Load the KEK named by `[storage] kek_source`:
    /// `file:<path>`, `env:<VAR>` or `systemd-creds:<name>` (read from
    /// `$CREDENTIALS_DIRECTORY`, as `LoadCredential=`/`LoadCredentialEncrypted=`
    /// provide it). Errors never include key material.
    pub fn load(source: &str) -> Result<Self, String> {
        let (kind, arg) = source.split_once(':').ok_or_else(|| {
            format!(
                "kek_source '{}' needs a kind: file:, env: or systemd-creds:",
                source
            )
        })?;
        let text = Zeroizing::new(match kind {
            "file" => std::fs::read_to_string(arg)
                .map_err(|e| format!("cannot read KEK file {}: {}", arg, e.kind()))?,
            "env" => std::env::var(arg).map_err(|_| format!("KEK env var {} is not set", arg))?,
            "systemd-creds" => {
                let dir = std::env::var("CREDENTIALS_DIRECTORY").map_err(|_| {
                    "CREDENTIALS_DIRECTORY is not set (is the unit using LoadCredential?)"
                        .to_string()
                })?;
                let path = std::path::Path::new(&dir).join(arg);
                std::fs::read_to_string(&path).map_err(|e| {
                    format!("cannot read credential {}: {}", path.display(), e.kind())
                })?
            }
            "aws-kms" => return Err("kek_source aws-kms is not supported yet".into()),
            other => return Err(format!("unknown kek_source kind '{}'", other)),
        });
        Self::parse(&text).map_err(|e| format!("{} (from {}:)", e, kind))
    }

    /// Short fingerprint, stored next to the wrapped DEK so a wrong KEK gets
    /// a clear error rather than a bare decryption failure.
    pub fn id(&self) -> String {
        hex::encode(Sha256::digest(self.bytes.as_ref()))[..16].to_string()
    }

    fn aead(&self) -> LessSafeKey {
        // A 32-byte key is always valid for AES-256-GCM.
        LessSafeKey::new(UnboundKey::new(&AES_256_GCM, self.bytes.as_ref()).unwrap())
    }

    /// Encrypt `plaintext` under this key: returns (nonce, ciphertext + tag).
    pub fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
        let mut nonce = [0u8; NONCE_LEN];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| "no system randomness".to_string())?;
        let mut buf = plaintext.to_vec();
        self.aead()
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad),
                &mut buf,
            )
            .map_err(|_| "encryption failed".to_string())?;
        Ok((nonce.to_vec(), buf))
    }

    /// Decrypt what `seal` produced. Fails if the key, nonce, ciphertext or
    /// AAD differ in any bit.
    pub fn open(
        &self,
        nonce: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        let nonce: [u8; NONCE_LEN] = nonce
            .try_into()
            .map_err(|_| "bad nonce length".to_string())?;
        let mut buf = Zeroizing::new(ciphertext.to_vec());
        let len = self
            .aead()
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad),
                &mut buf,
            )
            .map_err(|_| "decryption failed".to_string())?
            .len();
        buf.truncate(len);
        Ok(buf)
    }

    /// Wrap `dek` under this KEK: returns nonce || ciphertext.
    pub fn wrap(&self, dek: &Key) -> Result<Vec<u8>, String> {
        let (mut nonce, ct) = self.seal(dek.bytes.as_ref(), DEK_AAD)?;
        nonce.extend_from_slice(&ct);
        Ok(nonce)
    }

    /// Unwrap a DEK that `wrap` produced under this KEK.
    pub fn unwrap_dek(&self, wrapped: &[u8]) -> Result<Key, String> {
        if wrapped.len() < NONCE_LEN {
            return Err("wrapped DEK is truncated".into());
        }
        let (nonce, ct) = wrapped.split_at(NONCE_LEN);
        let plain = self.open(nonce, ct, DEK_AAD)?;
        if plain.len() != KEY_LEN {
            return Err("wrapped DEK has the wrong length".into());
        }
        let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
        bytes.copy_from_slice(&plain);
        Ok(Key { bytes })
    }
}

/// AAD binding a row ciphertext to its path and version.
pub fn row_aad(path: &str, version: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(path.len() + 9);
    aad.extend_from_slice(path.as_bytes());
    aad.push(0);
    aad.extend_from_slice(&version.to_be_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kek_parses_hex_and_base64_and_rejects_other_lengths() {
        let hex_key = "ab".repeat(32);
        let a = Key::parse(&format!("  {}\n", hex_key)).unwrap();
        let b = Key::parse("q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s=").unwrap();
        assert_eq!(a.id(), b.id(), "same 32 bytes either way");
        assert!(Key::parse("abcd").is_err());
        assert!(Key::parse(&"ab".repeat(31)).is_err());
        assert!(Key::parse(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn kek_load_errors_never_echo_the_value() {
        std::env::set_var("RUSTGUAC_TEST_BAD_KEK", "not-a-key-secret-material");
        let e = Key::load("env:RUSTGUAC_TEST_BAD_KEK").err().unwrap();
        assert!(!e.contains("secret-material"), "{e}");
        assert!(Key::load("env:RUSTGUAC_TEST_UNSET_KEK").is_err());
        assert!(Key::load("nokind").is_err());
        assert!(Key::load("aws-kms:arn:aws:kms:x").is_err());
    }

    #[test]
    fn seal_open_round_trip_and_aad_binding() {
        let k = Key::generate().unwrap();
        let aad = row_aad("rustguac/shared/a/b", 3);
        let (nonce, ct) = k.seal(b"{\"x\":1}", &aad).unwrap();
        assert_eq!(&k.open(&nonce, &ct, &aad).unwrap()[..], b"{\"x\":1}");
        // Another path, another version, or a flipped bit: all refused.
        assert!(k
            .open(&nonce, &ct, &row_aad("rustguac/shared/a/c", 3))
            .is_err());
        assert!(k
            .open(&nonce, &ct, &row_aad("rustguac/shared/a/b", 2))
            .is_err());
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(k.open(&nonce, &bad, &aad).is_err());
        assert!(Key::generate().unwrap().open(&nonce, &ct, &aad).is_err());
    }

    #[test]
    fn dek_wraps_and_unwraps_only_under_its_kek() {
        let kek = Key::generate().unwrap();
        let dek = Key::generate().unwrap();
        let wrapped = kek.wrap(&dek).unwrap();
        assert_eq!(kek.unwrap_dek(&wrapped).unwrap().id(), dek.id());
        assert!(Key::generate().unwrap().unwrap_dek(&wrapped).is_err());
        assert!(kek.unwrap_dek(&wrapped[..5]).is_err());
    }
}
