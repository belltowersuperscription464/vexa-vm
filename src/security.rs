//! Authentication and secret-at-rest primitives.
//!
//! Bearer credentials are opaque random values. Only their SHA-256 digests are
//! persisted. VM passwords and other recoverable secrets use envelope
//! encryption: every value receives a random data-encryption key (DEK), and the
//! configured master key (KEK) encrypts that DEK with AES-256-GCM.

use std::fmt;

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Algorithm, Argon2, Params, Version,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::{AppError, AppResult};

const NONCE_LEN: usize = 12;
const DATA_KEY_LEN: usize = 32;
const TOKEN_BYTES: usize = 32;
const MAX_SECRET_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
pub struct Security {
    master_key: [u8; DATA_KEY_LEN],
}

impl fmt::Debug for Security {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Security")
            .field("master_key", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone)]
pub struct IssuedToken {
    secret: String,
    hash: [u8; 32],
    prefix: String,
}

impl IssuedToken {
    /// The bearer value. Return it once to the caller and never log it.
    pub fn expose(&self) -> &str {
        &self.secret
    }

    pub const fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    /// A non-secret identifier suitable for API-key listings and audit logs.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    pub fn into_secret(self) -> String {
        self.secret
    }

    pub fn into_parts(self) -> (String, [u8; 32], String) {
        (self.secret, self.hash, self.prefix)
    }
}

impl fmt::Debug for IssuedToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedToken")
            .field("secret", &"[REDACTED]")
            .field("hash", &"[REDACTED]")
            .field("prefix", &self.prefix)
            .finish()
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct EnvelopeV1 {
    version: u8,
    algorithm: String,
    wrapped_key_nonce: String,
    wrapped_key: String,
    data_nonce: String,
    ciphertext: String,
}

impl Security {
    pub const fn new(master_key: [u8; DATA_KEY_LEN]) -> Self {
        Self { master_key }
    }

    /// Encrypt a recoverable secret and bind it to a stable database context,
    /// such as `vm:<uuid>:password`. Moving the envelope to another context
    /// will make authentication fail.
    pub fn encrypt_secret(&self, plaintext: &str, context: &str) -> AppResult<String> {
        validate_context(context)?;
        if plaintext.len() > MAX_SECRET_BYTES {
            return Err(AppError::Validation("secret is too large".into()));
        }

        let mut data_key = [0_u8; DATA_KEY_LEN];
        let mut wrapped_key_nonce = [0_u8; NONCE_LEN];
        let mut data_nonce = [0_u8; NONCE_LEN];
        OsRng.fill_bytes(&mut data_key);
        OsRng.fill_bytes(&mut wrapped_key_nonce);
        OsRng.fill_bytes(&mut data_nonce);

        let result = (|| {
            let key_cipher = Aes256Gcm::new_from_slice(&self.master_key)
                .map_err(|_| crypto_error("invalid master key"))?;
            let data_cipher =
                Aes256Gcm::new_from_slice(&data_key).map_err(|_| crypto_error("invalid data key"))?;

            let wrapped_key = key_cipher
                .encrypt(
                    Nonce::from_slice(&wrapped_key_nonce),
                    Payload {
                        msg: &data_key,
                        aad: &envelope_aad("wrapped-key", context),
                    },
                )
                .map_err(|_| crypto_error("could not wrap data key"))?;
            let ciphertext = data_cipher
                .encrypt(
                    Nonce::from_slice(&data_nonce),
                    Payload {
                        msg: plaintext.as_bytes(),
                        aad: &envelope_aad("ciphertext", context),
                    },
                )
                .map_err(|_| crypto_error("could not encrypt secret"))?;

            let envelope = EnvelopeV1 {
                version: 1,
                algorithm: "AES-256-GCM+AES-256-GCM".into(),
                wrapped_key_nonce: URL_SAFE_NO_PAD.encode(wrapped_key_nonce),
                wrapped_key: URL_SAFE_NO_PAD.encode(wrapped_key),
                data_nonce: URL_SAFE_NO_PAD.encode(data_nonce),
                ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
            };
            serde_json::to_string(&envelope).map_err(|_| crypto_error("could not encode encrypted envelope"))
        })();

        // Avoid retaining a plaintext DEK for longer than the operation.
        data_key.fill(0);
        result
    }

    pub fn decrypt_secret(&self, encoded: &str, context: &str) -> AppResult<String> {
        validate_context(context)?;
        if encoded.len() > MAX_SECRET_BYTES * 2 {
            return Err(crypto_error("encrypted envelope is too large"));
        }

        let envelope: EnvelopeV1 =
            serde_json::from_str(encoded).map_err(|_| crypto_error("encrypted envelope is malformed"))?;
        if envelope.version != 1 || envelope.algorithm != "AES-256-GCM+AES-256-GCM" {
            return Err(crypto_error("encrypted envelope version is unsupported"));
        }

        let wrapped_nonce = decode_fixed::<NONCE_LEN>(&envelope.wrapped_key_nonce, "wrapped-key nonce")?;
        let data_nonce = decode_fixed::<NONCE_LEN>(&envelope.data_nonce, "data nonce")?;
        let wrapped_key = decode_field(&envelope.wrapped_key, "wrapped key")?;
        let ciphertext = decode_field(&envelope.ciphertext, "ciphertext")?;

        let key_cipher =
            Aes256Gcm::new_from_slice(&self.master_key).map_err(|_| crypto_error("invalid master key"))?;
        let mut data_key = key_cipher
            .decrypt(
                Nonce::from_slice(&wrapped_nonce),
                Payload {
                    msg: &wrapped_key,
                    aad: &envelope_aad("wrapped-key", context),
                },
            )
            .map_err(|_| crypto_error("encrypted secret authentication failed"))?;
        if data_key.len() != DATA_KEY_LEN {
            data_key.fill(0);
            return Err(crypto_error("encrypted data key has the wrong length"));
        }

        let result = (|| {
            let data_cipher = Aes256Gcm::new_from_slice(&data_key)
                .map_err(|_| crypto_error("invalid decrypted data key"))?;
            let plaintext = data_cipher
                .decrypt(
                    Nonce::from_slice(&data_nonce),
                    Payload {
                        msg: &ciphertext,
                        aad: &envelope_aad("ciphertext", context),
                    },
                )
                .map_err(|_| crypto_error("encrypted secret authentication failed"))?;
            String::from_utf8(plaintext).map_err(|_| crypto_error("encrypted secret is not valid UTF-8"))
        })();

        data_key.fill(0);
        result
    }

    pub fn issue_session_token(&self) -> IssuedToken {
        issue_token("vxs")
    }

    pub fn issue_csrf_token(&self) -> IssuedToken {
        issue_token("vxcsrf")
    }

    pub fn issue_api_key(&self) -> IssuedToken {
        issue_token("vxa")
    }

    pub fn issue_customer_token(&self) -> IssuedToken {
        issue_token("vxc")
    }

    pub fn issue_customer_session_token(&self) -> IssuedToken {
        issue_token("vxcs")
    }

    pub fn issue_vnc_link_token(&self) -> IssuedToken {
        issue_token("vxv")
    }

    pub fn issue_vnc_session_token(&self) -> IssuedToken {
        issue_token("vxvs")
    }
}

/// Hash an opaque bearer token before any database lookup or insert.
pub fn hash_token(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// Stable associated-data context for a VM's recoverable login password.
pub fn vm_password_context(vm_id: &str) -> String {
    format!("vm:{vm_id}:password")
}

/// Stable associated-data context for a VM's Vexa Guest Tools channel key.
pub fn vm_guest_tools_secret_context(vm_id: &str) -> String {
    format!("vm:{vm_id}:guest-tools")
}

/// Generation-bound associated-data context for a staged Vexa Guest Tools
/// channel key. A pending envelope cannot be moved to a different VM or
/// promoted under a different generation.
pub fn vm_guest_tools_pending_secret_context(vm_id: &str, generation: &str) -> String {
    format!("vm:{vm_id}:guest-tools:pending:{generation}")
}

/// Constant-time comparison for a presented token and a persisted digest.
pub fn verify_token(token: &str, expected_hash: &[u8]) -> bool {
    if expected_hash.len() != 32 {
        return false;
    }
    let actual = hash_token(token);
    bool::from(actual.as_slice().ct_eq(expected_hash))
}

pub fn validate_admin_password(password: &str) -> AppResult<()> {
    let length = password.chars().count();
    if length < 12 {
        return Err(AppError::Validation(
            "admin passwords must contain at least 12 characters".into(),
        ));
    }
    if password.len() > 4096 {
        return Err(AppError::Validation("admin password is too long".into()));
    }
    Ok(())
}

/// Create a PHC-formatted Argon2id password hash using 64 MiB, three passes,
/// and one lane. The encoded string includes the parameters and random salt.
pub fn hash_password(password: &str) -> AppResult<String> {
    validate_admin_password(password)?;
    let mut salt_bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut salt_bytes);
    let salt =
        SaltString::encode_b64(&salt_bytes).map_err(|_| crypto_error("could not encode password salt"))?;
    argon2id()?
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| crypto_error("could not hash password"))
}

pub fn verify_password(password: &str, encoded_hash: &str) -> AppResult<bool> {
    if password.len() > 4096 || encoded_hash.len() > 4096 {
        return Ok(false);
    }
    let parsed =
        PasswordHash::new(encoded_hash).map_err(|_| crypto_error("stored password hash is malformed"))?;
    Ok(argon2id()?.verify_password(password.as_bytes(), &parsed).is_ok())
}

fn argon2id() -> AppResult<Argon2<'static>> {
    let params =
        Params::new(64 * 1024, 3, 1, Some(32)).map_err(|_| crypto_error("invalid Argon2id parameters"))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

fn issue_token(kind: &str) -> IssuedToken {
    let mut random = [0_u8; TOKEN_BYTES];
    OsRng.fill_bytes(&mut random);
    let secret = format!("{kind}_{}", URL_SAFE_NO_PAD.encode(random));
    let hash = hash_token(&secret);
    let visible = secret.chars().take(kind.len() + 1 + 8).collect::<String>();
    IssuedToken {
        secret,
        hash,
        prefix: visible,
    }
}

fn validate_context(context: &str) -> AppResult<()> {
    if context.is_empty() || context.len() > 512 {
        return Err(AppError::Validation(
            "encryption context must contain between 1 and 512 bytes".into(),
        ));
    }
    Ok(())
}

fn envelope_aad(purpose: &str, context: &str) -> Vec<u8> {
    format!("vexa-vm/envelope/v1/{purpose}\0{context}").into_bytes()
}

fn decode_field(encoded: &str, field: &str) -> AppResult<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| crypto_error(&format!("encrypted {field} is malformed")))
}

fn decode_fixed<const N: usize>(encoded: &str, field: &str) -> AppResult<[u8; N]> {
    decode_field(encoded, field)?
        .try_into()
        .map_err(|_| crypto_error(&format!("encrypted {field} has the wrong length")))
}

fn crypto_error(message: &str) -> AppError {
    AppError::Internal(format!("cryptographic operation failed: {message}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_round_trip_and_context_binding() {
        let security = Security::new([9_u8; 32]);
        let envelope = security
            .encrypt_secret("correct horse battery staple", "vm:123:password")
            .unwrap();
        assert!(!envelope.contains("correct horse"));
        assert_eq!(
            security.decrypt_secret(&envelope, "vm:123:password").unwrap(),
            "correct horse battery staple"
        );
        assert!(security.decrypt_secret(&envelope, "vm:456:password").is_err());
    }

    #[test]
    fn pending_guest_tools_context_binds_vm_and_generation() {
        let security = Security::new([10_u8; 32]);
        let context = vm_guest_tools_pending_secret_context("vm-123", "generation-1");
        let envelope = security.encrypt_secret("channel-key", &context).unwrap();
        assert_eq!(security.decrypt_secret(&envelope, &context).unwrap(), "channel-key");
        assert!(security
            .decrypt_secret(
                &envelope,
                &vm_guest_tools_pending_secret_context("vm-456", "generation-1"),
            )
            .is_err());
        assert!(security
            .decrypt_secret(
                &envelope,
                &vm_guest_tools_pending_secret_context("vm-123", "generation-2"),
            )
            .is_err());
    }

    #[test]
    fn token_digest_is_stable_and_secret_is_redacted() {
        let issued = Security::new([1_u8; 32]).issue_api_key();
        assert!(verify_token(issued.expose(), issued.hash()));
        assert!(!format!("{issued:?}").contains(issued.expose()));
        assert!(!verify_token("wrong", issued.hash()));
    }

    #[test]
    fn argon2id_password_round_trip() {
        let encoded = hash_password("a genuinely strong password").unwrap();
        assert!(encoded.starts_with("$argon2id$"));
        assert!(verify_password("a genuinely strong password", &encoded).unwrap());
        assert!(!verify_password("the wrong password", &encoded).unwrap());
    }
}
