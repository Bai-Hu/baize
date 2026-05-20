//! AES-256-GCM 密钥加密存储
//!
//! 私钥不以明文存储在 SQLite 中，使用 master secret 通过 AES-256-GCM 加密。
//! Master secret 通过环境变量 `BAIZE_MASTER_SECRET` 或命令行参数传入。

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// 从 master secret 派生 AES-256 密钥
fn derive_key(master_secret: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(master_secret);
    hasher.finalize().into()
}

/// 加密私钥明文
///
/// 输入：PEM 格式私钥明文 + master secret
/// 输出：base64 编码的 `nonce(12) || ciphertext`，可直接存储为字符串
pub fn encrypt_key(plaintext: &str, master_secret: &[u8]) -> Result<String> {
    let key = derive_key(master_secret);
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| Error::Internal(anyhow::anyhow!("AES key init: {}", e)))?;

    // 使用随机 nonce
    let nonce_bytes = generate_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| Error::Internal(anyhow::anyhow!("AES encrypt: {}", e)))?;

    // nonce || ciphertext → base64
    let mut combined = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);

    Ok(BASE64.encode(&combined))
}

/// 解密私钥密文
///
/// 输入：base64 编码的 `nonce(12) || ciphertext` + master secret
/// 输出：PEM 格式私钥明文
pub fn decrypt_key(ciphertext: &str, master_secret: &[u8]) -> Result<String> {
    let key = derive_key(master_secret);
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| Error::Internal(anyhow::anyhow!("AES key init: {}", e)))?;

    let combined = BASE64
        .decode(ciphertext)
        .map_err(|e| Error::Validation(format!("base64 decode: {}", e)))?;

    if combined.len() < 12 {
        return Err(Error::Validation("ciphertext too short".into()));
    }

    let (nonce_bytes, ct) = combined.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ct)
        .map_err(|e| Error::Internal(anyhow::anyhow!("AES decrypt: {}", e)))?;

    String::from_utf8(plaintext)
        .map_err(|e| Error::Validation(format!("plaintext not UTF-8: {}", e)))
}

/// 生成 12 字节密码学安全随机 nonce
fn generate_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).expect("failed to generate random nonce");
    nonce
}

/// 从环境变量获取 master secret
pub fn master_secret_from_env() -> Option<Vec<u8>> {
    std::env::var("BAIZE_MASTER_SECRET").ok().map(|s| s.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let master = b"test-master-secret-12345";
        let plaintext = "-----BEGIN PRIVATE KEY-----\ntest key content\n-----END PRIVATE KEY-----";

        let encrypted = encrypt_key(plaintext, master).unwrap();
        let decrypted = decrypt_key(&encrypted, master).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_produces_different_ciphertexts() {
        let master = b"test-master";
        let plaintext = "same content";

        let c1 = encrypt_key(plaintext, master).unwrap();
        let c2 = encrypt_key(plaintext, master).unwrap();

        // CSPRNG nonce 保证每次加密产生不同密文
        assert_ne!(c1, c2);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let master1 = b"correct-key";
        let master2 = b"wrong-key";
        let plaintext = "secret data";

        let encrypted = encrypt_key(plaintext, master1).unwrap();
        let result = decrypt_key(&encrypted, master2);

        assert!(result.is_err());
    }

    #[test]
    fn decrypt_invalid_base64_fails() {
        let result = decrypt_key("not valid base64!!!", b"key");
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_too_short_fails() {
        let result = decrypt_key("AQID", b"key"); // base64 of [1,2,3] — too short
        assert!(result.is_err());
    }

    #[test]
    fn derive_key_is_deterministic() {
        let k1 = derive_key(b"master");
        let k2 = derive_key(b"master");
        assert_eq!(k1, k2);
    }

    #[test]
    fn derive_key_differs_for_different_secrets() {
        let k1 = derive_key(b"secret-a");
        let k2 = derive_key(b"secret-b");
        assert_ne!(k1, k2);
    }
}
