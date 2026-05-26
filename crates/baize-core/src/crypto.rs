//! AES-256-GCM 密钥加密存储
//!
//! 私钥不以明文存储在 SQLite 中，使用 master secret 通过 AES-256-GCM 加密。
//! Master secret 通过环境变量 `BAIZE_MASTER_SECRET` 或命令行参数传入。

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use hex;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

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

    if combined.len() < 28 {
        return Err(Error::Validation("ciphertext too short (min 28: 12 nonce + 16 tag)".into()));
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

// ─── X25519 密钥生成（INF-KMS SESSION 用途） ───

const X25519_PRIV_PEM_HEADER: &str = "-----BEGIN X25519 PRIVATE KEY-----";
const X25519_PRIV_PEM_FOOTER: &str = "-----END X25519 PRIVATE KEY-----";
const X25519_PUB_PEM_HEADER: &str = "-----BEGIN X25519 PUBLIC KEY-----";
const X25519_PUB_PEM_FOOTER: &str = "-----END X25519 PUBLIC KEY-----";

/// 生成 X25519 密钥对用于 ECDH 会话密钥协商
/// 返回 (private_key_pem, public_key_pem)
pub fn generate_x25519_keypair() -> Result<(String, String)> {
    let secret = StaticSecret::random_from_rng(rand_core::OsRng);
    let public = PublicKey::from(&secret);

    let priv_pem = format!(
        "{}\n{}\n{}\n",
        X25519_PRIV_PEM_HEADER,
        BASE64.encode(secret.as_bytes()),
        X25519_PRIV_PEM_FOOTER,
    );
    let pub_pem = format!(
        "{}\n{}\n{}\n",
        X25519_PUB_PEM_HEADER,
        BASE64.encode(public.as_bytes()),
        X25519_PUB_PEM_FOOTER,
    );

    Ok((priv_pem, pub_pem))
}

/// 从 PEM 解码 X25519 私钥
pub fn decode_x25519_private(pem: &str) -> Result<StaticSecret> {
    let b64 = pem
        .lines()
        .find(|l| !l.starts_with('-'))
        .ok_or_else(|| Error::Validation("invalid X25519 PEM: no base64 content".into()))?;
    let bytes = BASE64
        .decode(b64.trim())
        .map_err(|e| Error::Validation(format!("invalid X25519 PEM base64: {}", e)))?;
    if bytes.len() != 32 {
        return Err(Error::Validation(format!(
            "X25519 private key must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    Ok(StaticSecret::from(array))
}

/// 从 PEM 解码 X25519 公钥
pub fn decode_x25519_public(pem: &str) -> Result<PublicKey> {
    let b64 = pem
        .lines()
        .find(|l| !l.starts_with('-'))
        .ok_or_else(|| Error::Validation("invalid X25519 public PEM: no base64 content".into()))?;
    let bytes = BASE64
        .decode(b64.trim())
        .map_err(|e| Error::Validation(format!("invalid X25519 public key base64: {}", e)))?;
    if bytes.len() != 32 {
        return Err(Error::Validation(format!(
            "X25519 public key must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    Ok(PublicKey::from(array))
}

/// X25519 ECDH 密钥协商
///
/// 注意：返回的 SharedSecret 应通过 `derive_session_key` 派生为 session_key 后使用，
/// 不要直接使用原始共享密钥。
pub fn x25519_ecdh(
    my_private: &StaticSecret,
    peer_public: &PublicKey,
) -> x25519_dalek::SharedSecret {
    my_private.diffie_hellman(peer_public)
}

// ─── Phase 3: HKDF 会话密钥派生 + E2E 加解密 ───

/// 从 ECDH 共享密钥通过 HKDF-SHA256 派生 AES-256 会话密钥
///
/// info 包含 session_id + 双方公钥摘要，确保：
/// 1. 不同 session 派生不同密钥
/// 2. 即使 ECDH 共享密钥碰撞，公钥不同也会产生不同 session key
pub fn derive_session_key(
    shared_secret: &x25519_dalek::SharedSecret,
    session_id: &str,
    my_pub: &PublicKey,
    peer_pub: &PublicKey,
) -> Result<[u8; 32]> {
    // info = "baize-session-key/{session_id}/{my_pub_hex}:{peer_pub_hex}"
    // 公钥摘要提供 domain separation，防止 shared secret 碰撞导致 session key 相同
    let info = format!(
        "baize-session-key/{}/{}:{}",
        session_id,
        hex::encode(my_pub.as_bytes()),
        hex::encode(peer_pub.as_bytes()),
    );
    let hk = Hkdf::<Sha256>::new(
        None, // salt = None (ECDH 共享密钥本身已有足够熵)
        shared_secret.as_bytes(),
    );
    let mut session_key = [0u8; 32];
    hk.expand(info.as_bytes(), &mut session_key)
        .map_err(|e| Error::Internal(anyhow::anyhow!("HKDF expand: {}", e)))?;
    Ok(session_key)
}

/// AES-256-GCM 加密会话消息
///
/// session_id 作为 AAD（Additional Authenticated Data），绑定密文到特定 session
/// 输出：base64(nonce_12 || ciphertext)
pub fn encrypt_session_message(
    session_key: &[u8; 32],
    plaintext: &[u8],
    session_id: &str,
) -> Result<String> {
    let cipher = Aes256Gcm::new_from_slice(session_key)
        .map_err(|e| Error::Internal(anyhow::anyhow!("AES key init: {}", e)))?;

    let nonce_bytes = generate_nonce();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, aes_gcm::aead::Payload {
            msg: plaintext,
            aad: session_id.as_bytes(),
        })
        .map_err(|e| Error::Internal(anyhow::anyhow!("AES session encrypt: {}", e)))?;

    let mut combined = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);

    Ok(BASE64.encode(&combined))
}

/// AES-256-GCM 解密会话消息
///
/// 输入：base64(nonce_12 || ciphertext) + session_id（AAD）
/// 输出：解密后的明文
pub fn decrypt_session_message(
    session_key: &[u8; 32],
    ciphertext: &str,
    session_id: &str,
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(session_key)
        .map_err(|e| Error::Internal(anyhow::anyhow!("AES key init: {}", e)))?;

    let combined = BASE64
        .decode(ciphertext)
        .map_err(|e| Error::Validation(format!("base64 decode: {}", e)))?;

    if combined.len() < 28 {
        return Err(Error::Validation("ciphertext too short (min 28: 12 nonce + 16 tag)".into()));
    }

    let (nonce_bytes, ct) = combined.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, aes_gcm::aead::Payload {
            msg: ct,
            aad: session_id.as_bytes(),
        })
        .map_err(|e| Error::Internal(anyhow::anyhow!("AES session decrypt: {}", e)))
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

    #[test]
    fn x25519_keypair_roundtrip() {
        let (priv_pem, pub_pem) = generate_x25519_keypair().unwrap();
        let secret = decode_x25519_private(&priv_pem).unwrap();
        // 私钥 32 字节可恢复公钥
        let _public = PublicKey::from(&secret);
        assert!(priv_pem.contains("X25519 PRIVATE KEY"));
        assert!(pub_pem.contains("X25519 PUBLIC KEY"));
    }

    #[test]
    fn x25519_ecdh_both_sides_match() {
        let (priv_a, pub_a) = generate_x25519_keypair().unwrap();
        let (priv_b, pub_b) = generate_x25519_keypair().unwrap();
        let secret_a = decode_x25519_private(&priv_a).unwrap();
        let secret_b = decode_x25519_private(&priv_b).unwrap();
        let pub_a_decoded = PublicKey::from(&secret_a);
        let pub_b_decoded = PublicKey::from(&secret_b);

        let shared_ab = x25519_ecdh(&secret_a, &pub_b_decoded);
        let shared_ba = x25519_ecdh(&secret_b, &pub_a_decoded);
        assert_eq!(shared_ab.as_bytes(), shared_ba.as_bytes());
    }

    #[test]
    fn x25519_keypair_pem_format() {
        let (priv_pem, pub_pem) = generate_x25519_keypair().unwrap();
        assert!(priv_pem.starts_with("-----BEGIN X25519 PRIVATE KEY-----"));
        assert!(priv_pem.contains("-----END X25519 PRIVATE KEY-----"));
        assert!(pub_pem.starts_with("-----BEGIN X25519 PUBLIC KEY-----"));
        assert!(pub_pem.contains("-----END X25519 PUBLIC KEY-----"));
    }

    // ─── Phase 3: HKDF + session 加解密测试 ───

    #[test]
    fn derive_session_key_deterministic() {
        let (priv_a, _) = generate_x25519_keypair().unwrap();
        let (priv_b, _) = generate_x25519_keypair().unwrap();
        let secret_a = decode_x25519_private(&priv_a).unwrap();
        let secret_b = decode_x25519_private(&priv_b).unwrap();
        let pub_a = PublicKey::from(&secret_a);
        let pub_b = PublicKey::from(&secret_b);

        let shared = x25519_ecdh(&secret_a, &pub_b);
        let k1 = derive_session_key(&shared, "sess-001", &pub_a, &pub_b).unwrap();
        let k2 = derive_session_key(&shared, "sess-001", &pub_a, &pub_b).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn derive_session_key_differs_for_different_session() {
        let (priv_a, _) = generate_x25519_keypair().unwrap();
        let (priv_b, _) = generate_x25519_keypair().unwrap();
        let secret_a = decode_x25519_private(&priv_a).unwrap();
        let secret_b = decode_x25519_private(&priv_b).unwrap();
        let pub_a = PublicKey::from(&secret_a);
        let pub_b = PublicKey::from(&secret_b);

        let shared = x25519_ecdh(&secret_a, &pub_b);
        let k1 = derive_session_key(&shared, "sess-001", &pub_a, &pub_b).unwrap();
        let k2 = derive_session_key(&shared, "sess-002", &pub_a, &pub_b).unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn encrypt_decrypt_session_message_roundtrip() {
        let (priv_a, _) = generate_x25519_keypair().unwrap();
        let (priv_b, _) = generate_x25519_keypair().unwrap();
        let secret_a = decode_x25519_private(&priv_a).unwrap();
        let secret_b = decode_x25519_private(&priv_b).unwrap();
        let pub_a = PublicKey::from(&secret_a);
        let pub_b = PublicKey::from(&secret_b);

        let shared = x25519_ecdh(&secret_a, &pub_b);
        let session_key = derive_session_key(&shared, "sess-roundtrip", &pub_a, &pub_b).unwrap();

        let plaintext = b"hello encrypted world";
        let encrypted = encrypt_session_message(&session_key, plaintext, "sess-roundtrip").unwrap();
        let decrypted = decrypt_session_message(&session_key, &encrypted, "sess-roundtrip").unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_session_wrong_key_fails() {
        let (priv_a, _) = generate_x25519_keypair().unwrap();
        let (priv_b, _) = generate_x25519_keypair().unwrap();
        let (priv_c, _) = generate_x25519_keypair().unwrap();
        let secret_a = decode_x25519_private(&priv_a).unwrap();
        let secret_b = decode_x25519_private(&priv_b).unwrap();
        let secret_c = decode_x25519_private(&priv_c).unwrap();
        let pub_a = PublicKey::from(&secret_a);
        let pub_b = PublicKey::from(&secret_b);
        let pub_c = PublicKey::from(&secret_c);

        // A↔B 共享密钥加密
        let shared_ab = x25519_ecdh(&secret_a, &pub_b);
        let key_ab = derive_session_key(&shared_ab, "sess-wrong", &pub_a, &pub_b).unwrap();

        // A↔C 共享密钥解密（不同密钥）
        let shared_ac = x25519_ecdh(&secret_a, &pub_c);
        let key_ac = derive_session_key(&shared_ac, "sess-wrong", &pub_a, &pub_c).unwrap();

        let encrypted = encrypt_session_message(&key_ab, b"secret", "sess-wrong").unwrap();
        let result = decrypt_session_message(&key_ac, &encrypted, "sess-wrong");
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_session_wrong_aad_fails() {
        let (priv_a, _) = generate_x25519_keypair().unwrap();
        let (priv_b, _) = generate_x25519_keypair().unwrap();
        let secret_a = decode_x25519_private(&priv_a).unwrap();
        let secret_b = decode_x25519_private(&priv_b).unwrap();
        let pub_a = PublicKey::from(&secret_a);
        let pub_b = PublicKey::from(&secret_b);

        let shared = x25519_ecdh(&secret_a, &pub_b);
        let key = derive_session_key(&shared, "sess-aad", &pub_a, &pub_b).unwrap();

        let encrypted = encrypt_session_message(&key, b"msg", "sess-aad").unwrap();
        // 用不同的 session_id（AAD）解密 → 失败
        let result = decrypt_session_message(&key, &encrypted, "sess-other");
        assert!(result.is_err());
    }
}
