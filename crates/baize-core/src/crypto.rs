//! 加密基础设施：可插拔 Provider 架构
//!
//! 五个可替换维度：
//! - KeyEncryption: 密钥加密存储（默认 AES-256-GCM）
//! - KeyExchange: 密钥交换（默认 X25519 ECDH）
//! - KeyDerivation: 密钥派生（默认 HKDF-SHA256）
//! - SessionCipher: 会话加解密（默认 AES-256-GCM）
//! - RequestSigner: 请求签名（默认 Ed25519）
//!
//! 二次开发者实现对应 trait，替换 CryptoProvider 中的字段即可切换算法。

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use hex;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::{Verifier, Signer};

use crate::error::{Error, Result};

// ─── 内部辅助 ───

/// HKDF info 参数，用于密钥加密场景的 domain separation
const KEY_ENCRYPTION_INFO: &[u8] = b"baize-key-encryption-v1";

/// 从 master secret 通过 HKDF-SHA256 派生 AES-256 密钥
fn derive_key(master_secret: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, master_secret);
    let mut key = [0u8; 32];
    hk.expand(KEY_ENCRYPTION_INFO, &mut key)
        .expect("HKDF expand for 32-byte key should never fail");
    key
}

/// 生成 12 字节密码学安全随机 nonce
fn generate_nonce() -> Result<[u8; 12]> {
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| Error::Internal(anyhow::anyhow!("nonce generation failed: {}", e)))?;
    Ok(nonce)
}

// ─── 可插拔 Trait 定义 ───

/// 密钥加密 Provider — 用于 master secret 保护私钥
pub trait KeyEncryption: Send + Sync {
    /// 算法名称（如 "AES-256-GCM"）
    fn algorithm_name(&self) -> &str;

    /// 加密：返回编码后的密文字符串
    fn encrypt(&self, plaintext: &str, master_secret: &[u8]) -> Result<String>;

    /// 解密：从编码后的密文恢复明文
    fn decrypt(&self, ciphertext: &str, master_secret: &[u8]) -> Result<String>;
}

/// 密钥交换 Provider — 用于 ECDH 会话密钥协商
///
/// 输入输出用 PEM 字符串和 Vec<u8>，而非库原生类型。
/// 理由：不同算法实现依赖不同库，库原生类型互不兼容，PEM 字符串是通用交换格式。
pub trait KeyExchange: Send + Sync {
    /// 算法名称（如 "X25519"）
    fn algorithm_name(&self) -> &str;

    /// 生成密钥对，返回 (private_pem, public_pem)
    fn generate_keypair(&self) -> Result<(String, String)>;

    /// 执行 ECDH，返回原始共享密钥字节
    fn diffie_hellman(&self, my_private_pem: &str, peer_public_pem: &str) -> Result<Vec<u8>>;
}

/// 密钥派生 Provider — 从共享密钥派生会话密钥
///
/// 只负责 HKDF expand 这一步。info 的构造（含 session_id + 双方公钥 hex）
/// 是会话协议逻辑，留在 session_ops.rs，不放进 trait。
///
/// **注意**：当前管道代码中 `derive_session_key` 仍直接使用 HKDF（因为 info
/// 构造是协议逻辑）。Phase 2（Protocol Registry）中会话密钥派生将改走此 trait，
/// 届时 info 由 protocol handler 构造后传入。
pub trait KeyDerivation: Send + Sync {
    /// 算法名称（如 "HKDF-SHA256"）
    fn algorithm_name(&self) -> &str;

    /// 派生密钥
    fn derive(&self, shared_secret: &[u8], info: &[u8], output_len: usize) -> Result<Vec<u8>>;
}

/// 会话加解密 Provider — 用于 LNK 会话消息的 E2E 加密
pub trait SessionCipher: Send + Sync {
    /// 算法名称（如 "AES-256-GCM"）
    fn algorithm_name(&self) -> &str;

    /// 加密消息（key: 32 字节，aad: 附加认证数据）
    fn encrypt(&self, key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<String>;

    /// 解密消息
    fn decrypt(&self, key: &[u8], ciphertext: &str, aad: &[u8]) -> Result<Vec<u8>>;
}

/// 请求签名 Provider — 用于 v1/v2 API 签名认证
///
/// 只负责"给定 key 和 message，计算/验证签名"这一步。
/// 签名输入的拼接（signing_input: timestamp+method+path+body）是协议逻辑，
/// 仍然留在 auth.rs，不属于 Provider 职责。
pub trait RequestSigner: Send + Sync {
    /// 算法名称（如 "HMAC-SHA256"、"Ed25519"）
    fn algorithm_name(&self) -> &str;

    /// 签名前缀（如 "hmac-sha256:"、"ed25519:"），用于 compute_signature / verify_signature
    fn signature_prefix(&self) -> &str;

    /// 计算签名（返回 hex 编码）
    ///
    /// 实现者应确保对任意合法 key/message 输入均返回 Ok。
    /// 这是因为调用方（如 `compute_signature`）预期签名不会失败，
    /// 并使用 `.unwrap()` / `.expect()` 处理返回值。
    fn sign(&self, key: &[u8], message: &[u8]) -> Result<String>;

    /// 验证签名（返回 bool 而非 Error，避免时序攻击信息泄露）
    fn verify(&self, key: &[u8], message: &[u8], signature: &str) -> bool;
}

// ─── 默认实现 ───

/// AES-256-GCM 密钥加密（默认）
pub struct Aes256GcmKeyEncryption;

impl KeyEncryption for Aes256GcmKeyEncryption {
    fn algorithm_name(&self) -> &str { "AES-256-GCM" }

    fn encrypt(&self, plaintext: &str, master_secret: &[u8]) -> Result<String> {
        let key = derive_key(master_secret);
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| Error::Internal(anyhow::anyhow!("AES key init: {}", e)))?;

        let nonce_bytes = generate_nonce()?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| Error::Internal(anyhow::anyhow!("AES encrypt: {}", e)))?;

        let mut combined = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&ciphertext);

        Ok(BASE64.encode(&combined))
    }

    fn decrypt(&self, ciphertext: &str, master_secret: &[u8]) -> Result<String> {
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
}

// X25519 PEM 格式常量
const X25519_PRIV_PEM_HEADER: &str = "-----BEGIN X25519 PRIVATE KEY-----";
const X25519_PRIV_PEM_FOOTER: &str = "-----END X25519 PRIVATE KEY-----";
const X25519_PUB_PEM_HEADER: &str = "-----BEGIN X25519 PUBLIC KEY-----";
const X25519_PUB_PEM_FOOTER: &str = "-----END X25519 PUBLIC KEY-----";

/// X25519 密钥交换（默认）
pub struct X25519KeyExchange;

impl KeyExchange for X25519KeyExchange {
    fn algorithm_name(&self) -> &str { "X25519" }

    fn generate_keypair(&self) -> Result<(String, String)> {
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

    fn diffie_hellman(&self, my_private_pem: &str, peer_public_pem: &str) -> Result<Vec<u8>> {
        let my_secret = decode_x25519_private(my_private_pem)?;
        let peer_public = decode_x25519_public(peer_public_pem)?;
        let shared = my_secret.diffie_hellman(&peer_public);
        Ok(shared.as_bytes().to_vec())
    }
}

/// HKDF-SHA256 密钥派生（默认）
pub struct HkdfSha256KeyDerivation;

impl KeyDerivation for HkdfSha256KeyDerivation {
    fn algorithm_name(&self) -> &str { "HKDF-SHA256" }

    fn derive(&self, shared_secret: &[u8], info: &[u8], output_len: usize) -> Result<Vec<u8>> {
        let hk = Hkdf::<Sha256>::new(None, shared_secret);
        let mut output = vec![0u8; output_len];
        hk.expand(info, &mut output)
            .map_err(|e| Error::Internal(anyhow::anyhow!("HKDF expand: {}", e)))?;
        Ok(output)
    }
}

/// AES-256-GCM 会话加解密（默认）
pub struct Aes256GcmSessionCipher;

impl SessionCipher for Aes256GcmSessionCipher {
    fn algorithm_name(&self) -> &str { "AES-256-GCM" }

    fn encrypt(&self, key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<String> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| Error::Internal(anyhow::anyhow!("AES key init: {}", e)))?;

        let nonce_bytes = generate_nonce()?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, aes_gcm::aead::Payload {
                msg: plaintext,
                aad,
            })
            .map_err(|e| Error::Internal(anyhow::anyhow!("AES session encrypt: {}", e)))?;

        let mut combined = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&ciphertext);

        Ok(BASE64.encode(&combined))
    }

    fn decrypt(&self, key: &[u8], ciphertext: &str, aad: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(key)
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
                aad,
            })
            .map_err(|e| Error::Internal(anyhow::anyhow!("AES session decrypt: {}", e)))
    }
}

type HmacSha256 = Hmac<Sha256>;

/// HMAC-SHA256 请求签名（旧版兼容）
pub struct HmacSha256RequestSigner;

impl RequestSigner for HmacSha256RequestSigner {
    fn algorithm_name(&self) -> &str { "HMAC-SHA256" }
    fn signature_prefix(&self) -> &str { "hmac-sha256:" }

    fn sign(&self, key: &[u8], message: &[u8]) -> Result<String> {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
            .expect("HMAC can take key of any size");
        mac.update(message);
        let result = mac.finalize();
        Ok(hex::encode(result.into_bytes()))
    }

    fn verify(&self, key: &[u8], message: &[u8], signature: &str) -> bool {
        let sig_bytes = match hex::decode(signature) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let mut mac = match <HmacSha256 as Mac>::new_from_slice(key) {
            Ok(m) => m,
            Err(_) => return false,
        };
        mac.update(message);
        mac.verify_slice(&sig_bytes).is_ok()
    }
}

/// Ed25519 请求签名（v2 默认）
///
/// 符合 V2_DEV.md Section 4.1：每个 agent 的 IDN_SIGN 密钥为 Ed25519，
/// 签名 = Ed25519 私钥签名，验签 = Ed25519 公钥验证。
pub struct Ed25519RequestSigner;

impl RequestSigner for Ed25519RequestSigner {
    fn algorithm_name(&self) -> &str { "Ed25519" }
    fn signature_prefix(&self) -> &str { "ed25519:" }

    fn sign(&self, key: &[u8], message: &[u8]) -> Result<String> {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(
            key.try_into().map_err(|_| Error::Internal(anyhow::anyhow!(
                "Ed25519 signing key must be exactly 32 bytes"
            )))?,
        );
        let signature = signing_key.sign(message);
        Ok(hex::encode(signature.to_bytes()))
    }

    fn verify(&self, key: &[u8], message: &[u8], signature: &str) -> bool {
        let sig_bytes = match hex::decode(signature) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let sig = match ed25519_dalek::Signature::try_from(sig_bytes.as_slice()) {
            Ok(s) => s,
            Err(_) => return false,
        };
        if key.len() != 32 {
            return false;
        }
        let key_array: [u8; 32] = match key.try_into() {
            Ok(k) => k,
            Err(_) => return false,
        };
        // key 是 32 字节私钥 seed → 推导公钥后验签
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_array);
        let verifying_key = signing_key.verifying_key();
        if verifying_key.verify(message, &sig).is_ok() {
            return true;
        }
        // 也尝试直接作为公钥验签（无私钥场景）
        if let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&key_array) {
            if vk.verify(message, &sig).is_ok() {
                return true;
            }
        }
        false
    }
}

// ─── CryptoProvider 聚合 ───

/// 加密 Provider 聚合 — 持有所有子 Provider
///
/// 二次开发者可以替换任意子 Provider：
/// ```ignore
/// let mut crypto = CryptoProvider::default();
/// crypto.request_signer = Box::new(MyEd25519Signer);
/// ```
///
/// 各子 Provider 的算法名称通过 [`Debug`] 实现可查。
pub struct CryptoProvider {
    pub key_encryption: Box<dyn KeyEncryption>,
    pub key_exchange: Box<dyn KeyExchange>,
    pub key_derivation: Box<dyn KeyDerivation>,
    pub session_cipher: Box<dyn SessionCipher>,
    pub request_signer: Box<dyn RequestSigner>,
}

impl std::fmt::Debug for CryptoProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoProvider")
            .field("key_encryption", &self.key_encryption.algorithm_name())
            .field("key_exchange", &self.key_exchange.algorithm_name())
            .field("key_derivation", &self.key_derivation.algorithm_name())
            .field("session_cipher", &self.session_cipher.algorithm_name())
            .field("request_signer", &self.request_signer.algorithm_name())
            .finish()
    }
}

impl Default for CryptoProvider {
    fn default() -> Self {
        Self {
            key_encryption: Box::new(Aes256GcmKeyEncryption),
            key_exchange: Box::new(X25519KeyExchange),
            key_derivation: Box::new(HkdfSha256KeyDerivation),
            session_cipher: Box::new(Aes256GcmSessionCipher),
            request_signer: Box::new(Ed25519RequestSigner),
        }
    }
}

// ─── 向后兼容的自由函数（薄包装） ───

/// 加密私钥明文（委托 Aes256GcmKeyEncryption）
pub fn encrypt_key(plaintext: &str, master_secret: &[u8]) -> Result<String> {
    Aes256GcmKeyEncryption.encrypt(plaintext, master_secret)
}

/// 解密私钥密文（委托 Aes256GcmKeyEncryption）
pub fn decrypt_key(ciphertext: &str, master_secret: &[u8]) -> Result<String> {
    Aes256GcmKeyEncryption.decrypt(ciphertext, master_secret)
}

/// 生成 X25519 密钥对（委托 X25519KeyExchange）
pub fn generate_x25519_keypair() -> Result<(String, String)> {
    X25519KeyExchange.generate_keypair()
}

/// 生成 Ed25519 密钥对，返回 (PKCS#8 PEM 私钥, hex 公钥)
pub fn generate_ed25519_keypair() -> Result<(String, String)> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)
        .map_err(|e| Error::Internal(anyhow::anyhow!("rng: {}", e)))?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    // 编码为 PKCS#8 PEM
    let pem = signing_key.to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
        .map_err(|e| Error::Internal(anyhow::anyhow!("PKCS8 PEM encode: {}", e)))?;
    let pub_hex = hex::encode(verifying_key.to_bytes());

    Ok((pem.to_string(), pub_hex))
}

// ─── 公共工具函数 ───

/// 从环境变量获取 master secret
///
/// 当 `BAIZE_MASTER_SECRET` 未设置时返回 None，所有私钥将以明文存储。
pub fn master_secret_from_env() -> Option<Vec<u8>> {
    match std::env::var("BAIZE_MASTER_SECRET") {
        Ok(s) => Some(s.into_bytes()),
        Err(_) => {
            eprintln!("[WARN] BAIZE_MASTER_SECRET not set — private keys will be stored in plaintext");
            None
        }
    }
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
    let info = format!(
        "baize-session-key/{}/{}:{}",
        session_id,
        hex::encode(my_pub.as_bytes()),
        hex::encode(peer_pub.as_bytes()),
    );
    let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
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
    Aes256GcmSessionCipher.encrypt(session_key, plaintext, session_id.as_bytes())
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
    Aes256GcmSessionCipher.decrypt(session_key, ciphertext, session_id.as_bytes())
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

        let shared_ab = x25519_ecdh(&secret_a, &pub_b);
        let key_ab = derive_session_key(&shared_ab, "sess-wrong", &pub_a, &pub_b).unwrap();

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
        let result = decrypt_session_message(&key, &encrypted, "sess-other");
        assert!(result.is_err());
    }

    // ─── CryptoProvider 测试 ───

    #[test]
    fn crypto_provider_default_key_encryption_roundtrip() {
        let crypto = CryptoProvider::default();
        let master = b"test-master";
        let plaintext = "test-key-data";
        let ct = crypto.key_encryption.encrypt(plaintext, master).unwrap();
        let pt = crypto.key_encryption.decrypt(&ct, master).unwrap();
        assert_eq!(pt, plaintext);
        assert_eq!(crypto.key_encryption.algorithm_name(), "AES-256-GCM");
    }

    #[test]
    fn crypto_provider_default_key_exchange_ecdh() {
        let crypto = CryptoProvider::default();
        let (priv_a, pub_a) = crypto.key_exchange.generate_keypair().unwrap();
        let (priv_b, pub_b) = crypto.key_exchange.generate_keypair().unwrap();
        let shared_ab = crypto.key_exchange.diffie_hellman(&priv_a, &pub_b).unwrap();
        let shared_ba = crypto.key_exchange.diffie_hellman(&priv_b, &pub_a).unwrap();
        assert_eq!(shared_ab, shared_ba);
        assert_eq!(crypto.key_exchange.algorithm_name(), "X25519");
    }

    #[test]
    fn crypto_provider_default_key_derivation() {
        let crypto = CryptoProvider::default();
        let secret = b"shared-secret-12345678901234567890";
        let info = b"test-info";
        let k1 = crypto.key_derivation.derive(secret, info, 32).unwrap();
        let k2 = crypto.key_derivation.derive(secret, info, 32).unwrap();
        assert_eq!(k1, k2);
        assert_eq!(k1.len(), 32);
        assert_eq!(crypto.key_derivation.algorithm_name(), "HKDF-SHA256");
    }

    #[test]
    fn crypto_provider_default_session_cipher_roundtrip() {
        let crypto = CryptoProvider::default();
        let key = [0u8; 32];
        let plaintext = b"hello world";
        let aad = b"session-1";
        let ct = crypto.session_cipher.encrypt(&key, plaintext, aad).unwrap();
        let pt = crypto.session_cipher.decrypt(&key, &ct, aad).unwrap();
        assert_eq!(pt, plaintext);
        assert_eq!(crypto.session_cipher.algorithm_name(), "AES-256-GCM");
    }

    #[test]
    fn crypto_provider_default_request_signer() {
        let crypto = CryptoProvider::default();
        let key = [42u8; 32]; // Ed25519 需要 32 字节密钥
        let msg = b"test-message";
        let sig = crypto.request_signer.sign(&key, msg).unwrap();
        assert!(crypto.request_signer.verify(&key, msg, &sig));
        assert!(!crypto.request_signer.verify(&key, b"wrong", &sig));
        assert_eq!(crypto.request_signer.algorithm_name(), "Ed25519");
    }

    #[test]
    fn custom_key_encryption_provider() {
        struct XorEncryption;
        impl KeyEncryption for XorEncryption {
            fn algorithm_name(&self) -> &str { "XOR-mock" }
            fn encrypt(&self, plaintext: &str, master_secret: &[u8]) -> Result<String> {
                let encrypted: Vec<u8> = plaintext.bytes()
                    .enumerate()
                    .map(|(i, b)| b ^ master_secret[i % master_secret.len()])
                    .collect();
                Ok(BASE64.encode(&encrypted))
            }
            fn decrypt(&self, ciphertext: &str, master_secret: &[u8]) -> Result<String> {
                let bytes = BASE64.decode(ciphertext)
                    .map_err(|e| Error::Validation(format!("base64: {}", e)))?;
                let decrypted: Vec<u8> = bytes.iter()
                    .enumerate()
                    .map(|(i, &b)| b ^ master_secret[i % master_secret.len()])
                    .collect();
                String::from_utf8(decrypted).map_err(|e| Error::Validation(format!("utf8: {}", e)))
            }
        }

        let mut crypto = CryptoProvider::default();
        crypto.key_encryption = Box::new(XorEncryption);
        assert_eq!(crypto.key_encryption.algorithm_name(), "XOR-mock");

        let ct = crypto.key_encryption.encrypt("hello", b"key").unwrap();
        let pt = crypto.key_encryption.decrypt(&ct, b"key").unwrap();
        assert_eq!(pt, "hello");
    }

    #[test]
    fn default_matches_current_behavior() {
        let crypto = CryptoProvider::default();
        let master = b"master-secret-test";

        // KeyEncryption: nonce 随机，密文不同，但解密结果一致
        let ct_default = crypto.key_encryption.encrypt("test", master).unwrap();
        let ct_fn = encrypt_key("test", master).unwrap();
        assert_eq!(crypto.key_encryption.decrypt(&ct_default, master).unwrap(), "test");
        assert_eq!(decrypt_key(&ct_fn, master).unwrap(), "test");

        // KeyExchange: PEM 格式一致
        let (priv_a, pub_a) = crypto.key_exchange.generate_keypair().unwrap();
        assert!(priv_a.contains("X25519 PRIVATE KEY"));
        assert!(pub_a.contains("X25519 PUBLIC KEY"));

        // RequestSigner: Ed25519 签名（128 hex chars = 64 bytes）
        let key = [0xabu8; 32];
        let sig = crypto.request_signer.sign(&key, b"msg").unwrap();
        assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(sig.len(), 128); // Ed25519 签名 = 64 bytes = 128 hex chars
    }
}
