//! Ed25519 请求签名认证（Phase 2 → V2 升级）
//!
//! v2 写操作必须携带有效签名，签名方案：Ed25519。
//! 签名输入：`timestamp\nmethod\npath\nbody`
//! 密钥来源：INF-KMS IDN_SIGN 用途密钥（Ed25519 私钥）。
//!
//! v1 兼容：仍支持 HMAC-SHA256 签名（通过 HmacSha256RequestSigner）。

use baize_core::crypto::RequestSigner;
use baize_core::error::Error;
use ed25519_dalek::pkcs8::DecodePrivateKey;

/// 签名时间戳窗口（秒）
const TIMESTAMP_WINDOW_SECS: i64 = 300; // ±5 分钟

/// HMAC-SHA256 签名前缀（v1 兼容，v2 不允许）
const HMAC_SIGNATURE_PREFIX: &str = "hmac-sha256:";

/// 构造签名输入
///
/// 格式：`timestamp\nmethod\npath\nbody`
pub fn signing_input(timestamp: &str, method: &str, path: &str, body: &str) -> String {
    format!("{}\n{}\n{}\n{}", timestamp, method, path, body)
}

/// 计算请求签名
///
/// 返回 `<prefix><hex>` 格式字符串，prefix 由 signer 的 `signature_prefix()` 决定。
pub fn compute_signature(
    signer: &dyn RequestSigner,
    key: &[u8],
    timestamp: &str,
    method: &str,
    path: &str,
    body: &str,
) -> String {
    let input = signing_input(timestamp, method, path, body);
    let sig = signer.sign(key, input.as_bytes()).unwrap();
    format!("{}{}", signer.signature_prefix(), sig)
}

/// 验证请求签名
///
/// 始终计算签名后再判断结果，避免通过响应时间区分失败阶段。
/// 统一返回 `SignatureInvalid`，不在错误消息中泄露具体失败原因。
///
/// 自动识别签名前缀，分派到对应 signer 验证逻辑。
/// v1 路径（allow_hmac=true）：接受 ed25519: 和 hmac-sha256: 前缀
/// v2 路径（allow_hmac=false）：只接受 ed25519: 前缀
pub fn verify_signature(
    signer: &dyn RequestSigner,
    key: &[u8],
    timestamp: &str,
    method: &str,
    path: &str,
    body: &str,
    provided_signature: &str,
    allow_hmac: bool,
) -> Result<(), Error> {
    // 解析签名格式 — 识别前缀
    let sig_hex = if let Some(hex) = provided_signature.strip_prefix(signer.signature_prefix()) {
        hex
    } else if allow_hmac && provided_signature.starts_with(HMAC_SIGNATURE_PREFIX) {
        provided_signature.strip_prefix(HMAC_SIGNATURE_PREFIX).unwrap()
    } else {
        return Err(Error::SignatureInvalid("authentication failed".into()));
    };

    // 始终计算签名（避免通过计算耗时可判断签名格式是否正确）
    let input = signing_input(timestamp, method, path, body);

    // 同时检查签名和时间戳有效性，统一返回相同错误类型
    let sig_ok = signer.verify(key, input.as_bytes(), sig_hex);
    let ts_ok = is_timestamp_valid(timestamp);

    if !sig_ok || !ts_ok {
        return Err(Error::SignatureInvalid("authentication failed".into()));
    }

    Ok(())
}

/// 检查时间戳是否在 ±5 分钟窗口内（内部使用，返回 bool 避免泄露信息）
fn is_timestamp_valid(timestamp: &str) -> bool {
    let ts = match chrono::DateTime::parse_from_rfc3339(timestamp) {
        Ok(t) => t,
        Err(_) => return false,
    };
    let now = chrono::Utc::now();
    let diff = (now - ts.with_timezone(&chrono::Utc)).num_seconds().abs();
    diff <= TIMESTAMP_WINDOW_SECS
}

/// 验证时间戳是否在 ±5 分钟窗口内（公开接口，用于单独校验时间戳）
pub fn verify_timestamp(timestamp: &str) -> Result<(), Error> {
    if !is_timestamp_valid(timestamp) {
        return Err(Error::ExpiredTimestamp("authentication failed".into()));
    }
    Ok(())
}

/// 从 agent-key blob 内容提取签名密钥
///
/// Ed25519 模式：解析 PKCS#8 PEM 得到 32 字节私钥 seed。
/// HMAC-SHA256 兼容模式：将 PEM 的 SHA-256 hash 作为密钥。
pub fn extract_signing_key(key_pem: &str) -> Vec<u8> {
    // 尝试解析为 Ed25519 PKCS#8 PEM（优先）
    if let Ok(signing_key) = ed25519_dalek::SigningKey::from_pkcs8_pem(key_pem) {
        return signing_key.to_bytes().to_vec();
    }
    // 回退：SHA-256 hash（HMAC-SHA256 兼容）
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(key_pem.as_bytes());
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_signer() -> Box<dyn RequestSigner> {
        Box::new(baize_core::crypto::HmacSha256RequestSigner)
    }

    fn test_key() -> Vec<u8> {
        b"test-secret-key-for-signing".to_vec()
    }

    fn now_timestamp() -> String {
        chrono::Utc::now().to_rfc3339()
    }

    #[test]
    fn compute_and_verify_signature() {
        let signer = test_signer();
        let key = test_key();
        let ts = now_timestamp();
        let sig = compute_signature(signer.as_ref(), &key, &ts, "POST", "/api/v1/intents", r#"{"goal":"test"}"#);

        assert!(sig.starts_with("hmac-sha256:"));

        let result = verify_signature(
            signer.as_ref(), &key, &ts, "POST", "/api/v1/intents", r#"{"goal":"test"}"#, &sig,
            true,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn wrong_key_fails() {
        let signer = test_signer();
        let key1 = test_key();
        let key2 = b"wrong-key".to_vec();
        let ts = now_timestamp();
        let sig = compute_signature(signer.as_ref(), &key1, &ts, "POST", "/api/v1/intents", "body");

        let result = verify_signature(
            signer.as_ref(), &key2, &ts, "POST", "/api/v1/intents", "body", &sig,
            true,
        );
        assert!(result.is_err());
    }

    #[test]
    fn wrong_body_fails() {
        let signer = test_signer();
        let key = test_key();
        let ts = now_timestamp();
        let sig = compute_signature(signer.as_ref(), &key, &ts, "POST", "/api/v1/intents", "original");

        let result = verify_signature(
            signer.as_ref(), &key, &ts, "POST", "/api/v1/intents", "tampered", &sig,
            true,
        );
        assert!(result.is_err());
    }

    #[test]
    fn expired_timestamp_fails() {
        let signer = test_signer();
        let key = test_key();
        let past = (chrono::Utc::now() - chrono::Duration::minutes(10)).to_rfc3339();
        let sig = compute_signature(signer.as_ref(), &key, &past, "POST", "/api/v1/intents", "body");

        let result = verify_signature(
            signer.as_ref(), &key, &past, "POST", "/api/v1/intents", "body", &sig,
            true,
        );
        assert!(result.is_err());
        // verify_signature 统一返回 SignatureInvalid，不区分时间戳过期和签名错误
        match result {
            Err(Error::SignatureInvalid(_)) => {}
            other => panic!("expected SignatureInvalid, got {:?}", other),
        }
    }

    #[test]
    fn invalid_signature_format_fails() {
        let signer = test_signer();
        let key = test_key();
        let ts = now_timestamp();

        let result = verify_signature(
            signer.as_ref(), &key, &ts, "POST", "/api/v1/intents", "body", "not-valid-format",
            true,
        );
        assert!(result.is_err());
    }

    #[test]
    fn timestamp_within_window_ok() {
        let signer = test_signer();
        let key = test_key();
        // 4 分钟前 → 在 5 分钟窗口内
        let near_past = (chrono::Utc::now() - chrono::Duration::minutes(4)).to_rfc3339();
        let sig = compute_signature(signer.as_ref(), &key, &near_past, "GET", "/api/v1/agents", "");

        let result = verify_signature(
            signer.as_ref(), &key, &near_past, "GET", "/api/v1/agents", "", &sig,
            true,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn signing_input_format() {
        let input = signing_input("2026-05-20T10:00:00Z", "POST", "/api/v1/intents", r#"{"a":1}"#);
        assert_eq!(input, "2026-05-20T10:00:00Z\nPOST\n/api/v1/intents\n{\"a\":1}");
    }

    #[test]
    fn extract_signing_key_deterministic() {
        let k1 = extract_signing_key("-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----");
        let k2 = extract_signing_key("-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----");
        assert_eq!(k1, k2);
    }

    #[test]
    fn extract_signing_key_differs_for_different_keys() {
        let k1 = extract_signing_key("key-a");
        let k2 = extract_signing_key("key-b");
        assert_ne!(k1, k2);
    }

    // ─── Ed25519 签名测试 ───

    fn ed25519_signer() -> Box<dyn RequestSigner> {
        Box::new(baize_core::crypto::Ed25519RequestSigner)
    }

    fn ed25519_key() -> Vec<u8> {
        [42u8; 32].to_vec()
    }

    #[test]
    fn ed25519_compute_and_verify() {
        let signer = ed25519_signer();
        let key = ed25519_key();
        let ts = now_timestamp();
        let sig = compute_signature(signer.as_ref(), &key, &ts, "POST", "/api/v2/blobs", r#"{"data":1}"#);

        assert!(sig.starts_with("ed25519:"));

        let result = verify_signature(
            signer.as_ref(), &key, &ts, "POST", "/api/v2/blobs", r#"{"data":1}"#, &sig,
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn ed25519_wrong_key_fails() {
        let signer = ed25519_signer();
        let key1 = ed25519_key();
        let key2 = [99u8; 32].to_vec();
        let ts = now_timestamp();
        let sig = compute_signature(signer.as_ref(), &key1, &ts, "POST", "/api/v2/blobs", "body");

        let result = verify_signature(
            signer.as_ref(), &key2, &ts, "POST", "/api/v2/blobs", "body", &sig,
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn ed25519_v2_rejects_hmac_prefix() {
        let signer = ed25519_signer();
        let key = ed25519_key();
        let ts = now_timestamp();
        // 伪造 HMAC 前缀的签名 → v2 应拒绝
        let result = verify_signature(
            signer.as_ref(), &key, &ts, "POST", "/api/v2/blobs", "body", "hmac-sha256:deadbeef",
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn ed25519_signature_is_128_hex() {
        let signer = ed25519_signer();
        let key = ed25519_key();
        let ts = now_timestamp();
        let sig = compute_signature(signer.as_ref(), &key, &ts, "POST", "/", "");
        let hex_part = sig.strip_prefix("ed25519:").unwrap();
        assert_eq!(hex_part.len(), 128); // 64 bytes = 128 hex chars
    }
}
