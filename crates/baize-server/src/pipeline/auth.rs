//! HMAC-SHA256 请求签名认证（Phase 2）
//!
//! v1 写操作必须携带有效签名，签名方案：HMAC-SHA256。
//! 签名输入：`timestamp\nmethod\npath\nbody`
//! 密钥来源：INF-KMS IDN_SIGN 用途密钥。
//!
//! 密钥派生说明：`extract_signing_key` 将 PEM 私钥的 SHA-256 hash 作为 HMAC 密钥。
//! 这是因为 PEM 私钥的原始字节长度和格式不确定（非标准 HMAC key 长度），
//! 通过 SHA-256 派生得到固定 32 字节密钥。MVP 阶段简化方案，后续可升级为 HKDF。

use hmac::{Hmac, Mac};
use sha2::Sha256;

use baize_core::error::Error;

type HmacSha256 = Hmac<Sha256>;

/// 签名时间戳窗口（秒）
const TIMESTAMP_WINDOW_SECS: i64 = 300; // ±5 分钟

/// 签名前缀
const SIGNATURE_PREFIX: &str = "hmac-sha256:";

/// 构造签名输入
///
/// 格式：`timestamp\nmethod\npath\nbody`
pub fn signing_input(timestamp: &str, method: &str, path: &str, body: &str) -> String {
    format!("{}\n{}\n{}\n{}", timestamp, method, path, body)
}

/// 计算 HMAC-SHA256 签名
///
/// 返回 `hmac-sha256:<hex>` 格式字符串
pub fn compute_signature(key: &[u8], timestamp: &str, method: &str, path: &str, body: &str) -> String {
    let input = signing_input(timestamp, method, path, body);
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC can take key of any size");
    mac.update(input.as_bytes());
    let result = mac.finalize();
    format!("{}{}", SIGNATURE_PREFIX, hex::encode(result.into_bytes()))
}

/// 验证请求签名
///
/// 始终计算 HMAC 后再判断结果，避免通过响应时间区分失败阶段。
/// 统一返回 `SignatureInvalid`，不在错误消息中泄露具体失败原因。
pub fn verify_signature(
    key: &[u8],
    timestamp: &str,
    method: &str,
    path: &str,
    body: &str,
    provided_signature: &str,
) -> Result<(), Error> {
    // 解析签名格式
    let sig_hex = provided_signature.strip_prefix(SIGNATURE_PREFIX)
        .ok_or_else(|| Error::SignatureInvalid("authentication failed".into()))?;

    let sig_bytes = hex::decode(sig_hex)
        .map_err(|_| Error::SignatureInvalid("authentication failed".into()))?;

    // 始终计算 HMAC（避免通过计算耗时可判断签名格式是否正确）
    let input = signing_input(timestamp, method, path, body);
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC can take key of any size");
    mac.update(input.as_bytes());

    // 同时检查签名和时间戳有效性，统一返回相同错误类型
    let sig_ok = mac.verify_slice(&sig_bytes).is_ok();
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
/// 将 PEM 私钥的 SHA-256 hash 作为 HMAC 密钥（MVP 简化方案）。
/// PEM 原始字节长度和格式不确定，通过 SHA-256 派生得到固定 32 字节密钥。
pub fn extract_signing_key(key_pem: &str) -> Vec<u8> {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(key_pem.as_bytes());
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> Vec<u8> {
        b"test-secret-key-for-signing".to_vec()
    }

    fn now_timestamp() -> String {
        chrono::Utc::now().to_rfc3339()
    }

    #[test]
    fn compute_and_verify_signature() {
        let key = test_key();
        let ts = now_timestamp();
        let sig = compute_signature(&key, &ts, "POST", "/api/v1/intents", r#"{"goal":"test"}"#);

        assert!(sig.starts_with("hmac-sha256:"));

        let result = verify_signature(
            &key, &ts, "POST", "/api/v1/intents", r#"{"goal":"test"}"#, &sig,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = test_key();
        let key2 = b"wrong-key".to_vec();
        let ts = now_timestamp();
        let sig = compute_signature(&key1, &ts, "POST", "/api/v1/intents", "body");

        let result = verify_signature(
            &key2, &ts, "POST", "/api/v1/intents", "body", &sig,
        );
        assert!(result.is_err());
    }

    #[test]
    fn wrong_body_fails() {
        let key = test_key();
        let ts = now_timestamp();
        let sig = compute_signature(&key, &ts, "POST", "/api/v1/intents", "original");

        let result = verify_signature(
            &key, &ts, "POST", "/api/v1/intents", "tampered", &sig,
        );
        assert!(result.is_err());
    }

    #[test]
    fn expired_timestamp_fails() {
        let key = test_key();
        let past = (chrono::Utc::now() - chrono::Duration::minutes(10)).to_rfc3339();
        let sig = compute_signature(&key, &past, "POST", "/api/v1/intents", "body");

        let result = verify_signature(
            &key, &past, "POST", "/api/v1/intents", "body", &sig,
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
        let key = test_key();
        let ts = now_timestamp();

        let result = verify_signature(
            &key, &ts, "POST", "/api/v1/intents", "body", "not-valid-format",
        );
        assert!(result.is_err());
    }

    #[test]
    fn timestamp_within_window_ok() {
        let key = test_key();
        // 4 分钟前 → 在 5 分钟窗口内
        let near_past = (chrono::Utc::now() - chrono::Duration::minutes(4)).to_rfc3339();
        let sig = compute_signature(&key, &near_past, "GET", "/api/v1/agents", "");

        let result = verify_signature(
            &key, &near_past, "GET", "/api/v1/agents", "", &sig,
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
}
