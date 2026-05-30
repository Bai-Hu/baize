//! LNK 域校验函数：会话建立、接受、消息

use std::collections::HashMap;

use baize_core::error::Error;
use baize_core::identity::IdentityProvider;
use baize_core::labels::*;
use baize_core::storage::BlobStore;

use crate::pipeline::is_timestamp_expired;

/// LNK 加密套件白名单（当前仅支持 AES-256-GCM）
pub(crate) const KNOWN_CIPHER_SUITES: &[&str] = &["AES-256-GCM"];

/// LNK-SES：session-init 写入校验
pub(crate) fn validate_session_init_blob(
    storage: &dyn BlobStore,
    identity: &dyn IdentityProvider,
    content: &str,
    labels: &HashMap<String, String>,
) -> Result<(), Error> {
    // 校验 peer_b 是已注册 agent
    let peer_b = labels.get(LABEL_SESSION_PEER_B)
        .ok_or_else(|| Error::Validation("x-session-peer-b is required for session-init".into()))?;

    if !identity.contains(peer_b) {
        return Err(Error::Validation(
            format!("peer_b '{}' is not a registered agent", peer_b)
        ));
    }

    // 校验 x-session-id 全局唯一（查询是否已有同 session-id 的 init blob）
    let session_id = labels.get(LABEL_SESSION_ID)
        .ok_or_else(|| Error::Validation("x-session-id is required for session-init".into()))?;

    let mut filter = HashMap::new();
    filter.insert("type".to_string(), BLOB_TYPE_SESSION_INIT.to_string());
    filter.insert(LABEL_SESSION_ID.to_string(), session_id.clone());
    let existing = storage.blob_query(&filter).unwrap_or_default();
    if !existing.is_empty() {
        return Err(Error::Conflict(
            format!("session '{}' already initialized", session_id)
        ));
    }

    // Phase 3: 校验 content JSON 包含 ephemeral_pub（非空字符串）
    let parsed: serde_json::Value = serde_json::from_str(content)
        .map_err(|e| Error::Validation(format!("invalid session-init JSON: {}", e)))?;
    let ephemeral_pub = parsed.get("ephemeral_pub")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if ephemeral_pub.is_empty() {
        return Err(Error::Validation("ephemeral_pub is required for session-init".into()));
    }

    // 校验 ephemeral_pub 是合法的 X25519 公钥
    baize_core::crypto::decode_x25519_public(ephemeral_pub)
        .map_err(|e| Error::Validation(format!("invalid ephemeral_pub: {}", e)))?;

    // Phase 3: 校验 cipher_suites（必须包含 AES-256-GCM，且所有套件在白名单内）
    let empty_suites = vec![];
    let cipher_suites = parsed.get("cipher_suites")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty_suites);
    for suite in cipher_suites {
        if let Some(s) = suite.as_str() {
            if !KNOWN_CIPHER_SUITES.contains(&s) {
                return Err(Error::Validation(
                    format!("unknown cipher suite '{}', known: {:?}", s, KNOWN_CIPHER_SUITES)
                ));
            }
        }
    }
    let has_aes_gcm = cipher_suites.iter().any(|s| {
        s.as_str() == Some("AES-256-GCM")
    });
    if !has_aes_gcm {
        return Err(Error::Validation(
            "cipher_suites must include 'AES-256-GCM'".into()
        ));
    }

    Ok(())
}

/// LNK-SES：session-accept 写入校验
pub(crate) fn validate_session_accept_blob(
    storage: &dyn BlobStore,
    content: &str,
    labels: &HashMap<String, String>,
    writer_agent: &str,
) -> Result<(), Error> {
    let session_id = labels.get(LABEL_SESSION_ID)
        .ok_or_else(|| Error::Validation("x-session-id is required for session-accept".into()))?;

    // 校验对应的 session-init blob 存在
    let mut filter = HashMap::new();
    filter.insert("type".to_string(), BLOB_TYPE_SESSION_INIT.to_string());
    filter.insert(LABEL_SESSION_ID.to_string(), session_id.clone());
    let init_blobs = storage.blob_query(&filter).unwrap_or_default();

    if init_blobs.is_empty() {
        return Err(Error::ChainBroken(
            format!("session '{}' has no init blob", session_id)
        ));
    }

    // 校验 accept 方是 session-init 中 x-session-peer-b
    let peer_b = init_blobs[0].labels.get(LABEL_SESSION_PEER_B)
        .map(|s| s.clone())
        .unwrap_or_default();
    if peer_b != writer_agent {
        return Err(Error::PermissionDenied(
            format!("only peer_b '{}' can accept this session, got '{}'", peer_b, writer_agent)
        ));
    }

    // 校验没有已存在的 accept（一个 session 只能 accept 一次）
    let mut accept_filter = HashMap::new();
    accept_filter.insert("type".to_string(), BLOB_TYPE_SESSION_ACCEPT.to_string());
    accept_filter.insert(LABEL_SESSION_ID.to_string(), session_id.clone());
    let existing_accepts = storage.blob_query(&accept_filter).unwrap_or_default();
    if !existing_accepts.is_empty() {
        return Err(Error::Conflict(
            format!("session '{}' already accepted", session_id)
        ));
    }

    // 校验 parent 指向 session-init blob
    if let Some(parent) = labels.get("parent") {
        if *parent != init_blobs[0].hash {
            return Err(Error::ChainBroken(
                "session-accept parent must point to session-init blob".into()
            ));
        }
    }

    // Phase 3: 校验 content JSON 包含 ephemeral_pub（非空字符串）
    let parsed: serde_json::Value = serde_json::from_str(content)
        .map_err(|e| Error::Validation(format!("invalid session-accept JSON: {}", e)))?;
    let ephemeral_pub = parsed.get("ephemeral_pub")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if ephemeral_pub.is_empty() {
        return Err(Error::Validation("ephemeral_pub is required for session-accept".into()));
    }

    // 校验 ephemeral_pub 是合法的 X25519 公钥
    baize_core::crypto::decode_x25519_public(ephemeral_pub)
        .map_err(|e| Error::Validation(format!("invalid ephemeral_pub: {}", e)))?;

    // Phase 3: 校验 selected_cipher_suite 在 init 的 cipher_suites 中
    let selected = parsed.get("selected_cipher_suite")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if selected.is_empty() {
        return Err(Error::Validation("selected_cipher_suite is required for session-accept".into()));
    }

    // 读取 init blob 的 content 获取 cipher_suites
    let init_content: serde_json::Value = serde_json::from_str(&init_blobs[0].content)
        .map_err(|e| Error::ChainBroken(format!("invalid session-init content: {}", e)))?;
    let init_suites = init_content.get("cipher_suites")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let suite_match = init_suites.iter().any(|s| s.as_str() == Some(selected));
    if !suite_match {
        return Err(Error::Validation(
            format!("selected_cipher_suite '{}' not in init cipher_suites", selected)
        ));
    }

    Ok(())
}

/// LNK-DTX：session 内消息写入校验
///
/// 校验：session 未关闭、handshake 完成、发送者是 session 的 peer、seq 递增。
pub(crate) fn validate_session_message_blob(
    storage: &dyn BlobStore,
    labels: &HashMap<String, String>,
    agent_id: &str,
) -> Result<(), Error> {
    let session_id = labels.get(LABEL_SESSION_ID)
        .ok_or_else(|| Error::Validation("x-session-id is required for session messages".into()))?;

    // 查询该 session 是否已关闭
    let mut close_filter = HashMap::new();
    close_filter.insert(LABEL_SESSION_STATUS.to_string(), "closed".to_string());
    close_filter.insert(LABEL_SESSION_ID.to_string(), session_id.clone());
    let closed_blobs = storage.blob_query(&close_filter).unwrap_or_default();
    if !closed_blobs.is_empty() {
        return Err(Error::Validation(
            format!("session '{}' is closed", session_id)
        ));
    }

    // 校验 session-init + session-accept 已完成
    let mut init_filter = HashMap::new();
    init_filter.insert("type".to_string(), BLOB_TYPE_SESSION_INIT.to_string());
    init_filter.insert(LABEL_SESSION_ID.to_string(), session_id.clone());
    let init_blobs = storage.blob_query(&init_filter).unwrap_or_default();
    if init_blobs.is_empty() {
        return Err(Error::ChainBroken(
            format!("session '{}' has no init blob", session_id)
        ));
    }

    // 校验 session 未过期（从 init blob content 中读取 expires_at）
    if let Ok(init_content) = serde_json::from_str::<serde_json::Value>(&init_blobs[0].content) {
        if let Some(expires) = init_content.get("expires_at").and_then(|v| v.as_str()) {
            if is_timestamp_expired(expires) {
                return Err(Error::Validation(
                    format!("session '{}' expired at {}", session_id, expires)
                ));
            }
        }
    }

    let mut accept_filter = HashMap::new();
    accept_filter.insert("type".to_string(), BLOB_TYPE_SESSION_ACCEPT.to_string());
    accept_filter.insert(LABEL_SESSION_ID.to_string(), session_id.clone());
    let accept_blobs = storage.blob_query(&accept_filter).unwrap_or_default();
    if accept_blobs.is_empty() {
        return Err(Error::ChainBroken(
            format!("session '{}' has no accept blob — handshake not completed", session_id)
        ));
    }

    // 校验发送者是 session 的 peer_a 或 peer_b
    let peer_a = init_blobs[0].labels.get(LABEL_SESSION_PEER_A).map(|s| s.as_str()).unwrap_or("");
    let peer_b = init_blobs[0].labels.get(LABEL_SESSION_PEER_B).map(|s| s.as_str()).unwrap_or("");
    if agent_id != peer_a && agent_id != peer_b {
        return Err(Error::PermissionDenied(
            format!("agent '{}' is not a peer of session '{}' (peers: {}, {})", agent_id, session_id, peer_a, peer_b)
        ));
    }

    // 校验 x-message-seq 单调递增
    if let Some(seq_str) = labels.get(LABEL_MESSAGE_SEQ) {
        let current_seq: u64 = seq_str.parse()
            .map_err(|_| Error::Validation(format!("invalid x-message-seq: {}", seq_str)))?;

        // 查询当前 session 内最大 seq
        let mut msg_filter = HashMap::new();
        msg_filter.insert(LABEL_SESSION_ID.to_string(), session_id.clone());
        let existing_msgs = storage.blob_query(&msg_filter).unwrap_or_default();

        let max_seq: u64 = existing_msgs.iter()
            .filter_map(|b| b.labels.get(LABEL_MESSAGE_SEQ))
            .filter_map(|s| s.parse::<u64>().ok())
            .max()
            .unwrap_or(0);

        if current_seq != max_seq + 1 {
            return Err(Error::Validation(format!(
                "x-message-seq must be {}, got {}", max_seq + 1, current_seq
            )));
        }
    }

    Ok(())
}
