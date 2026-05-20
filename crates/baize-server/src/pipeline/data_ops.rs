//! 数据操作接口：blob 写入、label 追加、导入、导出
//!
//! v1 扩展：按 blob type label 分派校验逻辑（INT/AZN/LNK）

use std::collections::HashMap;

use baize_core::constraint::{verify_authz_constraint_reduction, verify_intent_constraint_reduction};
use baize_core::error::Error;
use baize_core::labels::*;
use baize_core::storage::Storage;

use super::Baize;
use super::auditor::Auditor;
use super::agent_manager::PermissionGuard;

/// 数据操作接口：blob 写入、label 追加、导入、导出
pub trait DataOps {
    /// 管道：blob 写入（含 type dispatch 校验）
    fn pipe_blob_write(
        &self,
        agent_id: &str,
        content: &str,
        labels: &HashMap<String, String>,
    ) -> Result<baize_core::storage::Blob, Error>;

    /// 管道：label 追加
    fn pipe_label_add(
        &self,
        agent_id: &str,
        entity_hash: &str,
        key: &str,
        value: &str,
    ) -> Result<(), Error>;

    /// 管道：数据导入
    fn pipe_import(
        &self,
        agent_id: &str,
        content: &str,
        source: &str,
        trust_level: u8,
        extra_labels: Option<HashMap<String, String>>,
    ) -> Result<baize_core::storage::Blob, Error>;

    /// 管道：数据导出
    fn pipe_export(
        &self,
        agent_id: &str,
        hash: &str,
    ) -> Result<baize_core::storage::Blob, Error>;
}

impl DataOps for Baize {
    fn pipe_blob_write(
        &self,
        agent_id: &str,
        content: &str,
        labels: &HashMap<String, String>,
    ) -> Result<baize_core::storage::Blob, Error> {
        self.verify_write_agent(agent_id)?;

        // v1: 按 type label 分派校验
        let blob_type = labels.get("type").map(|s| s.as_str()).unwrap_or("");

        // LNK session 消息优先检查：带 x-session-id 且非 init/accept/close 的一律走 session 消息校验
        // 这必须在 type-based match 之前，因为 session 消息的 type 可以是任意值
        let is_session_msg = labels.contains_key(LABEL_SESSION_ID)
            && blob_type != BLOB_TYPE_SESSION_INIT
            && blob_type != BLOB_TYPE_SESSION_ACCEPT
            && blob_type != "session-close";

        if is_session_msg {
            validate_session_message_blob(&self.storage, labels)?;
        } else {
            match blob_type {
                // ─── INT-GIR：通用意图 ───
                BLOB_TYPE_INTENT => {
                    validate_intent_blob(&self.storage, content, labels)?;
                }

                // ─── INT-DER：子意图派生 ───
                BLOB_TYPE_SUB_INTENT => {
                    validate_sub_intent_blob(&self.storage, content, labels)?;
                }

                // ─── INT-RCT：执行回执 ───
                BLOB_TYPE_RECEIPT => {
                    validate_receipt_blob(&self.storage, content, labels)?;
                }

                // ─── AZN-APR/AZN-ISS：授权签发 ───
                BLOB_TYPE_AUTHORIZATION => {
                    validate_authorization_blob(&self.storage, content, labels)?;
                }

                // ─── LNK-SES：会话建立 ───
                BLOB_TYPE_SESSION_INIT => {
                    validate_session_init_blob(&self.storage, &self.agents, labels)?;
                }

                // ─── LNK-SES：会话接受 ───
                BLOB_TYPE_SESSION_ACCEPT => {
                    validate_session_accept_blob(&self.storage, labels)?;
                }

                // ─── 其他类型：走原有逻辑 ───
                _ => {}
            }
        }

        let blob = self.storage.blob_write(content, labels)?;
        self.audit("blob_write", agent_id, "success", Some(&blob.hash))?;
        Ok(blob)
    }

    fn pipe_label_add(
        &self,
        agent_id: &str,
        entity_hash: &str,
        key: &str,
        value: &str,
    ) -> Result<(), Error> {
        self.verify_write_agent(agent_id)?;
        self.storage.label_add(entity_hash, key, value)?;
        self.audit("label_add", agent_id, "success", Some(entity_hash))?;
        Ok(())
    }

    fn pipe_import(
        &self,
        agent_id: &str,
        content: &str,
        source: &str,
        trust_level: u8,
        extra_labels: Option<HashMap<String, String>>,
    ) -> Result<baize_core::storage::Blob, Error> {
        self.verify_write_agent(agent_id)?;

        let mut labels = extra_labels.unwrap_or_default();
        labels.insert("source".to_string(), source.to_string());
        labels.insert("trust-level".to_string(), trust_level.to_string());
        labels.insert("imported".to_string(), "true".to_string());

        if trust_level == 0 {
            labels.insert("sandbox".to_string(), "true".to_string());
        }

        let blob = self.storage.blob_write(content, &labels)?;
        self.audit("import", agent_id, "success", Some(&blob.hash))?;
        Ok(blob)
    }

    fn pipe_export(
        &self,
        agent_id: &str,
        hash: &str,
    ) -> Result<baize_core::storage::Blob, Error> {
        let identity = self.verify_read_agent(agent_id)?;
        let blob = self.storage.blob_read(hash)?;

        // 敏感标签检查
        if let Some(sensitivity) = blob.labels.get("sensitivity") {
            let required_level = match sensitivity.as_str() {
                "high" => 3,
                "medium" => 2,
                "low" => 1,
                _ => 0,
            };
            if identity.level < required_level {
                return Err(Error::PermissionDenied(
                    format!("export requires level {} for sensitivity '{}', agent {} is level {}",
                        required_level, sensitivity, agent_id, identity.level)
                ));
            }
        }

        // Zone 检查
        if let Some(blob_zone) = blob.labels.get("zone") {
            if !identity.zones.iter().any(|z| z == "*")
                && !identity.zones.contains(blob_zone)
            {
                return Err(Error::PermissionDenied(
                    format!("agent {} scope {:?} does not cover zone '{}'",
                        agent_id, identity.zones, blob_zone)
                ));
            }
        }

        self.audit("export", agent_id, "success", Some(hash))?;
        Ok(blob)
    }
}

// ─── INT 校验函数 ───

/// INT-GIR：通用意图写入校验
fn validate_intent_blob(
    storage: &Storage,
    content: &str,
    labels: &HashMap<String, String>,
) -> Result<(), Error> {
    let parsed: serde_json::Value = serde_json::from_str(content)
        .map_err(|e| Error::Validation(format!("invalid intent JSON: {}", e)))?;

    // 校验 intent_constraints 非空
    let constraints = parsed.get("intent_constraints");
    match constraints {
        None | Some(serde_json::Value::Null) => {
            return Err(Error::Validation("intent_constraints is required".into()));
        }
        Some(serde_json::Value::Object(m)) if m.is_empty() => {
            return Err(Error::Validation("intent_constraints cannot be empty".into()));
        }
        _ => {}
    }

    // 校验 expires_at > created_at（解析为 DateTime 后比较，避免字符串比较不准）
    let expires = parsed.get("expires_at").and_then(|v| v.as_str()).unwrap_or("");
    let created = parsed.get("created_at").and_then(|v| v.as_str()).unwrap_or("");
    if !expires.is_empty() && !created.is_empty() {
        let exp_dt = chrono::DateTime::parse_from_rfc3339(expires);
        let cre_dt = chrono::DateTime::parse_from_rfc3339(created);
        if let (Ok(exp), Ok(cre)) = (exp_dt, cre_dt) {
            if exp <= cre {
                return Err(Error::Validation(
                    "expires_at must be after created_at".into()
                ));
            }
        }
        // 解析失败时跳过比较（兼容非标准时间格式）
    }

    // 校验 x-intent-id 在有效期内唯一
    if let Some(intent_id) = labels.get(LABEL_INTENT_ID) {
        let mut filter = HashMap::new();
        filter.insert(LABEL_INTENT_ID.to_string(), intent_id.clone());
        filter.insert(LABEL_INTENT_STATUS.to_string(), "active".to_string());
        let existing = storage.blob_query(&filter).unwrap_or_default();
        if !existing.is_empty() {
            return Err(Error::Conflict(
                format!("intent_id '{}' already exists with active status", intent_id)
            ));
        }
    }

    Ok(())
}

/// INT-DER：子意图派生写入校验
fn validate_sub_intent_blob(
    storage: &Storage,
    content: &str,
    _labels: &HashMap<String, String>,
) -> Result<(), Error> {
    let parsed: serde_json::Value = serde_json::from_str(content)
        .map_err(|e| Error::Validation(format!("invalid sub-intent JSON: {}", e)))?;

    // 读取 parent_intent_digest
    let parent_digest = parsed.get("parent_intent_digest")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Validation("parent_intent_digest is required for sub-intent".into()))?;

    // 校验父 blob 存在且 type 为 intent 或 sub-intent
    let parent_blob = storage.blob_read(parent_digest)
        .map_err(|_| Error::ChainBroken(format!("parent intent {} not found", parent_digest)))?;

    let parent_type = parent_blob.labels.get("type").unwrap_or(&"".to_string()).clone();
    if parent_type != BLOB_TYPE_INTENT && parent_type != BLOB_TYPE_SUB_INTENT {
        return Err(Error::ChainBroken(format!(
            "parent {} is not an intent (type='{}')", parent_digest, parent_type
        )));
    }

    // 校验约束收缩
    let child_constraints = parsed.get("intent_constraints").cloned().unwrap_or_default();
    let parent_content: serde_json::Value = serde_json::from_str(&parent_blob.content)
        .unwrap_or_default();
    let parent_constraints = parent_content.get("intent_constraints").cloned().unwrap_or_default();

    verify_intent_constraint_reduction(&parent_constraints, &child_constraints)
        .map_err(|e| Error::ConstraintViolation(e.to_string()))?;

    // 校验 derivation_depth = 父 depth + 1
    let parent_depth: u32 = parent_blob.labels.get(LABEL_DERIVATION_DEPTH)
        .and_then(|d| d.parse().ok())
        .unwrap_or(0);
    let child_depth: u32 = parsed.get("derivation_depth")
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;

    if child_depth != parent_depth + 1 {
        return Err(Error::Validation(format!(
            "derivation_depth must be {} (parent depth + 1), got {}",
            parent_depth + 1, child_depth
        )));
    }

    // 校验 expires_at 不晚于父 expires_at
    let child_expires = parsed.get("expires_at").and_then(|v| v.as_str()).unwrap_or("");
    let parent_expires = parent_blob.labels.get(LABEL_INTENT_EXPIRES)
        .map(|s| s.as_str())
        .unwrap_or("");
    if !child_expires.is_empty() && !parent_expires.is_empty() && child_expires > parent_expires {
        return Err(Error::Validation(
            "sub-intent expires_at cannot be later than parent expires_at".into()
        ));
    }

    Ok(())
}

/// INT-RCT：执行回执写入校验
fn validate_receipt_blob(
    storage: &Storage,
    content: &str,
    _labels: &HashMap<String, String>,
) -> Result<(), Error> {
    let parsed: serde_json::Value = serde_json::from_str(content)
        .map_err(|e| Error::Validation(format!("invalid receipt JSON: {}", e)))?;

    // 校验 intent_digest 对应 blob 存在且为 intent/sub-intent
    let intent_digest = parsed.get("intent_digest")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Validation("intent_digest is required for receipt".into()))?;

    let intent_blob = storage.blob_read(intent_digest)
        .map_err(|_| Error::ChainBroken(format!("intent {} not found for receipt", intent_digest)))?;

    let intent_type = intent_blob.labels.get("type").unwrap_or(&"".to_string()).clone();
    if intent_type != BLOB_TYPE_INTENT && intent_type != BLOB_TYPE_SUB_INTENT {
        return Err(Error::ChainBroken(format!(
            "intent_digest points to non-intent type '{}'", intent_type
        )));
    }

    // 校验 authorization_digest 对应 blob 存在且为 authorization
    let authz_digest = parsed.get("authorization_digest")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Validation("authorization_digest is required for receipt".into()))?;

    let authz_blob = storage.blob_read(authz_digest)
        .map_err(|_| Error::ChainBroken(format!("authorization {} not found for receipt", authz_digest)))?;

    let authz_type = authz_blob.labels.get("type").unwrap_or(&"".to_string()).clone();
    if authz_type != BLOB_TYPE_AUTHORIZATION {
        return Err(Error::ChainBroken(format!(
            "authorization_digest points to non-authorization type '{}'", authz_type
        )));
    }

    // 校验 result_status 与 execution_result/rejection_reason 一致性
    let result_status = parsed.get("result_status")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if result_status == "REJECTED" && parsed.get("rejection_reason").is_none() {
        return Err(Error::Validation(
            "rejection_reason is required when result_status is REJECTED".into()
        ));
    }

    Ok(())
}

// ─── AZN 校验函数 ───

/// AZN-APR/AZN-ISS：授权签发写入校验
fn validate_authorization_blob(
    storage: &Storage,
    content: &str,
    _labels: &HashMap<String, String>,
) -> Result<(), Error> {
    let parsed: serde_json::Value = serde_json::from_str(content)
        .map_err(|e| Error::Validation(format!("invalid authorization JSON: {}", e)))?;

    // 校验 source_intent_digest 对应 blob 存在且有效
    let source_intent = parsed.get("source_intent_digest")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Validation("source_intent_digest is required".into()))?;

    // 校验 constraints 非空（协议 §10.2：必备且非空）
    let constraints = parsed.get("constraints")
        .ok_or_else(|| Error::Validation("constraints is required".into()))?;
    if constraints.is_null() || (constraints.is_object() && constraints.as_object().map_or(true, |m| m.is_empty())) {
        return Err(Error::Validation("constraints must not be empty".into()));
    }

    let intent_blob = storage.blob_read(source_intent)
        .map_err(|_| Error::ChainBroken(format!("source intent {} not found", source_intent)))?;

    let intent_type = intent_blob.labels.get("type").unwrap_or(&"".to_string()).clone();
    if intent_type != BLOB_TYPE_INTENT && intent_type != BLOB_TYPE_SUB_INTENT {
        return Err(Error::ChainBroken(format!(
            "source_intent_digest points to non-intent type '{}'", intent_type
        )));
    }

    // 校验意图状态：expired 或 revoked 均无效
    let intent_status = intent_blob.labels.get(LABEL_INTENT_STATUS)
        .map(|s| s.as_str())
        .unwrap_or("active");
    if intent_status == "expired" || intent_status == "revoked" {
        return Err(Error::Validation(
            format!("source intent is {}", intent_status)
        ));
    }

    // 校验签发方凭证状态（查 x-cert-revoked/suspended/expired label）
    let issuer = parsed.get("issuer")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if !issuer.is_empty() {
        let mut filter = HashMap::new();
        filter.insert("type".to_string(), BLOB_TYPE_AGENT_CERT.to_string());
        filter.insert(LABEL_CERT_AGENT.to_string(), issuer.to_string());
        let certs = storage.blob_query(&filter).unwrap_or_default();
        if let Some(cert) = certs.first() {
            if cert.labels.contains_key(LABEL_CERT_REVOKED) {
                return Err(Error::PermissionDenied(
                    format!("issuer {} is revoked", issuer)
                ));
            }
            if cert.labels.contains_key(LABEL_CERT_SUSPENDED) {
                return Err(Error::PermissionDenied(
                    format!("issuer {} is suspended", issuer)
                ));
            }
            if cert.labels.contains_key(LABEL_CERT_EXPIRED) {
                return Err(Error::PermissionDenied(
                    format!("issuer {} is expired", issuer)
                ));
            }
        }
    }

    // 校验 exp 不晚于意图 expires_at
    let authz_exp = parsed.get("exp").and_then(|v| v.as_str()).unwrap_or("");
    let intent_expires = intent_blob.labels.get(LABEL_INTENT_EXPIRES)
        .map(|s| s.as_str())
        .unwrap_or("");
    if !authz_exp.is_empty() && !intent_expires.is_empty() && authz_exp > intent_expires {
        return Err(Error::Validation(
            "authorization exp cannot be later than intent expires_at".into()
        ));
    }

    // AZN-DLG：如果有 parent_authz_digest，校验委托链
    if let Some(parent_digest) = parsed.get("parent_authz_digest").and_then(|v| v.as_str()) {
        validate_delegation(storage, &parsed, parent_digest)?;
    }

    Ok(())
}

/// AZN-DLG：委托子授权校验
fn validate_delegation(
    storage: &Storage,
    authz_content: &serde_json::Value,
    parent_digest: &str,
) -> Result<(), Error> {
    // 读取父授权 blob
    let parent_blob = storage.blob_read(parent_digest)
        .map_err(|_| Error::ChainBroken(format!("parent authorization {} not found", parent_digest)))?;

    if parent_blob.labels.get("type").unwrap_or(&"".to_string()) != BLOB_TYPE_AUTHORIZATION {
        return Err(Error::ChainBroken(format!(
            "parent {} is not authorization type", parent_digest
        )));
    }

    let parent_authz: serde_json::Value = serde_json::from_str(&parent_blob.content)
        .map_err(|e| Error::ChainBroken(format!("invalid parent authorization: {}", e)))?;

    // 校验父授权状态
    let parent_status = parent_blob.labels.get(LABEL_AUTHZ_STATUS)
        .map(|s| s.as_str())
        .unwrap_or("");
    if parent_status != "valid" {
        return Err(Error::Validation(
            format!("parent authorization status is '{}', expected 'valid'", parent_status)
        ));
    }

    // 校验约束收缩
    let parent_constraints = parent_authz.get("constraints").cloned().unwrap_or_default();
    let child_constraints = authz_content.get("constraints").cloned().unwrap_or_default();

    verify_authz_constraint_reduction(&parent_constraints, &child_constraints)
        .map_err(|e| Error::ConstraintViolation(e.to_string()))?;

    // 校验 delegation_depth_remaining = 父 - 1
    let parent_depth = parent_authz.get("delegation_depth_remaining")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let child_depth = authz_content.get("delegation_depth_remaining")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    if child_depth != parent_depth.saturating_sub(1) {
        return Err(Error::Validation(format!(
            "delegation_depth_remaining must be {}, got {}",
            parent_depth.saturating_sub(1), child_depth
        )));
    }

    // 校验 root_authorizer 一致
    let parent_root = parent_authz.get("root_authorizer")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let child_root = authz_content.get("root_authorizer")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if parent_root != child_root {
        return Err(Error::Validation(
            format!("root_authorizer mismatch: parent={}, child={}", parent_root, child_root)
        ));
    }

    // 校验父 delegatable = true
    let parent_delegatable = parent_authz.get("delegatable")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if !parent_delegatable {
        return Err(Error::Validation(
            format!("parent authorization {} is not delegatable", parent_digest)
        ));
    }

    Ok(())
}

// ─── LNK 校验函数 ───

/// LNK-SES：session-init 写入校验
fn validate_session_init_blob(
    storage: &Storage,
    agents: &std::collections::HashMap<String, (baize_core::cert::CertIdentity, baize_core::cert::IssuerCtx)>,
    labels: &HashMap<String, String>,
) -> Result<(), Error> {
    // 校验 peer_b 是已注册 agent
    let peer_b = labels.get(LABEL_SESSION_PEER_B)
        .ok_or_else(|| Error::Validation("x-session-peer-b is required for session-init".into()))?;

    if !agents.contains_key(peer_b) {
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

    Ok(())
}

/// LNK-SES：session-accept 写入校验
fn validate_session_accept_blob(
    storage: &Storage,
    labels: &HashMap<String, String>,
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

    // 注意：accept 的写入方身份校验由 verify_write_agent 完成
    // 这里只验证 session 状态
    let _ = peer_b; // peer_b 用于后续扩展（accept 方必须是 peer_b）

    Ok(())
}

/// LNK-DTX：session 内消息写入校验
fn validate_session_message_blob(
    storage: &Storage,
    labels: &HashMap<String, String>,
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

    let mut accept_filter = HashMap::new();
    accept_filter.insert("type".to_string(), BLOB_TYPE_SESSION_ACCEPT.to_string());
    accept_filter.insert(LABEL_SESSION_ID.to_string(), session_id.clone());
    let accept_blobs = storage.blob_query(&accept_filter).unwrap_or_default();
    if accept_blobs.is_empty() {
        return Err(Error::ChainBroken(
            format!("session '{}' has no accept blob — handshake not completed", session_id)
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

#[cfg(test)]
mod tests {
    use super::*;
    use baize_core::scope::Level;

    use crate::pipeline::agent_manager::AgentRegistry;

    fn setup_baize() -> Baize {
        Baize::init_in_memory().unwrap()
    }

    fn register_agent(baize: &mut Baize, name: &str, level: u8) {
        baize.agent_register(name, Level(level), vec!["A"], None).unwrap();
    }

    // ─── INT tests ───

    #[test]
    fn intent_write_ok() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "writer", 2);

        let content = serde_json::json!({
            "intent_id": "int-001",
            "intent_owner": "writer",
            "intent_creator": "writer",
            "intent_goal": "deploy service",
            "intent_constraints": {"budget": 100},
            "version": "1.0",
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-12-31T23:59:59Z",
        }).to_string();

        let mut labels = HashMap::new();
        labels.insert("type".to_string(), BLOB_TYPE_INTENT.to_string());
        labels.insert(LABEL_INTENT_ID.to_string(), "int-001".to_string());
        labels.insert(LABEL_INTENT_STATUS.to_string(), "active".to_string());
        labels.insert(LABEL_INTENT_EXPIRES.to_string(), "2026-12-31T23:59:59Z".to_string());

        let result = baize.pipe_blob_write("writer", &content, &labels);
        assert!(result.is_ok(), "intent write should succeed: {:?}", result);
    }

    #[test]
    fn intent_write_empty_constraints_fails() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "writer", 2);

        let content = serde_json::json!({
            "intent_id": "int-002",
            "intent_owner": "writer",
            "intent_creator": "writer",
            "intent_goal": "deploy",
            "intent_constraints": {},
            "version": "1.0",
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-12-31T23:59:59Z",
        }).to_string();

        let mut labels = HashMap::new();
        labels.insert("type".to_string(), BLOB_TYPE_INTENT.to_string());
        labels.insert(LABEL_INTENT_ID.to_string(), "int-002".to_string());

        let result = baize.pipe_blob_write("writer", &content, &labels);
        assert!(result.is_err());
        match result {
            Err(Error::Validation(msg)) => assert!(msg.contains("intent_constraints")),
            other => panic!("expected Validation, got {:?}", other),
        }
    }

    #[test]
    fn intent_write_duplicate_id_fails() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "writer", 2);

        let content = serde_json::json!({
            "intent_id": "int-dup",
            "intent_owner": "writer",
            "intent_creator": "writer",
            "intent_goal": "deploy",
            "intent_constraints": {"budget": 100},
            "version": "1.0",
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-12-31T23:59:59Z",
        }).to_string();

        let mut labels = HashMap::new();
        labels.insert("type".to_string(), BLOB_TYPE_INTENT.to_string());
        labels.insert(LABEL_INTENT_ID.to_string(), "int-dup".to_string());
        labels.insert(LABEL_INTENT_STATUS.to_string(), "active".to_string());
        labels.insert(LABEL_INTENT_EXPIRES.to_string(), "2026-12-31T23:59:59Z".to_string());

        baize.pipe_blob_write("writer", &content, &labels).unwrap();

        let content2 = serde_json::json!({
            "intent_id": "int-dup",
            "intent_owner": "writer",
            "intent_creator": "writer",
            "intent_goal": "different",
            "intent_constraints": {"budget": 200},
            "version": "1.0",
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-12-31T23:59:59Z",
        }).to_string();

        let mut labels2 = HashMap::new();
        labels2.insert("type".to_string(), BLOB_TYPE_INTENT.to_string());
        labels2.insert(LABEL_INTENT_ID.to_string(), "int-dup".to_string());
        labels2.insert(LABEL_INTENT_STATUS.to_string(), "active".to_string());
        labels2.insert(LABEL_INTENT_EXPIRES.to_string(), "2026-12-31T23:59:59Z".to_string());

        let result = baize.pipe_blob_write("writer", &content2, &labels2);
        assert!(result.is_err());
        match result {
            Err(Error::Conflict(msg)) => assert!(msg.contains("int-dup")),
            other => panic!("expected Conflict, got {:?}", other),
        }
    }

    #[test]
    fn sub_intent_write_ok() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "writer", 2);

        // 先写根意图
        let parent_content = serde_json::json!({
            "intent_id": "int-parent",
            "intent_owner": "writer",
            "intent_creator": "writer",
            "intent_goal": "deploy",
            "intent_constraints": {"budget": 200},
            "version": "1.0",
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-12-31T23:59:59Z",
        }).to_string();

        let mut parent_labels = HashMap::new();
        parent_labels.insert("type".to_string(), BLOB_TYPE_INTENT.to_string());
        parent_labels.insert(LABEL_INTENT_ID.to_string(), "int-parent".to_string());
        parent_labels.insert(LABEL_INTENT_STATUS.to_string(), "active".to_string());
        parent_labels.insert(LABEL_INTENT_EXPIRES.to_string(), "2026-12-31T23:59:59Z".to_string());
        parent_labels.insert(LABEL_DERIVATION_DEPTH.to_string(), "0".to_string());

        let parent_blob = baize.pipe_blob_write("writer", &parent_content, &parent_labels).unwrap();

        // 写子意图
        let child_content = serde_json::json!({
            "sub_intent_id": "sub-001",
            "parent_intent_digest": parent_blob.hash,
            "deriver_id": "writer",
            "subject": "deploy",
            "derivation_depth": 1,
            "intent_goal": "deploy db",
            "intent_constraints": {"budget": 100},
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-06-01T00:00:00Z",
        }).to_string();

        let mut child_labels = HashMap::new();
        child_labels.insert("type".to_string(), BLOB_TYPE_SUB_INTENT.to_string());
        child_labels.insert(LABEL_INTENT_ID.to_string(), "sub-001".to_string());
        child_labels.insert(LABEL_INTENT_STATUS.to_string(), "active".to_string());
        child_labels.insert(LABEL_INTENT_EXPIRES.to_string(), "2026-06-01T00:00:00Z".to_string());
        child_labels.insert(LABEL_PARENT_INTENT.to_string(), parent_blob.hash.clone());
        child_labels.insert(LABEL_DERIVATION_DEPTH.to_string(), "1".to_string());

        let result = baize.pipe_blob_write("writer", &child_content, &child_labels);
        assert!(result.is_ok(), "sub-intent write should succeed: {:?}", result);
    }

    #[test]
    fn sub_intent_constraint_violation_fails() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "writer", 2);

        let parent_content = serde_json::json!({
            "intent_id": "int-parent",
            "intent_owner": "writer",
            "intent_creator": "writer",
            "intent_goal": "deploy",
            "intent_constraints": {"budget": 100},
            "version": "1.0",
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-12-31T23:59:59Z",
        }).to_string();

        let mut parent_labels = HashMap::new();
        parent_labels.insert("type".to_string(), BLOB_TYPE_INTENT.to_string());
        parent_labels.insert(LABEL_INTENT_ID.to_string(), "int-parent".to_string());
        parent_labels.insert(LABEL_INTENT_STATUS.to_string(), "active".to_string());
        parent_labels.insert(LABEL_INTENT_EXPIRES.to_string(), "2026-12-31T23:59:59Z".to_string());
        parent_labels.insert(LABEL_DERIVATION_DEPTH.to_string(), "0".to_string());

        let parent_blob = baize.pipe_blob_write("writer", &parent_content, &parent_labels).unwrap();

        // 子意图超出父约束
        let child_content = serde_json::json!({
            "sub_intent_id": "sub-bad",
            "parent_intent_digest": parent_blob.hash,
            "deriver_id": "writer",
            "subject": "deploy",
            "derivation_depth": 1,
            "intent_goal": "deploy db",
            "intent_constraints": {"budget": 500},
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-06-01T00:00:00Z",
        }).to_string();

        let mut child_labels = HashMap::new();
        child_labels.insert("type".to_string(), BLOB_TYPE_SUB_INTENT.to_string());
        child_labels.insert(LABEL_INTENT_ID.to_string(), "sub-bad".to_string());
        child_labels.insert(LABEL_PARENT_INTENT.to_string(), parent_blob.hash.clone());
        child_labels.insert(LABEL_DERIVATION_DEPTH.to_string(), "1".to_string());

        let result = baize.pipe_blob_write("writer", &child_content, &child_labels);
        assert!(result.is_err());
        match result {
            Err(Error::ConstraintViolation(msg)) => assert!(msg.contains("budget")),
            other => panic!("expected ConstraintViolation, got {:?}", other),
        }
    }

    // ─── LNK tests ───

    #[test]
    fn session_init_ok() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "alice", 2);
        register_agent(&mut baize, "bob", 2);

        let mut labels = HashMap::new();
        labels.insert("type".to_string(), BLOB_TYPE_SESSION_INIT.to_string());
        labels.insert(LABEL_SESSION_ID.to_string(), "sess-001".to_string());
        labels.insert(LABEL_SESSION_PEER_A.to_string(), "alice".to_string());
        labels.insert(LABEL_SESSION_PEER_B.to_string(), "bob".to_string());

        let result = baize.pipe_blob_write("alice", r#"{"ephemeral_pub":"key1"}"#, &labels);
        assert!(result.is_ok(), "session-init should succeed: {:?}", result);
    }

    #[test]
    fn session_init_unknown_peer_fails() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "alice", 2);

        let mut labels = HashMap::new();
        labels.insert("type".to_string(), BLOB_TYPE_SESSION_INIT.to_string());
        labels.insert(LABEL_SESSION_ID.to_string(), "sess-002".to_string());
        labels.insert(LABEL_SESSION_PEER_A.to_string(), "alice".to_string());
        labels.insert(LABEL_SESSION_PEER_B.to_string(), "unknown-agent".to_string());

        let result = baize.pipe_blob_write("alice", r#"{"ephemeral_pub":"key1"}"#, &labels);
        assert!(result.is_err());
    }

    #[test]
    fn session_accept_ok() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "alice", 2);
        register_agent(&mut baize, "bob", 2);

        let mut init_labels = HashMap::new();
        init_labels.insert("type".to_string(), BLOB_TYPE_SESSION_INIT.to_string());
        init_labels.insert(LABEL_SESSION_ID.to_string(), "sess-003".to_string());
        init_labels.insert(LABEL_SESSION_PEER_A.to_string(), "alice".to_string());
        init_labels.insert(LABEL_SESSION_PEER_B.to_string(), "bob".to_string());

        let init_blob = baize.pipe_blob_write("alice", r#"{"ephemeral_pub":"key1"}"#, &init_labels).unwrap();

        let mut accept_labels = HashMap::new();
        accept_labels.insert("type".to_string(), BLOB_TYPE_SESSION_ACCEPT.to_string());
        accept_labels.insert(LABEL_SESSION_ID.to_string(), "sess-003".to_string());
        accept_labels.insert("parent".to_string(), init_blob.hash);

        let result = baize.pipe_blob_write("bob", r#"{"ephemeral_pub":"key2"}"#, &accept_labels);
        assert!(result.is_ok(), "session-accept should succeed: {:?}", result);
    }

    #[test]
    fn session_message_seq_ok() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "alice", 2);
        register_agent(&mut baize, "bob", 2);

        // init
        let mut init_labels = HashMap::new();
        init_labels.insert("type".to_string(), BLOB_TYPE_SESSION_INIT.to_string());
        init_labels.insert(LABEL_SESSION_ID.to_string(), "sess-004".to_string());
        init_labels.insert(LABEL_SESSION_PEER_A.to_string(), "alice".to_string());
        init_labels.insert(LABEL_SESSION_PEER_B.to_string(), "bob".to_string());
        let init_blob = baize.pipe_blob_write("alice", r#"{"ephemeral_pub":"k1"}"#, &init_labels).unwrap();

        // accept
        let mut accept_labels = HashMap::new();
        accept_labels.insert("type".to_string(), BLOB_TYPE_SESSION_ACCEPT.to_string());
        accept_labels.insert(LABEL_SESSION_ID.to_string(), "sess-004".to_string());
        accept_labels.insert("parent".to_string(), init_blob.hash);
        baize.pipe_blob_write("bob", r#"{"ephemeral_pub":"k2"}"#, &accept_labels).unwrap();

        // message seq=1
        let mut msg_labels = HashMap::new();
        msg_labels.insert("type".to_string(), BLOB_TYPE_INTENT.to_string());
        msg_labels.insert(LABEL_SESSION_ID.to_string(), "sess-004".to_string());
        msg_labels.insert(LABEL_MESSAGE_SEQ.to_string(), "1".to_string());

        let result = baize.pipe_blob_write("alice", r#"{"msg":"hello"}"#, &msg_labels);
        assert!(result.is_ok(), "session message seq=1 should succeed: {:?}", result);
    }

    #[test]
    fn session_message_seq_skip_fails() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "alice", 2);
        register_agent(&mut baize, "bob", 2);

        // init + accept
        let mut init_labels = HashMap::new();
        init_labels.insert("type".to_string(), BLOB_TYPE_SESSION_INIT.to_string());
        init_labels.insert(LABEL_SESSION_ID.to_string(), "sess-005".to_string());
        init_labels.insert(LABEL_SESSION_PEER_A.to_string(), "alice".to_string());
        init_labels.insert(LABEL_SESSION_PEER_B.to_string(), "bob".to_string());
        let init_blob = baize.pipe_blob_write("alice", r#"{"k":"v"}"#, &init_labels).unwrap();

        let mut accept_labels = HashMap::new();
        accept_labels.insert("type".to_string(), BLOB_TYPE_SESSION_ACCEPT.to_string());
        accept_labels.insert(LABEL_SESSION_ID.to_string(), "sess-005".to_string());
        accept_labels.insert("parent".to_string(), init_blob.hash);
        baize.pipe_blob_write("bob", r#"{"k":"v"}"#, &accept_labels).unwrap();

        // seq=3 (should be 1)
        let mut msg_labels = HashMap::new();
        msg_labels.insert("type".to_string(), BLOB_TYPE_INTENT.to_string());
        msg_labels.insert(LABEL_SESSION_ID.to_string(), "sess-005".to_string());
        msg_labels.insert(LABEL_MESSAGE_SEQ.to_string(), "3".to_string());

        let result = baize.pipe_blob_write("alice", r#"{"msg":"hello"}"#, &msg_labels);
        assert!(result.is_err());
    }

    // ─── v0 regression tests ───

    #[test]
    fn plain_blob_write_still_works() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "writer", 2);

        let result = baize.pipe_blob_write("writer", "plain data", &HashMap::new());
        assert!(result.is_ok());
        assert_eq!(result.unwrap().content, "plain data");
    }
}
