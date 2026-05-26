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
use crate::pipeline::is_timestamp_expired;

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
        let identity = self.verify_write_agent(agent_id)?;

        // v1: 按 type label 分派校验
        let blob_type = labels.get("type").map(|s| s.as_str()).unwrap_or("");

        // Phase 4: IDN-ATH proof 强制 — Level 3+ 敏感操作需有效 proof（root 豁免）
        if identity.level >= 3 && agent_id != baize_core::ROOT_AGENT_ID && proof_required_for_blob_type(blob_type) {
            self.require_valid_proof(agent_id)?;
        }

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
                    // v2: 检查 intent 自身有效期
                    if let Some(expires) = labels.get(LABEL_INTENT_EXPIRES) {
                        if is_timestamp_expired(expires) {
                            return Err(Error::IntentExpired(
                                format!("intent expired at {}", expires)
                            ));
                        }
                    }
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
                    validate_session_init_blob(&self.storage, &self.agents, content, labels)?;
                }

                // ─── LNK-SES：会话接受 ───
                BLOB_TYPE_SESSION_ACCEPT => {
                    validate_session_accept_blob(&self.storage, content, labels, agent_id)?;
                }

                // ─── 其他类型：走原有逻辑 ───
                _ => {}
            }
        }

        let blob = self.storage.blob_write(content, labels)?;

        // P1: receipt 写入后自动 CNV 全链路校验（失败回滚）
        if blob.labels.get("type") == Some(&BLOB_TYPE_RECEIPT.to_string()) {
            let cnv_result = baize_asl::verify::cnv_verify(&self.storage, &blob.hash);
            match cnv_result {
                Ok(result) if !result.valid => {
                    let _ = self.storage.blob_delete(&blob.hash);
                    return Err(Error::ConstraintViolation(
                        format!("CNV verification failed: {}", result.errors.join("; "))
                    ));
                }
                Err(e) => {
                    let _ = self.storage.blob_delete(&blob.hash);
                    return Err(e);
                }
                _ => {}
            }
        }

        // P1: authorization 写入后自动 AZN-VER 校验（失败回滚）
        if blob.labels.get("type") == Some(&BLOB_TYPE_AUTHORIZATION.to_string()) {
            // 从 content 中读取 grant_type 作为 action_type（自动校验时无需外部指定）
            let action_type = serde_json::from_str::<serde_json::Value>(&blob.content)
                .ok()
                .and_then(|v| v.get("grant_type").and_then(|g| g.as_str()).map(String::from))
                .unwrap_or_else(|| "execute".to_string());
            let authz_result = baize_asl::verify::verify_authorization(
                &self.storage, &blob.hash, &action_type,
                &baize_asl::verify::ExecutionContext::default(),
            );
            match authz_result {
                Ok(result) if !result.valid => {
                    let _ = self.storage.blob_delete(&blob.hash);
                    return Err(Error::ConstraintViolation(
                        format!("AZN-VER failed: {}", result.errors.join("; "))
                    ));
                }
                Err(e) => {
                    let _ = self.storage.blob_delete(&blob.hash);
                    return Err(e);
                }
                _ => {}
            }
        }

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

// ─── v2 Phase 1.2: 有效期辅助函数 ───

/// Phase 4: 判断 blob type 是否需要 Level 3+ proof
fn proof_required_for_blob_type(blob_type: &str) -> bool {
    matches!(blob_type,
        BLOB_TYPE_AUTHORIZATION |
        BLOB_TYPE_RECEIPT |
        BLOB_TYPE_SESSION_INIT |
        BLOB_TYPE_SESSION_ACCEPT
    )
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

    // v2: 检查父意图是否已过期
    if let Some(parent_expires) = parent_blob.labels.get(LABEL_INTENT_EXPIRES) {
        if is_timestamp_expired(parent_expires) {
            return Err(Error::IntentExpired(
                format!("parent intent expired at {}", parent_expires)
            ));
        }
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

    // v2: 检查授权是否已过期
    let authz_parsed: serde_json::Value = serde_json::from_str(&authz_blob.content)
        .map_err(|e| Error::ChainBroken(format!("invalid authorization content: {}", e)))?;
    if let Some(authz_exp) = authz_parsed.get("exp").and_then(|v| v.as_str()) {
        if is_timestamp_expired(authz_exp) {
            return Err(Error::AuthorizationExpired(
                format!("authorization expired at {}", authz_exp)
            ));
        }
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

    // v2: 检查源意图是否已过期（时间维度）
    if let Some(intent_expires) = intent_blob.labels.get(LABEL_INTENT_EXPIRES) {
        if is_timestamp_expired(intent_expires) {
            return Err(Error::IntentExpired(
                format!("source intent expired at {}", intent_expires)
            ));
        }
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

/// LNK 加密套件白名单（当前仅支持 AES-256-GCM）
const KNOWN_CIPHER_SUITES: &[&str] = &["AES-256-GCM"];

/// LNK-SES：session-init 写入校验
fn validate_session_init_blob(
    storage: &Storage,
    agents: &std::collections::HashMap<String, (baize_core::cert::CertIdentity, baize_core::cert::IssuerCtx)>,
    content: &str,
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
fn validate_session_accept_blob(
    storage: &Storage,
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
    let init_content: serde_json::Value = serde_json::from_str(&init_blobs[0].content).unwrap_or_default();
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

    /// 辅助：生成一个合法的 X25519 公钥 PEM 片段（用于测试）
    fn gen_ephemeral_pub() -> String {
        let (_, pub_pem) = baize_core::crypto::generate_x25519_keypair().unwrap();
        // 提取 base64 部分（中间行）
        pub_pem.lines().find(|l| !l.starts_with('-')).unwrap().to_string()
    }

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

        let pub_a = gen_ephemeral_pub();
        let content = format!(r#"{{"ephemeral_pub":"{}","cipher_suites":["AES-256-GCM"]}}"#, pub_a);
        let result = baize.pipe_blob_write("alice", &content, &labels);
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

        let pub_a = gen_ephemeral_pub();
        let content = format!(r#"{{"ephemeral_pub":"{}","cipher_suites":["AES-256-GCM"]}}"#, pub_a);
        let result = baize.pipe_blob_write("alice", &content, &labels);
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

        let pub_a = gen_ephemeral_pub();
        let init_content = format!(r#"{{"ephemeral_pub":"{}","cipher_suites":["AES-256-GCM"]}}"#, pub_a);
        let init_blob = baize.pipe_blob_write("alice", &init_content, &init_labels).unwrap();

        let mut accept_labels = HashMap::new();
        accept_labels.insert("type".to_string(), BLOB_TYPE_SESSION_ACCEPT.to_string());
        accept_labels.insert(LABEL_SESSION_ID.to_string(), "sess-003".to_string());
        accept_labels.insert("parent".to_string(), init_blob.hash);

        let pub_b = gen_ephemeral_pub();
        let accept_content = format!(r#"{{"ephemeral_pub":"{}","selected_cipher_suite":"AES-256-GCM"}}"#, pub_b);
        let result = baize.pipe_blob_write("bob", &accept_content, &accept_labels);
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
        let pub_a = gen_ephemeral_pub();
        let init_blob = baize.pipe_blob_write("alice", &format!(r#"{{"ephemeral_pub":"{}","cipher_suites":["AES-256-GCM"]}}"#, pub_a), &init_labels).unwrap();

        // accept
        let mut accept_labels = HashMap::new();
        accept_labels.insert("type".to_string(), BLOB_TYPE_SESSION_ACCEPT.to_string());
        accept_labels.insert(LABEL_SESSION_ID.to_string(), "sess-004".to_string());
        accept_labels.insert("parent".to_string(), init_blob.hash);
        let pub_b = gen_ephemeral_pub();
        baize.pipe_blob_write("bob", &format!(r#"{{"ephemeral_pub":"{}","selected_cipher_suite":"AES-256-GCM"}}"#, pub_b), &accept_labels).unwrap();

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
        let pub_a = gen_ephemeral_pub();
        let init_blob = baize.pipe_blob_write("alice", &format!(r#"{{"ephemeral_pub":"{}","cipher_suites":["AES-256-GCM"]}}"#, pub_a), &init_labels).unwrap();

        let mut accept_labels = HashMap::new();
        accept_labels.insert("type".to_string(), BLOB_TYPE_SESSION_ACCEPT.to_string());
        accept_labels.insert(LABEL_SESSION_ID.to_string(), "sess-005".to_string());
        accept_labels.insert("parent".to_string(), init_blob.hash);
        let pub_b = gen_ephemeral_pub();
        baize.pipe_blob_write("bob", &format!(r#"{{"ephemeral_pub":"{}","selected_cipher_suite":"AES-256-GCM"}}"#, pub_b), &accept_labels).unwrap();

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

    // ─── v2 Phase 1.2: 有效期运行时检查 ───

    #[test]
    fn intent_write_already_expired_fails() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "writer", 2);

        let content = serde_json::json!({
            "intent_id": "int-exp",
            "intent_constraints": {"budget": 100},
            "created_at": "2020-01-01T00:00:00Z",
            "expires_at": "2020-12-31T23:59:59Z",
        }).to_string();

        let mut labels = HashMap::new();
        labels.insert("type".to_string(), BLOB_TYPE_INTENT.to_string());
        labels.insert(LABEL_INTENT_EXPIRES.to_string(), "2020-12-31T23:59:59Z".to_string());

        let result = baize.pipe_blob_write("writer", &content, &labels);
        assert!(result.is_err(), "expired intent should be rejected");
        match result {
            Err(Error::IntentExpired(msg)) => assert!(msg.contains("2020-12-31")),
            other => panic!("expected IntentExpired, got {:?}", other),
        }
    }

    #[test]
    fn sub_intent_expired_parent_fails() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "writer", 2);

        // 用 storage 直接写一个已过期的父意图（绕过 intent 自身过期检查）
        let mut parent_labels = HashMap::new();
        parent_labels.insert("type".to_string(), BLOB_TYPE_INTENT.to_string());
        parent_labels.insert(LABEL_INTENT_EXPIRES.to_string(), "2020-12-31T23:59:59Z".to_string());
        parent_labels.insert(LABEL_DERIVATION_DEPTH.to_string(), "0".to_string());
        let parent_blob = baize.storage.blob_write(
            "{\"intent_constraints\":{\"budget\":200}}", &parent_labels
        ).unwrap();

        // 尝试从过期父意图派生子意图
        let child_content = serde_json::json!({
            "parent_intent_digest": parent_blob.hash,
            "derivation_depth": 1,
            "intent_constraints": {"budget": 100},
            "expires_at": "2099-06-01T00:00:00Z",
        }).to_string();

        let mut child_labels = HashMap::new();
        child_labels.insert("type".to_string(), BLOB_TYPE_SUB_INTENT.to_string());
        child_labels.insert(LABEL_DERIVATION_DEPTH.to_string(), "1".to_string());

        let result = baize.pipe_blob_write("writer", &child_content, &child_labels);
        assert!(result.is_err(), "sub-intent from expired parent should be rejected");
        match result {
            Err(Error::IntentExpired(msg)) => assert!(msg.contains("parent")),
            other => panic!("expected IntentExpired, got {:?}", other),
        }
    }

    #[test]
    fn receipt_expired_authz_fails() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "writer", 2);

        // 用 storage 直接写 intent 和已过期的 authz
        let mut intent_labels = HashMap::new();
        intent_labels.insert("type".to_string(), BLOB_TYPE_INTENT.to_string());
        intent_labels.insert(LABEL_INTENT_EXPIRES.to_string(), "2099-12-31T23:59:59Z".to_string());
        let intent_blob = baize.storage.blob_write("{}", &intent_labels).unwrap();

        let authz_content = serde_json::json!({
            "exp": "2020-12-31T23:59:59Z",
            "constraints": {"budget": 100}
        }).to_string();
        let mut authz_labels = HashMap::new();
        authz_labels.insert("type".to_string(), BLOB_TYPE_AUTHORIZATION.to_string());
        authz_labels.insert(LABEL_AUTHZ_STATUS.to_string(), "valid".to_string());
        let authz_blob = baize.storage.blob_write(&authz_content, &authz_labels).unwrap();

        let receipt_content = serde_json::json!({
            "intent_digest": intent_blob.hash,
            "authorization_digest": authz_blob.hash,
            "result_status": "SUCCESS",
        }).to_string();

        let mut labels = HashMap::new();
        labels.insert("type".to_string(), BLOB_TYPE_RECEIPT.to_string());

        let result = baize.pipe_blob_write("writer", &receipt_content, &labels);
        assert!(result.is_err(), "receipt with expired authz should be rejected");
        match result {
            Err(Error::AuthorizationExpired(msg)) => assert!(msg.contains("2020-12-31")),
            other => panic!("expected AuthorizationExpired, got {:?}", other),
        }
    }

    #[test]
    fn intent_write_future_expires_ok() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "writer", 2);

        let content = serde_json::json!({
            "intent_id": "int-future",
            "intent_constraints": {"budget": 100},
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": "2099-12-31T23:59:59Z",
        }).to_string();

        let mut labels = HashMap::new();
        labels.insert("type".to_string(), BLOB_TYPE_INTENT.to_string());
        labels.insert(LABEL_INTENT_ID.to_string(), "int-future".to_string());
        labels.insert(LABEL_INTENT_STATUS.to_string(), "active".to_string());
        labels.insert(LABEL_INTENT_EXPIRES.to_string(), "2099-12-31T23:59:59Z".to_string());

        let result = baize.pipe_blob_write("writer", &content, &labels);
        assert!(result.is_ok(), "future intent should be accepted: {:?}", result);
    }

    #[test]
    fn receipt_corrupt_authz_fails() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "writer", 2);

        // 用 storage 直接写 intent
        let mut intent_labels = HashMap::new();
        intent_labels.insert("type".to_string(), BLOB_TYPE_INTENT.to_string());
        intent_labels.insert(LABEL_INTENT_EXPIRES.to_string(), "2099-12-31T23:59:59Z".to_string());
        let intent_blob = baize.storage.blob_write("{}", &intent_labels).unwrap();

        // 写一个 content 为非法 JSON 的 authz blob
        let mut authz_labels = HashMap::new();
        authz_labels.insert("type".to_string(), BLOB_TYPE_AUTHORIZATION.to_string());
        authz_labels.insert(LABEL_AUTHZ_STATUS.to_string(), "valid".to_string());
        let authz_blob = baize.storage.blob_write("not valid json!!!", &authz_labels).unwrap();

        let receipt_content = serde_json::json!({
            "intent_digest": intent_blob.hash,
            "authorization_digest": authz_blob.hash,
            "result_status": "SUCCESS",
        }).to_string();

        let mut labels = HashMap::new();
        labels.insert("type".to_string(), BLOB_TYPE_RECEIPT.to_string());

        let result = baize.pipe_blob_write("writer", &receipt_content, &labels);
        assert!(result.is_err(), "receipt with corrupt authz should be rejected");
        match result {
            Err(Error::ChainBroken(msg)) => assert!(msg.contains("invalid authorization content")),
            other => panic!("expected ChainBroken, got {:?}", other),
        }
    }

    // ─── P1: baize-asl 桥接测试 ───

    /// 辅助：构造 CNV 能通过的完整 receipt content（ASL payload 格式）
    fn make_valid_receipt_content(intent_hash: &str, authz_hash: &str) -> String {
        serde_json::json!({
            "receipt_id": "rct-cnv-001",
            "executor_id": "writer",
            "task_id": "task-001",
            "action_type": "execute",
            "intent_digest": intent_hash,
            "authorization_digest": authz_hash,
            "result_status": "SUCCEEDED",
            "started_at": "2026-01-01T00:00:00Z",
            "finished_at": "2026-01-01T00:01:00Z",
        }).to_string()
    }

    /// 辅助：构造 AZN-VER 能通过的 authorization content（ASL payload 格式）
    fn make_valid_authz_content(intent_hash: &str) -> String {
        serde_json::json!({
            "authorization_id": "authz-001",
            "issuer": "baize-root",
            "subject": "writer",
            "grant_type": "execute",
            "constraints": {"target_scope": ["zone-A"]},
            "delegatable": false,
            "source_intent_digest": intent_hash,
            "root_authorizer": "baize-root",
            "nbf": "2026-01-01T00:00:00Z",
            "exp": "2099-12-31T23:59:59Z",
            "iat": "2026-01-01T00:00:00Z",
            "jti": "jti-001",
            "version": "1.0",
        }).to_string()
    }

    #[test]
    fn receipt_write_triggers_cnv_ok() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "writer", 2);

        // 1. 写 intent（带完整 ASL labels）
        let intent_content = serde_json::json!({
            "intent_id": "int-cnv",
            "intent_owner": "writer",
            "intent_creator": "writer",
            "intent_goal": "deploy",
            "intent_constraints": {"budget": 100},
            "version": "1.0",
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": "2099-12-31T23:59:59Z",
        }).to_string();
        let mut intent_labels = HashMap::new();
        intent_labels.insert("type".to_string(), BLOB_TYPE_INTENT.to_string());
        intent_labels.insert(LABEL_INTENT_ID.to_string(), "int-cnv".to_string());
        intent_labels.insert(LABEL_INTENT_STATUS.to_string(), "active".to_string());
        intent_labels.insert(LABEL_INTENT_EXPIRES.to_string(), "2099-12-31T23:59:59Z".to_string());
        let intent_blob = baize.pipe_blob_write("writer", &intent_content, &intent_labels).unwrap();

        // 2. 写 authorization（带完整 ASL labels）
        let authz_content = make_valid_authz_content(&intent_blob.hash);
        let mut authz_labels = HashMap::new();
        authz_labels.insert("type".to_string(), BLOB_TYPE_AUTHORIZATION.to_string());
        authz_labels.insert(LABEL_AUTHZ_STATUS.to_string(), "valid".to_string());
        authz_labels.insert(LABEL_SOURCE_INTENT.to_string(), intent_blob.hash.clone());
        let authz_blob = baize.storage.blob_write(&authz_content, &authz_labels).unwrap();

        // 3. 写 receipt → 触发 CNV 自动校验
        let receipt_content = make_valid_receipt_content(&intent_blob.hash, &authz_blob.hash);
        let mut receipt_labels = HashMap::new();
        receipt_labels.insert("type".to_string(), BLOB_TYPE_RECEIPT.to_string());
        receipt_labels.insert(LABEL_RECEIPT_INTENT.to_string(), intent_blob.hash.clone());
        receipt_labels.insert(LABEL_RECEIPT_AUTHZ.to_string(), authz_blob.hash.clone());

        let result = baize.pipe_blob_write("writer", &receipt_content, &receipt_labels);
        assert!(result.is_ok(), "receipt with valid CNV chain should succeed: {:?}", result);
    }

    #[test]
    fn receipt_write_cnv_source_intent_mismatch_fails() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "writer", 2);

        // 写一个 intent
        let mut intent_labels = HashMap::new();
        intent_labels.insert("type".to_string(), BLOB_TYPE_INTENT.to_string());
        intent_labels.insert(LABEL_INTENT_ID.to_string(), "int-mismatch".to_string());
        intent_labels.insert(LABEL_INTENT_STATUS.to_string(), "active".to_string());
        intent_labels.insert(LABEL_INTENT_EXPIRES.to_string(), "2099-12-31T23:59:59Z".to_string());
        let intent_blob = baize.storage.blob_write(
            &serde_json::json!({
                "intent_id": "int-mismatch",
                "intent_constraints": {"budget": 100},
                "created_at": "2026-01-01T00:00:00Z",
                "expires_at": "2099-12-31T23:59:59Z",
            }).to_string(),
            &intent_labels,
        ).unwrap();

        // 写另一个无关的 intent（用作 authz 的错误 source）
        let mut other_intent_labels = HashMap::new();
        other_intent_labels.insert("type".to_string(), BLOB_TYPE_INTENT.to_string());
        other_intent_labels.insert(LABEL_INTENT_ID.to_string(), "int-other".to_string());
        other_intent_labels.insert(LABEL_INTENT_STATUS.to_string(), "active".to_string());
        other_intent_labels.insert(LABEL_INTENT_EXPIRES.to_string(), "2099-12-31T23:59:59Z".to_string());
        let other_intent_blob = baize.storage.blob_write(
            &serde_json::json!({"intent_id": "int-other", "intent_constraints": {"budget": 50}}).to_string(),
            &other_intent_labels,
        ).unwrap();

        // 写 authorization，source 指向另一个 intent（不匹配 receipt 的 intent）
        let authz_content = make_valid_authz_content(&other_intent_blob.hash);
        let mut authz_labels = HashMap::new();
        authz_labels.insert("type".to_string(), BLOB_TYPE_AUTHORIZATION.to_string());
        authz_labels.insert(LABEL_AUTHZ_STATUS.to_string(), "valid".to_string());
        authz_labels.insert(LABEL_SOURCE_INTENT.to_string(), other_intent_blob.hash.clone());
        let authz_blob = baize.storage.blob_write(&authz_content, &authz_labels).unwrap();

        // 写 receipt → CNV 校验发现 source_intent_digest 不在 intent chain 中
        let receipt_content = make_valid_receipt_content(&intent_blob.hash, &authz_blob.hash);
        let mut receipt_labels = HashMap::new();
        receipt_labels.insert("type".to_string(), BLOB_TYPE_RECEIPT.to_string());
        receipt_labels.insert(LABEL_RECEIPT_INTENT.to_string(), intent_blob.hash.clone());
        receipt_labels.insert(LABEL_RECEIPT_AUTHZ.to_string(), authz_blob.hash.clone());

        let result = baize.pipe_blob_write("writer", &receipt_content, &receipt_labels);
        assert!(result.is_err(), "receipt with CNV source_intent mismatch should fail");
        match result {
            Err(Error::ConstraintViolation(msg)) => assert!(msg.contains("source_intent_digest"), "expected CNV error, got: {}", msg),
            other => panic!("expected ConstraintViolation, got {:?}", other),
        }
    }

    #[test]
    fn authz_write_triggers_azn_ver_ok() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "writer", 2);

        // 写 intent
        let mut intent_labels = HashMap::new();
        intent_labels.insert("type".to_string(), BLOB_TYPE_INTENT.to_string());
        intent_labels.insert(LABEL_INTENT_ID.to_string(), "int-azn".to_string());
        intent_labels.insert(LABEL_INTENT_STATUS.to_string(), "active".to_string());
        intent_labels.insert(LABEL_INTENT_EXPIRES.to_string(), "2099-12-31T23:59:59Z".to_string());
        let intent_blob = baize.storage.blob_write(
            &serde_json::json!({
                "intent_id": "int-azn",
                "intent_constraints": {"budget": 100},
                "created_at": "2026-01-01T00:00:00Z",
                "expires_at": "2099-12-31T23:59:59Z",
            }).to_string(),
            &intent_labels,
        ).unwrap();

        // 写 authorization → 触发 AZN-VER 自动校验
        let authz_content = make_valid_authz_content(&intent_blob.hash);
        let mut authz_labels = HashMap::new();
        authz_labels.insert("type".to_string(), BLOB_TYPE_AUTHORIZATION.to_string());
        authz_labels.insert(LABEL_AUTHZ_STATUS.to_string(), "valid".to_string());
        authz_labels.insert(LABEL_SOURCE_INTENT.to_string(), intent_blob.hash.clone());

        let result = baize.pipe_blob_write("writer", &authz_content, &authz_labels);
        assert!(result.is_ok(), "authz with valid AZN-VER should succeed: {:?}", result);
    }

    #[test]
    fn authz_write_azn_ver_expired_fails() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "writer", 2);

        // 写 intent
        let mut intent_labels = HashMap::new();
        intent_labels.insert("type".to_string(), BLOB_TYPE_INTENT.to_string());
        intent_labels.insert(LABEL_INTENT_ID.to_string(), "int-exp-azn".to_string());
        intent_labels.insert(LABEL_INTENT_STATUS.to_string(), "active".to_string());
        intent_labels.insert(LABEL_INTENT_EXPIRES.to_string(), "2099-12-31T23:59:59Z".to_string());
        let intent_blob = baize.storage.blob_write(
            &serde_json::json!({
                "intent_id": "int-exp-azn",
                "intent_constraints": {"budget": 100},
            }).to_string(),
            &intent_labels,
        ).unwrap();

        // 写已过期的 authorization → AZN-VER 校验二失败
        let expired_authz_content = serde_json::json!({
            "authorization_id": "authz-exp",
            "issuer": "baize-root",
            "subject": "writer",
            "grant_type": "execute",
            "constraints": {"target_scope": ["zone-A"]},
            "delegatable": false,
            "source_intent_digest": intent_blob.hash,
            "root_authorizer": "baize-root",
            "nbf": "2020-01-01T00:00:00Z",
            "exp": "2020-12-31T23:59:59Z",
            "iat": "2020-01-01T00:00:00Z",
            "jti": "jti-exp",
            "version": "1.0",
        }).to_string();
        let mut authz_labels = HashMap::new();
        authz_labels.insert("type".to_string(), BLOB_TYPE_AUTHORIZATION.to_string());
        authz_labels.insert(LABEL_AUTHZ_STATUS.to_string(), "valid".to_string());
        authz_labels.insert(LABEL_SOURCE_INTENT.to_string(), intent_blob.hash.clone());

        let result = baize.pipe_blob_write("writer", &expired_authz_content, &authz_labels);
        assert!(result.is_err(), "expired authz should fail AZN-VER");
        match result {
            Err(Error::ConstraintViolation(msg)) => assert!(msg.contains("expired") || msg.contains("AZN-VER"), "expected AZN-VER expiry error, got: {}", msg),
            other => panic!("expected ConstraintViolation, got {:?}", other),
        }
    }

    // ─── Phase 3: session 校验增强测试 ───

    #[test]
    fn session_init_requires_ephemeral_pub() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "alice", 2);
        register_agent(&mut baize, "bob", 2);

        let mut labels = HashMap::new();
        labels.insert("type".to_string(), BLOB_TYPE_SESSION_INIT.to_string());
        labels.insert(LABEL_SESSION_ID.to_string(), "sess-no-eph".to_string());
        labels.insert(LABEL_SESSION_PEER_A.to_string(), "alice".to_string());
        labels.insert(LABEL_SESSION_PEER_B.to_string(), "bob".to_string());

        // 缺少 ephemeral_pub
        let result = baize.pipe_blob_write("alice", r#"{"cipher_suites":["AES-256-GCM"]}"#, &labels);
        assert!(result.is_err());
        match result {
            Err(Error::Validation(msg)) => assert!(msg.contains("ephemeral_pub"), "got: {}", msg),
            other => panic!("expected Validation, got {:?}", other),
        }
    }

    #[test]
    fn session_init_requires_aes_256_gcm_cipher_suite() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "alice", 2);
        register_agent(&mut baize, "bob", 2);

        let mut labels = HashMap::new();
        labels.insert("type".to_string(), BLOB_TYPE_SESSION_INIT.to_string());
        labels.insert(LABEL_SESSION_ID.to_string(), "sess-no-cipher".to_string());
        labels.insert(LABEL_SESSION_PEER_A.to_string(), "alice".to_string());
        labels.insert(LABEL_SESSION_PEER_B.to_string(), "bob".to_string());

        // cipher_suites 不包含 AES-256-GCM（ephemeral_pub 需要合法格式）
        let pub_a = gen_ephemeral_pub();
        let result = baize.pipe_blob_write("alice", &format!(r#"{{"ephemeral_pub":"{}","cipher_suites":["ChaCha20-Poly1305"]}}"#, pub_a), &labels);
        assert!(result.is_err());
        match result {
            Err(Error::Validation(msg)) => assert!(msg.contains("AES-256-GCM"), "got: {}", msg),
            other => panic!("expected Validation, got {:?}", other),
        }
    }

    #[test]
    fn session_accept_requires_ephemeral_pub() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "alice", 2);
        register_agent(&mut baize, "bob", 2);

        // init
        let mut init_labels = HashMap::new();
        init_labels.insert("type".to_string(), BLOB_TYPE_SESSION_INIT.to_string());
        init_labels.insert(LABEL_SESSION_ID.to_string(), "sess-accept-no-eph".to_string());
        init_labels.insert(LABEL_SESSION_PEER_A.to_string(), "alice".to_string());
        init_labels.insert(LABEL_SESSION_PEER_B.to_string(), "bob".to_string());
        let pub_a = gen_ephemeral_pub();
        let init_blob = baize.pipe_blob_write("alice", &format!(r#"{{"ephemeral_pub":"{}","cipher_suites":["AES-256-GCM"]}}"#, pub_a), &init_labels).unwrap();

        let mut accept_labels = HashMap::new();
        accept_labels.insert("type".to_string(), BLOB_TYPE_SESSION_ACCEPT.to_string());
        accept_labels.insert(LABEL_SESSION_ID.to_string(), "sess-accept-no-eph".to_string());
        accept_labels.insert("parent".to_string(), init_blob.hash);

        // 缺少 ephemeral_pub
        let result = baize.pipe_blob_write("bob", r#"{"selected_cipher_suite":"AES-256-GCM"}"#, &accept_labels);
        assert!(result.is_err());
        match result {
            Err(Error::Validation(msg)) => assert!(msg.contains("ephemeral_pub"), "got: {}", msg),
            other => panic!("expected Validation, got {:?}", other),
        }
    }

    #[test]
    fn session_accept_cipher_suite_mismatch_fails() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "alice", 2);
        register_agent(&mut baize, "bob", 2);

        // init
        let mut init_labels = HashMap::new();
        init_labels.insert("type".to_string(), BLOB_TYPE_SESSION_INIT.to_string());
        init_labels.insert(LABEL_SESSION_ID.to_string(), "sess-cipher-mismatch".to_string());
        init_labels.insert(LABEL_SESSION_PEER_A.to_string(), "alice".to_string());
        init_labels.insert(LABEL_SESSION_PEER_B.to_string(), "bob".to_string());
        let pub_a = gen_ephemeral_pub();
        let init_blob = baize.pipe_blob_write("alice", &format!(r#"{{"ephemeral_pub":"{}","cipher_suites":["AES-256-GCM"]}}"#, pub_a), &init_labels).unwrap();

        let mut accept_labels = HashMap::new();
        accept_labels.insert("type".to_string(), BLOB_TYPE_SESSION_ACCEPT.to_string());
        accept_labels.insert(LABEL_SESSION_ID.to_string(), "sess-cipher-mismatch".to_string());
        accept_labels.insert("parent".to_string(), init_blob.hash);

        // selected_cipher_suite 不在 init 的 cipher_suites 中（ephemeral_pub 需合法）
        let pub_b = gen_ephemeral_pub();
        let result = baize.pipe_blob_write("bob", &format!(r#"{{"ephemeral_pub":"{}","selected_cipher_suite":"ChaCha20-Poly1305"}}"#, pub_b), &accept_labels);
        assert!(result.is_err());
        match result {
            Err(Error::Validation(msg)) => assert!(msg.contains("selected_cipher_suite"), "got: {}", msg),
            other => panic!("expected Validation, got {:?}", other),
        }
    }

    #[test]
    fn session_message_after_close_rejected() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "alice", 2);
        register_agent(&mut baize, "bob", 2);

        // init
        let mut init_labels = HashMap::new();
        init_labels.insert("type".to_string(), BLOB_TYPE_SESSION_INIT.to_string());
        init_labels.insert(LABEL_SESSION_ID.to_string(), "sess-close-msg".to_string());
        init_labels.insert(LABEL_SESSION_PEER_A.to_string(), "alice".to_string());
        init_labels.insert(LABEL_SESSION_PEER_B.to_string(), "bob".to_string());
        let pub_a = gen_ephemeral_pub();
        let init_blob = baize.pipe_blob_write("alice", &format!(r#"{{"ephemeral_pub":"{}","cipher_suites":["AES-256-GCM"]}}"#, pub_a), &init_labels).unwrap();

        // accept
        let mut accept_labels = HashMap::new();
        accept_labels.insert("type".to_string(), BLOB_TYPE_SESSION_ACCEPT.to_string());
        accept_labels.insert(LABEL_SESSION_ID.to_string(), "sess-close-msg".to_string());
        accept_labels.insert("parent".to_string(), init_blob.hash);
        let pub_b = gen_ephemeral_pub();
        baize.pipe_blob_write("bob", &format!(r#"{{"ephemeral_pub":"{}","selected_cipher_suite":"AES-256-GCM"}}"#, pub_b), &accept_labels).unwrap();

        // close session（直接写 session-close blob）
        let close_content = serde_json::json!({
            "session_id": "sess-close-msg",
            "action": "close",
            "closed_by": "alice",
        }).to_string();
        let mut close_labels = HashMap::new();
        close_labels.insert("type".to_string(), "session-close".to_string());
        close_labels.insert(LABEL_SESSION_ID.to_string(), "sess-close-msg".to_string());
        close_labels.insert(LABEL_SESSION_STATUS.to_string(), "closed".to_string());
        baize.storage.blob_write(&close_content, &close_labels).unwrap();

        // 尝试在关闭后发 message → 应被拒绝
        let mut msg_labels = HashMap::new();
        msg_labels.insert("type".to_string(), BLOB_TYPE_INTENT.to_string());
        msg_labels.insert(LABEL_SESSION_ID.to_string(), "sess-close-msg".to_string());
        msg_labels.insert(LABEL_MESSAGE_SEQ.to_string(), "1".to_string());

        let result = baize.pipe_blob_write("alice", r#"{"msg":"after close"}"#, &msg_labels);
        assert!(result.is_err(), "message after session close should be rejected");
        match result {
            Err(Error::Validation(msg)) => assert!(msg.contains("closed"), "got: {}", msg),
            other => panic!("expected Validation, got {:?}", other),
        }
    }

    #[test]
    fn session_message_expired_session_rejected() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "alice", 2);
        register_agent(&mut baize, "bob", 2);

        // init with past expires_at（直接写入 storage 绕过管道创建已过期的 session）
        let mut init_labels = HashMap::new();
        init_labels.insert("type".to_string(), BLOB_TYPE_SESSION_INIT.to_string());
        init_labels.insert(LABEL_SESSION_ID.to_string(), "sess-expired".to_string());
        init_labels.insert(LABEL_SESSION_PEER_A.to_string(), "alice".to_string());
        init_labels.insert(LABEL_SESSION_PEER_B.to_string(), "bob".to_string());
        let pub_a = gen_ephemeral_pub();
        let past = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        let init_content = format!(
            r#"{{"ephemeral_pub":"{}","cipher_suites":["AES-256-GCM"],"expires_at":"{}"}}"#,
            pub_a, past
        );
        baize.storage.blob_write(&init_content, &init_labels).unwrap();

        // accept（直接写入 storage）
        let mut accept_labels = HashMap::new();
        accept_labels.insert("type".to_string(), BLOB_TYPE_SESSION_ACCEPT.to_string());
        accept_labels.insert(LABEL_SESSION_ID.to_string(), "sess-expired".to_string());
        let pub_b = gen_ephemeral_pub();
        baize.storage.blob_write(
            &format!(r#"{{"ephemeral_pub":"{}","selected_cipher_suite":"AES-256-GCM"}}"#, pub_b),
            &accept_labels,
        ).unwrap();

        // 尝试在过期 session 发 message → 应被拒绝
        let mut msg_labels = HashMap::new();
        msg_labels.insert("type".to_string(), BLOB_TYPE_INTENT.to_string());
        msg_labels.insert(LABEL_SESSION_ID.to_string(), "sess-expired".to_string());
        msg_labels.insert(LABEL_MESSAGE_SEQ.to_string(), "1".to_string());

        let result = baize.pipe_blob_write("alice", r#"{"msg":"after expire"}"#, &msg_labels);
        assert!(result.is_err(), "message to expired session should be rejected");
        match result {
            Err(Error::Validation(msg)) => assert!(msg.contains("expired"), "got: {}", msg),
            other => panic!("expected Validation, got {:?}", other),
        }
    }
}
