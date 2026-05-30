//! INT 域校验函数：意图写入、子意图派生、执行回执

use std::collections::HashMap;

use baize_core::constraint::verify_intent_constraint_reduction;
use baize_core::error::Error;
use baize_core::labels::*;
use baize_core::storage::BlobStore;

use crate::pipeline::{is_timestamp_expired, is_timestamp_after};

/// INT-GIR：通用意图写入校验
pub(crate) fn validate_intent_blob(
    storage: &dyn BlobStore,
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

    // v2: 检查 intent label 中的自身有效期（x-intent-expires）
    if let Some(expires) = labels.get(LABEL_INTENT_EXPIRES) {
        if is_timestamp_expired(expires) {
            return Err(Error::IntentExpired(
                format!("intent expired at {}", expires)
            ));
        }
    }

    Ok(())
}

/// INT-DER：子意图派生写入校验
pub(crate) fn validate_sub_intent_blob(
    storage: &dyn BlobStore,
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
        .map_err(|e| Error::ChainBroken(format!("parent intent {} has invalid JSON content: {}", parent_digest, e)))?;
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

    // 校验 expires_at 不晚于父 expires_at（DateTime 比较，避免字符串比较不准）
    let child_expires = parsed.get("expires_at").and_then(|v| v.as_str()).unwrap_or("");
    let parent_expires = parent_blob.labels.get(LABEL_INTENT_EXPIRES)
        .map(|s| s.as_str())
        .unwrap_or("");
    if !child_expires.is_empty() && !parent_expires.is_empty() {
        if is_timestamp_after(child_expires, parent_expires).unwrap_or(false) {
            return Err(Error::Validation(
                "sub-intent expires_at cannot be later than parent expires_at".into()
            ));
        }
    }

    Ok(())
}

/// INT-RCT：执行回执写入校验
pub(crate) fn validate_receipt_blob(
    storage: &dyn BlobStore,
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
