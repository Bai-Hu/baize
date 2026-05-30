//! AZN 域校验函数：授权签发、委托子授权

use std::collections::HashMap;

use baize_core::constraint::verify_authz_constraint_reduction;
use baize_core::error::Error;
use baize_core::labels::*;
use baize_core::storage::BlobStore;

use crate::pipeline::{is_timestamp_expired, is_timestamp_after};

/// AZN-APR/AZN-ISS：授权签发写入校验
pub(crate) fn validate_authorization_blob(
    storage: &dyn BlobStore,
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

    // 校验 exp 不晚于意图 expires_at（DateTime 比较，避免字符串比较不准）
    let authz_exp = parsed.get("exp").and_then(|v| v.as_str()).unwrap_or("");
    let intent_expires = intent_blob.labels.get(LABEL_INTENT_EXPIRES)
        .map(|s| s.as_str())
        .unwrap_or("");
    if !authz_exp.is_empty() && !intent_expires.is_empty() {
        if is_timestamp_after(authz_exp, intent_expires).unwrap_or(false) {
            return Err(Error::Validation(
                "authorization exp cannot be later than intent expires_at".into()
            ));
        }
    }

    // AZN-DLG：如果有 parent_authz_digest，校验委托链
    if let Some(parent_digest) = parsed.get("parent_authz_digest").and_then(|v| v.as_str()) {
        validate_delegation(storage, &parsed, parent_digest)?;
    }

    Ok(())
}

/// AZN-DLG：委托子授权校验
pub(crate) fn validate_delegation(
    storage: &dyn BlobStore,
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
