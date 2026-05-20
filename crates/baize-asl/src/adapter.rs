//! ASL payload ↔ blob+label 双向转换 + binding_context_digest 计算（V1_DEV §5.2）
//!
//! 适配层负责：
//! - 将 IntentContent/SubIntentContent/ReceiptContent/AuthorizationContent 转为 blob labels
//! - 从 blob content 反序列化为 ASL 载荷
//! - 计算 IDN-ATT 的 binding_context_digest

use std::collections::HashMap;

use sha2::{Digest, Sha256};

use baize_core::error::Error;
use baize_core::labels::*;

use crate::payload::*;

/// ASL 适配器 — 无状态，所有方法接收数据做转换
pub struct AslAdapter;

/// ReceiptStatus → SCREAMING_SNAKE_CASE 字符串
pub fn receipt_status_to_str(status: &ReceiptStatus) -> &'static str {
    match status {
        ReceiptStatus::Succeeded => "SUCCEEDED",
        ReceiptStatus::Failed => "FAILED",
        ReceiptStatus::Partial => "PARTIAL",
        ReceiptStatus::Rejected => "REJECTED",
        ReceiptStatus::Cancelled => "CANCELLED",
        ReceiptStatus::Expired => "EXPIRED",
    }
}

impl AslAdapter {
    // ─── Payload → blob labels ───

    /// 从 IntentContent 生成 blob labels
    pub fn intent_to_labels(content: &IntentContent) -> HashMap<String, String> {
        let mut labels = HashMap::new();
        labels.insert("type".to_string(), BLOB_TYPE_INTENT.to_string());
        labels.insert(LABEL_INTENT_ID.to_string(), content.intent_id.clone());
        labels.insert(LABEL_INTENT_OWNER.to_string(), content.intent_owner.clone());
        labels.insert(LABEL_INTENT_STATUS.to_string(), "active".to_string());
        labels.insert(LABEL_INTENT_EXPIRES.to_string(), content.expires_at.clone());
        labels
    }

    /// 从 SubIntentContent 生成 blob labels
    pub fn sub_intent_to_labels(content: &SubIntentContent) -> HashMap<String, String> {
        let mut labels = HashMap::new();
        labels.insert("type".to_string(), BLOB_TYPE_SUB_INTENT.to_string());
        labels.insert(LABEL_INTENT_ID.to_string(), content.sub_intent_id.clone());
        labels.insert(LABEL_INTENT_OWNER.to_string(), content.deriver_id.clone());
        labels.insert(LABEL_INTENT_STATUS.to_string(), "active".to_string());
        labels.insert(LABEL_INTENT_EXPIRES.to_string(), content.expires_at.clone());
        labels.insert(LABEL_PARENT_INTENT.to_string(), content.parent_intent_digest.clone());
        labels.insert(LABEL_DERIVATION_DEPTH.to_string(), content.derivation_depth.to_string());
        labels
    }

    /// 从 ReceiptContent 生成 blob labels
    pub fn receipt_to_labels(content: &ReceiptContent) -> HashMap<String, String> {
        let mut labels = HashMap::new();
        labels.insert("type".to_string(), BLOB_TYPE_RECEIPT.to_string());
        labels.insert(LABEL_RECEIPT_ID.to_string(), content.receipt_id.clone());
        labels.insert(LABEL_RECEIPT_EXECUTOR.to_string(), content.executor_id.clone());
        labels.insert(
            LABEL_RECEIPT_STATUS.to_string(),
            receipt_status_to_str(&content.result_status).to_string(),
        );
        labels.insert(LABEL_RECEIPT_INTENT.to_string(), content.intent_digest.clone());
        labels.insert(LABEL_RECEIPT_AUTHZ.to_string(), content.authorization_digest.clone());
        labels
    }

    /// 从 AuthorizationContent 生成 blob labels
    pub fn authorization_to_labels(content: &AuthorizationContent) -> HashMap<String, String> {
        let mut labels = HashMap::new();
        labels.insert("type".to_string(), BLOB_TYPE_AUTHORIZATION.to_string());
        labels.insert(LABEL_AUTHZ_ID.to_string(), content.authorization_id.clone());
        labels.insert(LABEL_AUTHZ_ISSUER.to_string(), content.issuer.clone());
        labels.insert(LABEL_AUTHZ_SUBJECT.to_string(), content.subject.clone());
        labels.insert(LABEL_AUTHZ_STATUS.to_string(), "valid".to_string());
        labels.insert(LABEL_SOURCE_INTENT.to_string(), content.source_intent_digest.clone());
        if let Some(ref parent) = content.parent_authz_digest {
            labels.insert(LABEL_PARENT_AUTHZ.to_string(), parent.clone());
        }
        labels
    }

    // ─── blob content → Payload（统一返回 Error） ───

    /// 从 blob content 反序列化 IntentContent
    pub fn intent_from_blob(content: &str) -> Result<IntentContent, Error> {
        serde_json::from_str(content)
            .map_err(|e| Error::Validation(format!("invalid intent content: {}", e)))
    }

    /// 从 blob content 反序列化 SubIntentContent
    pub fn sub_intent_from_blob(content: &str) -> Result<SubIntentContent, Error> {
        serde_json::from_str(content)
            .map_err(|e| Error::Validation(format!("invalid sub-intent content: {}", e)))
    }

    /// 从 blob content 反序列化 ReceiptContent
    pub fn receipt_from_blob(content: &str) -> Result<ReceiptContent, Error> {
        serde_json::from_str(content)
            .map_err(|e| Error::Validation(format!("invalid receipt content: {}", e)))
    }

    /// 从 blob content 反序列化 AuthorizationContent
    pub fn authorization_from_blob(content: &str) -> Result<AuthorizationContent, Error> {
        serde_json::from_str(content)
            .map_err(|e| Error::Validation(format!("invalid authorization content: {}", e)))
    }

    // ─── IDN-ATT: binding_context_digest ───

    /// 计算 IDN-ATT binding_context_digest
    ///
    /// 按固定顺序序列化三组属性，计算 SHA-256：
    /// 1. 主体状态属性：从 cert_labels 提取 x-cert-* 相关字段
    /// 2. 环境属性：从 cert_labels 提取 x-see-* 相关字段
    /// 3. 实例状态属性：从 instance_state_attributes
    pub fn compute_binding_context_digest(
        cert_labels: &HashMap<String, String>,
        instance_state: &serde_json::Value,
    ) -> String {
        // 按固定顺序收集属性
        let mut binding_input = String::new();

        // 1. 主体状态属性（按 key 字母序）
        let subject_keys = [
            LABEL_CERT_AGENT,
            LABEL_CERT_LEVEL,
            LABEL_CERT_PARENT,
            LABEL_CERT_ZONES,
            LABEL_CERT_STATUS,
        ];
        for key in &subject_keys {
            if let Some(val) = cert_labels.get(*key) {
                binding_input.push_str(&format!("{}={}\n", key, val));
            }
        }

        // 2. 环境属性（按 key 字母序）
        let env_keys = [
            LABEL_SEE_ATTESTATION,
            LABEL_CERT_HOST_IDENTITY,
            LABEL_SEE_ENV_ID,
            LABEL_SEE_LEVEL,
            LABEL_SEE_PLATFORM_STATE,
        ];
        for key in &env_keys {
            if let Some(val) = cert_labels.get(*key) {
                binding_input.push_str(&format!("{}={}\n", key, val));
            }
        }

        // 3. 实例状态属性
        if !instance_state.is_null() {
            let sorted = serde_json::to_string(instance_state).unwrap_or_default();
            binding_input.push_str(&sorted);
        }

        let digest = Sha256::digest(binding_input.as_bytes());
        format!("sha256:{}", hex::encode(digest))
    }

    /// 计算 handshake_transcript_digest
    ///
    /// hash(init_blob || accept_blob)
    pub fn compute_handshake_digest(init_content: &str, accept_content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(init_content.as_bytes());
        hasher.update(accept_content.as_bytes());
        let digest = hasher.finalize();
        format!("sha256:{}", hex::encode(digest))
    }
}

/// ASL 合规上下文
///
/// 初始版本为无状态 struct，后续可扩展 ASL 版本号、外部端点配置、信任锚材料等。
/// pipeline 模块通过 `&self.asl` 访问适配和校验能力。
pub struct AslContext {
    pub adapter: AslAdapter,
}

impl Default for AslContext {
    fn default() -> Self {
        Self {
            adapter: AslAdapter,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_intent() -> IntentContent {
        IntentContent {
            intent_id: "int-001".into(),
            intent_owner: "agent-alice".into(),
            intent_creator: "agent-alice".into(),
            task_id: None,
            intent_goal: "deploy".into(),
            intent_constraints: serde_json::json!({"budget": 100}),
            intent_preferences: None,
            origin_input_digest: None,
            origin_input_excerpt: None,
            version: "1.0".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            expires_at: "2026-12-31T23:59:59Z".into(),
        }
    }

    #[test]
    fn intent_labels() {
        let labels = AslAdapter::intent_to_labels(&make_intent());
        assert_eq!(labels.get("type").unwrap(), "intent");
        assert_eq!(labels.get(LABEL_INTENT_ID).unwrap(), "int-001");
        assert_eq!(labels.get(LABEL_INTENT_OWNER).unwrap(), "agent-alice");
        assert_eq!(labels.get(LABEL_INTENT_STATUS).unwrap(), "active");
    }

    #[test]
    fn sub_intent_labels() {
        let sub = SubIntentContent {
            sub_intent_id: "sub-001".into(),
            parent_intent_digest: "sha256:parent".into(),
            deriver_id: "agent-alice".into(),
            subject: "deploy".into(),
            derivation_depth: 1,
            derivation_basis: None,
            intent_goal: "deploy db".into(),
            intent_constraints: serde_json::json!({"budget": 50}),
            created_at: "2026-01-01T00:00:00Z".into(),
            expires_at: "2026-06-01T00:00:00Z".into(),
        };

        let labels = AslAdapter::sub_intent_to_labels(&sub);
        assert_eq!(labels.get("type").unwrap(), "sub-intent");
        assert_eq!(labels.get(LABEL_PARENT_INTENT).unwrap(), "sha256:parent");
        assert_eq!(labels.get(LABEL_DERIVATION_DEPTH).unwrap(), "1");
    }

    #[test]
    fn receipt_labels_all_statuses() {
        let make_receipt = |status: ReceiptStatus| ReceiptContent {
            receipt_id: "rct-001".into(),
            executor_id: "agent-bob".into(),
            task_id: "task-001".into(),
            action_type: "execute".into(),
            intent_digest: "sha256:intent".into(),
            authorization_digest: "sha256:authz".into(),
            execution_params_digest: None,
            result_status: status,
            execution_result: None,
            rejection_reason: None,
            started_at: "2026-01-01T00:00:00Z".into(),
            finished_at: "2026-01-01T00:01:00Z".into(),
            downstream_receipt_digests: None,
        };

        let cases = [
            (ReceiptStatus::Succeeded, "SUCCEEDED"),
            (ReceiptStatus::Failed, "FAILED"),
            (ReceiptStatus::Partial, "PARTIAL"),
            (ReceiptStatus::Rejected, "REJECTED"),
            (ReceiptStatus::Cancelled, "CANCELLED"),
            (ReceiptStatus::Expired, "EXPIRED"),
        ];
        for (status, expected) in &cases {
            let labels = AslAdapter::receipt_to_labels(&make_receipt(status.clone()));
            assert_eq!(labels.get(LABEL_RECEIPT_STATUS).unwrap(), *expected);
        }
    }

    #[test]
    fn authz_labels_with_parent() {
        let authz = AuthorizationContent {
            authorization_id: "authz-001".into(),
            issuer: "root".into(),
            subject: "agent-alice".into(),
            grant_type: "execute".into(),
            constraints: AuthzConstraints {
                target_scope: None, amount_scope: None, time_scope: None,
                method_scope: None, environment_scope: None, behavior_scope: None,
                cumulative_limit: None,
            },
            delegatable: true,
            delegation_depth_remaining: Some(2),
            delegation_mode: Some(DelegationMode::Bounded),
            source_intent_digest: "sha256:intent".into(),
            parent_authz_digest: Some("sha256:parent".into()),
            root_authorizer: "root".into(),
            aud: None,
            nbf: "2026-01-01T00:00:00Z".into(),
            exp: "2026-12-31T23:59:59Z".into(),
            iat: "2026-01-01T00:00:00Z".into(),
            jti: "jti-001".into(),
            version: "1.0".into(),
        };

        let labels = AslAdapter::authorization_to_labels(&authz);
        assert_eq!(labels.get(LABEL_PARENT_AUTHZ).unwrap(), "sha256:parent");
        assert_eq!(labels.get(LABEL_AUTHZ_STATUS).unwrap(), "valid");
    }

    #[test]
    fn authz_labels_without_parent() {
        let authz = AuthorizationContent {
            authorization_id: "authz-002".into(),
            issuer: "root".into(),
            subject: "agent-alice".into(),
            grant_type: "execute".into(),
            constraints: AuthzConstraints {
                target_scope: None, amount_scope: None, time_scope: None,
                method_scope: None, environment_scope: None, behavior_scope: None,
                cumulative_limit: None,
            },
            delegatable: false,
            delegation_depth_remaining: None,
            delegation_mode: None,
            source_intent_digest: "sha256:intent".into(),
            parent_authz_digest: None,
            root_authorizer: "root".into(),
            aud: None,
            nbf: "2026-01-01T00:00:00Z".into(),
            exp: "2026-12-31T23:59:59Z".into(),
            iat: "2026-01-01T00:00:00Z".into(),
            jti: "jti-002".into(),
            version: "1.0".into(),
        };

        let labels = AslAdapter::authorization_to_labels(&authz);
        assert!(!labels.contains_key(LABEL_PARENT_AUTHZ));
    }

    #[test]
    fn from_blob_invalid_json() {
        assert!(AslAdapter::intent_from_blob("not json").is_err());
        assert!(AslAdapter::sub_intent_from_blob("{").is_err());
        assert!(AslAdapter::receipt_from_blob("").is_err());
        assert!(AslAdapter::authorization_from_blob("null").is_err());
    }

    #[test]
    fn from_blob_roundtrip() {
        let intent = make_intent();
        let json = serde_json::to_string(&intent).unwrap();
        let parsed = AslAdapter::intent_from_blob(&json).unwrap();
        assert_eq!(parsed.intent_id, "int-001");
        assert_eq!(parsed.intent_goal, "deploy");
    }

    #[test]
    fn binding_context_digest_deterministic() {
        let mut cert_labels = HashMap::new();
        cert_labels.insert(LABEL_CERT_AGENT.to_string(), "agent-001".into());
        cert_labels.insert(LABEL_CERT_LEVEL.to_string(), "2".into());
        cert_labels.insert(LABEL_CERT_ZONES.to_string(), "A,B".into());
        cert_labels.insert(LABEL_CERT_STATUS.to_string(), "active".into());
        let instance = serde_json::json!({"instance_id": "inst-001"});

        let d1 = AslAdapter::compute_binding_context_digest(&cert_labels, &instance);
        let d2 = AslAdapter::compute_binding_context_digest(&cert_labels, &instance);
        assert_eq!(d1, d2);
        assert!(d1.starts_with("sha256:"));
    }

    #[test]
    fn binding_context_digest_differs_for_different_input() {
        let mut labels1 = HashMap::new();
        labels1.insert(LABEL_CERT_AGENT.to_string(), "agent-001".into());

        let mut labels2 = HashMap::new();
        labels2.insert(LABEL_CERT_AGENT.to_string(), "agent-002".into());

        let d1 = AslAdapter::compute_binding_context_digest(&labels1, &serde_json::Value::Null);
        let d2 = AslAdapter::compute_binding_context_digest(&labels2, &serde_json::Value::Null);
        assert_ne!(d1, d2);
    }

    #[test]
    fn binding_context_digest_empty_labels() {
        let empty = HashMap::new();
        let d = AslAdapter::compute_binding_context_digest(&empty, &serde_json::Value::Null);
        assert!(d.starts_with("sha256:"));
    }

    #[test]
    fn handshake_digest_deterministic() {
        let d1 = AslAdapter::compute_handshake_digest("init-data", "accept-data");
        let d2 = AslAdapter::compute_handshake_digest("init-data", "accept-data");
        assert_eq!(d1, d2);
        assert!(d1.starts_with("sha256:"));
    }

    #[test]
    fn handshake_digest_differs_for_different_input() {
        let d1 = AslAdapter::compute_handshake_digest("init-a", "accept-a");
        let d2 = AslAdapter::compute_handshake_digest("init-b", "accept-b");
        assert_ne!(d1, d2);
    }
}
