//! ASL 载荷结构定义（V1_DEV §3.1）
//!
//! blob content 直接存储 ASL JSON。所有 `_digest` 后缀字段名统一。

use serde::{Deserialize, Serialize};

// ─── 通用意图 (INT-GIR) ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentContent {
    pub intent_id: String,
    pub intent_owner: String,
    pub intent_creator: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    pub intent_goal: String,
    pub intent_constraints: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub intent_preferences: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin_input_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin_input_excerpt: Option<String>,
    pub version: String,
    pub created_at: String,
    pub expires_at: String,
}

// ─── 子意图 (INT-DER) ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubIntentContent {
    pub sub_intent_id: String,
    pub parent_intent_digest: String,
    pub deriver_id: String,
    pub subject: String,
    pub derivation_depth: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derivation_basis: Option<String>,
    pub intent_goal: String,
    pub intent_constraints: serde_json::Value,
    pub created_at: String,
    pub expires_at: String,
}

// ─── 执行回执 (INT-RCT) ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptContent {
    pub receipt_id: String,
    pub executor_id: String,
    pub task_id: String,
    pub action_type: String,
    pub intent_digest: String,
    pub authorization_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_params_digest: Option<String>,
    pub result_status: ReceiptStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_result: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejection_reason: Option<String>,
    pub started_at: String,
    pub finished_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub downstream_receipt_digests: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReceiptStatus {
    Succeeded,
    Failed,
    Partial,
    Rejected,
    Cancelled,
    Expired,
}

// ─── 授权载荷 (AZN-APR) ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationContent {
    pub authorization_id: String,
    pub issuer: String,
    pub subject: String,
    pub grant_type: String,
    pub constraints: AuthzConstraints,
    pub delegatable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation_depth_remaining: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation_mode: Option<DelegationMode>,
    pub source_intent_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_authz_digest: Option<String>,
    pub root_authorizer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<Vec<String>>,
    pub nbf: String,
    pub exp: String,
    pub iat: String,
    pub jti: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthzConstraints {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_scope: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount_scope: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_scope: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method_scope: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment_scope: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub behavior_scope: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cumulative_limit: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DelegationMode {
    Specified,
    Bounded,
}

// ─── 运行态证明 (IDN-ATH) ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeProofContent {
    pub proof_id: String,
    pub credential_digest: String,
    pub instance_state_attributes: serde_json::Value,
    pub binding_context_digest: String,
    pub proof_anchor_mode: ProofAnchorMode,
    pub issued_at: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProofAnchorMode {
    CredentialAnchored,
    EnvironmentAnchored,
}

// ─── 会话载荷 (LNK) ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInitContent {
    pub ephemeral_pub: String,
    pub cipher_suites: Vec<String>,
    pub credential_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionAcceptContent {
    pub ephemeral_pub: String,
    pub selected_cipher_suite: String,
    pub credential_digest: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intent_roundtrip() {
        let intent = IntentContent {
            intent_id: "int-001".into(),
            intent_owner: "agent-alice".into(),
            intent_creator: "agent-alice".into(),
            task_id: None,
            intent_goal: "deploy service".into(),
            intent_constraints: serde_json::json!({"budget": 100}),
            intent_preferences: None,
            origin_input_digest: None,
            origin_input_excerpt: None,
            version: "1.0".into(),
            created_at: "2026-01-01T00:00:00Z".into(),
            expires_at: "2026-12-31T23:59:59Z".into(),
        };

        let json = serde_json::to_string(&intent).unwrap();
        let parsed: IntentContent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.intent_id, "int-001");
        assert_eq!(parsed.intent_constraints["budget"], 100);
    }

    #[test]
    fn authorization_roundtrip() {
        let authz = AuthorizationContent {
            authorization_id: "authz-001".into(),
            issuer: "root".into(),
            subject: "agent-alice".into(),
            grant_type: "execute".into(),
            constraints: AuthzConstraints {
                target_scope: Some(serde_json::json!(["zone-A"])),
                amount_scope: None,
                time_scope: None,
                method_scope: None,
                environment_scope: None,
                behavior_scope: None,
                cumulative_limit: None,
            },
            delegatable: true,
            delegation_depth_remaining: Some(3),
            delegation_mode: Some(DelegationMode::Bounded),
            source_intent_digest: "sha256:abc".into(),
            parent_authz_digest: None,
            root_authorizer: "root".into(),
            aud: None,
            nbf: "2026-01-01T00:00:00Z".into(),
            exp: "2026-12-31T23:59:59Z".into(),
            iat: "2026-01-01T00:00:00Z".into(),
            jti: "jti-001".into(),
            version: "1.0".into(),
        };

        let json = serde_json::to_string(&authz).unwrap();
        let parsed: AuthorizationContent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.authorization_id, "authz-001");
        assert!(parsed.delegatable);
        assert_eq!(parsed.delegation_mode, Some(DelegationMode::Bounded));
    }

    #[test]
    fn receipt_status_serialization() {
        let statuses = vec![
            ReceiptStatus::Succeeded,
            ReceiptStatus::Failed,
            ReceiptStatus::Partial,
            ReceiptStatus::Rejected,
            ReceiptStatus::Cancelled,
            ReceiptStatus::Expired,
        ];
        for status in &statuses {
            let json = serde_json::to_string(status).unwrap();
            let parsed: ReceiptStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(format!("{:?}", status), format!("{:?}", parsed));
        }
    }

    #[test]
    fn runtime_proof_roundtrip() {
        let proof = RuntimeProofContent {
            proof_id: "proof-001".into(),
            credential_digest: "sha256:cert".into(),
            instance_state_attributes: serde_json::json!({
                "instance_id": "inst-001",
                "instance_status": "running"
            }),
            binding_context_digest: "sha256:binding".into(),
            proof_anchor_mode: ProofAnchorMode::CredentialAnchored,
            issued_at: "2026-01-01T00:00:00Z".into(),
            expires_at: "2026-01-01T00:05:00Z".into(),
        };

        let json = serde_json::to_string(&proof).unwrap();
        let parsed: RuntimeProofContent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.proof_id, "proof-001");
        assert_eq!(parsed.proof_anchor_mode, ProofAnchorMode::CredentialAnchored);
    }

    #[test]
    fn session_init_roundtrip() {
        let init = SessionInitContent {
            ephemeral_pub: "pubkey123".into(),
            cipher_suites: vec!["AES-256-GCM".into()],
            credential_digest: "sha256:cert".into(),
        };

        let json = serde_json::to_string(&init).unwrap();
        let parsed: SessionInitContent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.ephemeral_pub, "pubkey123");
        assert_eq!(parsed.cipher_suites.len(), 1);
    }

    #[test]
    fn session_accept_roundtrip() {
        let accept = SessionAcceptContent {
            ephemeral_pub: "pubkey456".into(),
            selected_cipher_suite: "AES-256-GCM".into(),
            credential_digest: "sha256:cert".into(),
        };

        let json = serde_json::to_string(&accept).unwrap();
        let parsed: SessionAcceptContent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.selected_cipher_suite, "AES-256-GCM");
    }
}
