//! Label 常量集中管理（v0 + v1 + audit）
//!
//! 所有 blob label key 统一定义在此模块，避免散落在各处硬编码。

// ─── INF: 安全执行环境 ───

pub const LABEL_SEE_LEVEL: &str = "x-see-level";
pub const LABEL_SEE_ENV_ID: &str = "x-see-environment-id";
pub const LABEL_SEE_PLATFORM_STATE: &str = "x-see-platform-state";
pub const LABEL_SEE_ATTESTATION: &str = "x-see-attestation-support";

// ─── INF-KMS: 密钥管理 ───

pub const LABEL_KEY_PURPOSE: &str = "x-key-purpose";
pub const LABEL_KEY_OWNER: &str = "x-key-owner";
pub const LABEL_KEY_SEE_LEVEL: &str = "x-key-see-level";
pub const LABEL_KEY_NONEXPORTABLE: &str = "x-key-nonexportable";
pub const LABEL_KEY_ALGORITHM: &str = "x-key-algorithm";
pub const LABEL_KEY_REVOKED: &str = "x-key-revoked";

// ─── IDN: 身份属性（IDN-ATT 三组属性映射） ───

/// 主体状态属性 (subject_state_attributes)
pub const LABEL_CERT_AGENT: &str = "x-cert-agent";
pub const LABEL_CERT_LEVEL: &str = "x-cert-level";
pub const LABEL_CERT_PARENT: &str = "x-cert-parent";
pub const LABEL_CERT_ZONES: &str = "x-cert-zones";
pub const LABEL_CERT_STATUS: &str = "x-cert-status";

/// 环境属性 (environment_attributes)
/// x-see-level, x-see-environment-id, x-see-platform-state, x-see-attestation-support
/// 已在 INF labels 中定义
pub const LABEL_CERT_HOST_IDENTITY: &str = "x-cert-host-identity";

/// 实例状态属性 (instance_state_attributes)
/// 由 runtime-proof blob 的 content.instance_state_attributes 承载

/// 凭证状态标志（持久化用，与 IDN-LCM 对应）
pub const LABEL_CERT_SUSPENDED: &str = "x-cert-suspended";
pub const LABEL_CERT_REVOKED: &str = "x-cert-revoked";
pub const LABEL_CERT_EXPIRED: &str = "x-cert-expired";

/// 绑定上下文摘要
pub const LABEL_BINDING_CONTEXT_DIGEST: &str = "x-binding-context-digest";

// ─── INT: 意图 labels ───

pub const LABEL_INTENT_ID: &str = "x-intent-id";
pub const LABEL_INTENT_OWNER: &str = "x-intent-owner";
pub const LABEL_INTENT_STATUS: &str = "x-intent-status";
pub const LABEL_INTENT_EXPIRES: &str = "x-intent-expires";
pub const LABEL_PARENT_INTENT: &str = "x-parent-intent";
pub const LABEL_DERIVATION_DEPTH: &str = "x-derivation-depth";

// ─── AZN: 授权 labels ───

pub const LABEL_AUTHZ_ID: &str = "x-authz-id";
pub const LABEL_AUTHZ_ISSUER: &str = "x-authz-issuer";
pub const LABEL_AUTHZ_SUBJECT: &str = "x-authz-subject";
pub const LABEL_AUTHZ_STATUS: &str = "x-authz-status";
pub const LABEL_SOURCE_INTENT: &str = "x-source-intent";
pub const LABEL_PARENT_AUTHZ: &str = "x-parent-authz";

// ─── Receipt: 回执 labels ───

pub const LABEL_RECEIPT_ID: &str = "x-receipt-id";
pub const LABEL_RECEIPT_EXECUTOR: &str = "x-receipt-executor";
pub const LABEL_RECEIPT_STATUS: &str = "x-receipt-status";
pub const LABEL_RECEIPT_INTENT: &str = "x-receipt-intent";
pub const LABEL_RECEIPT_AUTHZ: &str = "x-receipt-authz";

// ─── LNK: 会话 labels（协议 §8） ───

pub const LABEL_SESSION_ID: &str = "x-session-id";
pub const LABEL_SESSION_PEER_A: &str = "x-session-peer-a";
pub const LABEL_SESSION_PEER_B: &str = "x-session-peer-b";
pub const LABEL_SESSION_STATUS: &str = "x-session-status";
pub const LABEL_SESSION_CLOSED_AT: &str = "x-session-closed-at";
pub const LABEL_SESSION_CLOSE_REASON: &str = "x-session-close-reason";
pub const LABEL_SESSION_FINAL_HASH: &str = "x-session-final-hash";
pub const LABEL_MESSAGE_ID: &str = "x-message-id";
pub const LABEL_MESSAGE_SEQ: &str = "x-message-seq";

// ─── IDN-ATH: 运行态证明 labels ───

pub const LABEL_PROOF_AGENT: &str = "x-proof-agent";
pub const LABEL_PROOF_CREDENTIAL: &str = "x-proof-credential";

// ─── Audit chain labels ───

pub const LABEL_AUDIT_PREV: &str = "x-audit-prev";
pub const LABEL_AUDIT_CHAIN_INDEX: &str = "x-audit-chain-index";

// ─── INF-KMS 密钥用途 ───

/// INF-KMS 密钥用途常量
pub const KEY_PURPOSES: &[&str] = &["IDN_SIGN", "INT_SIGN", "AZN_SIGN", "RCT_SIGN", "SESSION"];

// ─── Blob type 常量 ───

pub const BLOB_TYPE_INTENT: &str = "intent";
pub const BLOB_TYPE_SUB_INTENT: &str = "sub-intent";
pub const BLOB_TYPE_RECEIPT: &str = "receipt";
pub const BLOB_TYPE_AUTHORIZATION: &str = "authorization";
pub const BLOB_TYPE_SESSION_INIT: &str = "session-init";
pub const BLOB_TYPE_SESSION_ACCEPT: &str = "session-accept";
pub const BLOB_TYPE_AGENT_CERT: &str = "agent-cert";
pub const BLOB_TYPE_AGENT_KEY: &str = "agent-key";
pub const BLOB_TYPE_ROOT_CA: &str = "root-ca";
pub const BLOB_TYPE_AUDIT: &str = "audit";

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_LABELS: &[&str] = &[
        LABEL_SEE_LEVEL, LABEL_SEE_ENV_ID, LABEL_SEE_PLATFORM_STATE, LABEL_SEE_ATTESTATION,
        LABEL_KEY_PURPOSE, LABEL_KEY_OWNER, LABEL_KEY_SEE_LEVEL, LABEL_KEY_NONEXPORTABLE,
        LABEL_KEY_ALGORITHM, LABEL_KEY_REVOKED, LABEL_CERT_AGENT, LABEL_CERT_LEVEL, LABEL_CERT_PARENT,
        LABEL_CERT_ZONES, LABEL_CERT_STATUS, LABEL_CERT_HOST_IDENTITY,
        LABEL_CERT_SUSPENDED, LABEL_CERT_REVOKED, LABEL_CERT_EXPIRED,
        LABEL_BINDING_CONTEXT_DIGEST, LABEL_INTENT_ID, LABEL_INTENT_OWNER,
        LABEL_INTENT_STATUS, LABEL_INTENT_EXPIRES, LABEL_PARENT_INTENT,
        LABEL_DERIVATION_DEPTH, LABEL_AUTHZ_ID, LABEL_AUTHZ_ISSUER, LABEL_AUTHZ_SUBJECT,
        LABEL_AUTHZ_STATUS, LABEL_SOURCE_INTENT, LABEL_PARENT_AUTHZ,
        LABEL_RECEIPT_ID, LABEL_RECEIPT_EXECUTOR, LABEL_RECEIPT_STATUS,
        LABEL_RECEIPT_INTENT, LABEL_RECEIPT_AUTHZ, LABEL_SESSION_ID,
        LABEL_SESSION_PEER_A, LABEL_SESSION_PEER_B, LABEL_SESSION_STATUS,
        LABEL_SESSION_CLOSED_AT, LABEL_SESSION_CLOSE_REASON, LABEL_SESSION_FINAL_HASH,
        LABEL_MESSAGE_ID, LABEL_MESSAGE_SEQ, LABEL_PROOF_AGENT, LABEL_PROOF_CREDENTIAL,
        LABEL_AUDIT_PREV, LABEL_AUDIT_CHAIN_INDEX,
    ];

    #[test]
    fn all_labels_are_prefixed() {
        for label in ALL_LABELS {
            assert!(
                label.starts_with("x-"),
                "label '{}' should start with 'x-'",
                label
            );
        }
    }

    #[test]
    fn no_duplicate_values() {
        for (i, a) in ALL_LABELS.iter().enumerate() {
            for (j, b) in ALL_LABELS.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "duplicate label value: '{}' at index {} and {}", a, i, j);
                }
            }
        }
    }
}
