//! 可插拔身份抽象 — 允许二次开发者集成 OAuth、SPIFFE 或自定义身份提供者
//!
//! V3 Phase 3：将 Baize 内部硬编码的证书身份系统替换为 trait-based 的 IdentityProvider。
//! 默认实现 CertIdentityProvider 包装现有 X.509 证书逻辑。

use std::collections::HashMap;

use crate::cert::{CertIdentity, CredentialStatus};
use crate::crypto::CryptoProvider;
use crate::error::Result;
use crate::storage::BlobStore;

// ─── 通用身份表示 ───

/// 通用 agent 身份 — 所有 IdentityProvider 实现都产生此结构
///
/// 包含管道层做授权决策、审计日志、凭证生命周期管理所需的全部字段。
/// `attributes` HashMap 留给 provider 填充特有属性（如 OAuth scopes、SPIFFE trust domain）。
#[derive(Debug, Clone)]
pub struct AgentIdentity {
    pub agent_id: String,
    pub parent_id: Option<String>,
    pub level: u8,
    pub zones: Vec<String>,
    pub status: CredentialStatus,
    /// Provider 特有属性（OAuth scopes、SPIFFE trust domain 等）
    pub attributes: HashMap<String, String>,
}

impl From<AgentIdentity> for CertIdentity {
    fn from(a: AgentIdentity) -> Self {
        CertIdentity {
            agent_id: a.agent_id,
            parent_id: a.parent_id,
            level: a.level,
            zones: a.zones,
            status: a.status,
        }
    }
}

// ─── IdentityProvider trait ───

/// 可插拔身份提供者 — 管理 agent 的注册、查询、状态和密钥
///
/// 默认 CertIdentityProvider 包装现有 X.509 证书系统。
/// 二次开发者实现此 trait 即可替换为 OAuth/SPIFFE/自定义方案。
///
/// 所有方法使用 &self（内部可变性模式，与 BlobStore 一致）。
pub trait IdentityProvider: Send + Sync {
    // 支持 downcast（用于 Baize 层访问 CertIdentityProvider 特有方法）
    fn as_any(&self) -> &dyn std::any::Any;
    // ─── Root CA 初始化 ───

    /// 初始化 root CA（首次启动时生成，已存在时跳过）
    fn init_root(
        &self,
        storage: &dyn BlobStore,
        crypto: &CryptoProvider,
    ) -> Result<()>;

    // ─── 生命周期 ───

    /// 注册新 agent（包含证书签发、存储、内存索引）
    fn register(
        &self,
        name: &str,
        level: u8,
        zones: &[&str],
        parent_id: Option<&str>,
        issuer_id: &str,
        storage: &dyn BlobStore,
        crypto: &CryptoProvider,
    ) -> Result<AgentIdentity>;

    /// 吊销 agent（不可逆）
    fn revoke(&self, agent_id: &str, storage: &dyn BlobStore) -> Result<()>;

    /// 从持久化存储恢复所有 agent 到内存
    fn restore(
        &self,
        storage: &dyn BlobStore,
        crypto: &CryptoProvider,
    ) -> Result<()>;

    // ─── 查询 ───

    /// 获取 agent 身份（不存在返回 None）
    fn get_identity(&self, agent_id: &str) -> Option<AgentIdentity>;

    /// 检查 agent 是否已注册
    fn contains(&self, agent_id: &str) -> bool;

    /// 沿 parent 链追溯到 root
    fn trace_identity(&self, agent_id: &str) -> Result<Vec<AgentIdentity>>;

    /// 列出所有已注册 agent
    fn list(&self) -> Vec<(String, AgentIdentity)>;

    // ─── 状态管理 ───

    /// 获取凭证状态
    fn credential_status(&self, agent_id: &str) -> Result<CredentialStatus>;

    /// 更新凭证状态（IDN-LCM 状态机）
    fn update_status(
        &self,
        agent_id: &str,
        new_status: CredentialStatus,
        reason: &str,
        storage: &dyn BlobStore,
    ) -> Result<()>;

    // ─── 密钥操作（KmsManager 需要）───

    /// 获取 agent 的 IDN_SIGN 用途活跃密钥 PEM
    fn get_signing_key(
        &self,
        agent_id: &str,
        storage: &dyn BlobStore,
        crypto: &CryptoProvider,
    ) -> Result<String>;

    /// 密钥轮换后更新 provider 内部的签名状态（如 IssuerCtx）
    fn update_signing_key(
        &self,
        agent_id: &str,
        new_key_pem: &str,
        storage: &dyn BlobStore,
    ) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_identity_has_all_fields() {
        let id = AgentIdentity {
            agent_id: "test".to_string(),
            parent_id: Some("root".to_string()),
            level: 3,
            zones: vec!["A".to_string(), "B".to_string()],
            status: CredentialStatus::Active,
            attributes: HashMap::new(),
        };
        assert_eq!(id.agent_id, "test");
        assert_eq!(id.parent_id, Some("root".to_string()));
        assert_eq!(id.level, 3);
        assert_eq!(id.zones, vec!["A", "B"]);
        assert_eq!(id.status, CredentialStatus::Active);
        assert!(id.attributes.is_empty());
    }

    #[test]
    fn agent_identity_with_custom_attributes() {
        let mut attrs = HashMap::new();
        attrs.insert("oauth_scope".to_string(), "read write".to_string());
        let id = AgentIdentity {
            agent_id: "oauth-agent".to_string(),
            parent_id: None,
            level: 2,
            zones: vec!["*".to_string()],
            status: CredentialStatus::Active,
            attributes: attrs,
        };
        assert_eq!(id.attributes.get("oauth_scope").unwrap(), "read write");
    }
}
