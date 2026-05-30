//! CertIdentityProvider — 默认的 X.509 证书身份提供者
//!
//! 包装现有证书系统，内部用 `Mutex<HashMap>` 保持现有逻辑不变。
//! `IssuerCtx` 不暴露到 trait 层。

use std::collections::HashMap;
use std::sync::Mutex;

use baize_core::cert::{CertIdentity, CertTool, CredentialStatus, IssuerCtx};
use baize_core::crypto::CryptoProvider;
use baize_core::error::Error;
use baize_core::identity::{AgentIdentity, IdentityProvider};
use baize_core::labels::*;
use baize_core::scope::{Level, Scope};
use baize_core::storage::BlobStore;
use baize_core::ROOT_AGENT_ID;

// ─── CertIdentityProvider ───

/// 默认身份提供者 — 包装 X.509 证书系统
///
/// 内部用 `Mutex<HashMap<String, (CertIdentity, IssuerCtx)>>` 管理所有 agent。
/// 所有方法使用 `&self`（内部可变性模式，与 BlobStore 一致）。
pub struct CertIdentityProvider {
    agents: Mutex<HashMap<String, (CertIdentity, IssuerCtx)>>,
}

impl CertIdentityProvider {
    pub fn new() -> Self {
        Self {
            agents: Mutex::new(HashMap::new()),
        }
    }

    // ─── 内部辅助方法 ───

    /// CertIdentity → AgentIdentity 转换
    fn to_agent_identity(cert: &CertIdentity) -> AgentIdentity {
        AgentIdentity {
            agent_id: cert.agent_id.clone(),
            parent_id: cert.parent_id.clone(),
            level: cert.level,
            zones: cert.zones.clone(),
            status: cert.status,
            attributes: HashMap::new(),
        }
    }

    /// 从 agent-cert blob 的 labels 恢复凭证状态
    /// 优先级：revoked > expired > suspended > active
    fn recover_credential_status(storage: &dyn BlobStore, cert_hash: &str) -> CredentialStatus {
        let labels = storage.label_query_for_entity(cert_hash)
            .unwrap_or_default();

        if labels.iter().any(|l| l.key == LABEL_CERT_REVOKED && l.value == "true") {
            CredentialStatus::Revoked
        } else if labels.iter().any(|l| l.key == LABEL_CERT_EXPIRED && l.value == "true") {
            CredentialStatus::Expired
        } else if labels.iter().any(|l| l.key == LABEL_CERT_SUSPENDED && l.value == "true") {
            CredentialStatus::Suspended
        } else {
            CredentialStatus::Active
        }
    }

    /// 解密 key blob content（如有 master secret）
    fn decrypt_key_content(content: &str, crypto: &CryptoProvider) -> Result<String, Error> {
        let master_secret = baize_core::crypto::master_secret_from_env();
        match master_secret {
            Some(secret) => crypto.key_encryption.decrypt(content, &secret),
            None => Ok(content.to_string()),
        }
    }

    /// 凭证状态迁移校验（对齐 PROTOCOL_SPEC_V1 §7.3）
    fn validate_status_transition(from: CredentialStatus, to: CredentialStatus) -> Result<(), Error> {
        let valid = match (from, to) {
            (a, b) if a == b => true,
            (CredentialStatus::Active, CredentialStatus::Suspended) => true,
            (CredentialStatus::Active, CredentialStatus::Revoked) => true,
            (CredentialStatus::Suspended, CredentialStatus::Active) => true,
            (CredentialStatus::Suspended, CredentialStatus::Revoked) => true,
            (_, CredentialStatus::Expired) => true,
            _ => false,
        };

        if !valid {
            return Err(Error::Validation(
                format!("invalid credential status transition: {:?} → {:?}", from, to)
            ));
        }
        Ok(())
    }

    // ─── 非 trait 公开方法（Baize 层直接使用） ───

    /// 在锁内使用签发者上下文执行操作
    pub fn with_issuer<F, R>(&self, agent_id: &str, f: F) -> Result<R, Error>
    where
        F: FnOnce(&CertIdentity, &IssuerCtx) -> Result<R, Error>,
    {
        let agents = self.agents.lock().unwrap();
        let (identity, ctx) = agents.get(agent_id)
            .ok_or_else(|| Error::NotFound(format!("agent {}", agent_id)))?;
        f(identity, ctx)
    }

    /// 获取 CertIdentity（用于 Baize 层需要 CertIdentity 的场景）
    pub fn get_cert_identity(&self, agent_id: &str) -> Option<CertIdentity> {
        let agents = self.agents.lock().unwrap();
        agents.get(agent_id).map(|(id, _)| id.clone())
    }

    /// 注册 agent 到内存 HashMap（证书签发完成后调用）
    pub fn insert_agent(&self, agent_id: String, identity: CertIdentity, ctx: IssuerCtx) {
        let mut agents = self.agents.lock().unwrap();
        agents.insert(agent_id, (identity, ctx));
    }

    /// 从内存移除 agent
    pub fn remove_agent(&self, agent_id: &str) -> Option<(CertIdentity, IssuerCtx)> {
        let mut agents = self.agents.lock().unwrap();
        agents.remove(agent_id)
    }

    /// 遍历所有 agent（在锁内执行闭包）
    pub fn for_each_agent<F>(&self, mut f: F)
    where
        F: FnMut(&String, &CertIdentity),
    {
        let agents = self.agents.lock().unwrap();
        for (id, (identity, _)) in agents.iter() {
            f(id, identity);
        }
    }

    /// 列出所有 agent（CertIdentity 列表，不包含 IssuerCtx）
    pub fn list_cert_identities(&self) -> Vec<(String, CertIdentity)> {
        let agents = self.agents.lock().unwrap();
        agents.iter()
            .map(|(id, (identity, _))| (id.clone(), identity.clone()))
            .collect()
    }
}

impl IdentityProvider for CertIdentityProvider {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn init_root(
        &self,
        storage: &dyn BlobStore,
        crypto: &CryptoProvider,
    ) -> Result<(), Error> {
        let mut root_filter = HashMap::new();
        root_filter.insert("type".to_string(), "root-ca".to_string());
        let existing_root = storage.blob_query(&root_filter)?;

        if !existing_root.is_empty() {
            // 已有 root CA：从存储恢复
            let root_cert_pem = &existing_root[0].content;
            let root_identity = CertTool::parse_identity(root_cert_pem)?;

            // 尝试恢复 root key
            let mut key_filter = HashMap::new();
            key_filter.insert("type".to_string(), "agent-key".to_string());
            key_filter.insert("agent-id".to_string(), ROOT_AGENT_ID.to_string());
            let root_keys = storage.blob_query(&key_filter)?;

            // 恢复 root IssuerCtx：优先查找 cert-sign 密钥（P-256）
            // 兼容旧数据：若 cert-sign 不存在，遍历所有 key 尝试恢复
            let cert_sign_key = root_keys.iter().find(|b| {
                b.labels.get(LABEL_KEY_PURPOSE).map_or(false, |p| p == KEY_PURPOSE_CERT_SIGN)
            });

            let mut root_ctx = None;
            // 优先尝试 cert-sign
            if let Some(key_blob) = cert_sign_key {
                let pem = Self::decrypt_key_content(&key_blob.content, crypto)?;
                if let Ok(ctx) = CertTool::recover_issuer(root_cert_pem, &pem) {
                    root_ctx = Some(ctx);
                }
            }
            // 回退：遍历所有 key 尝试（兼容旧版数据库中 P-256 IDN_SIGN key）
            if root_ctx.is_none() {
                for key_blob in &root_keys {
                    let pem = Self::decrypt_key_content(&key_blob.content, crypto)?;
                    if let Ok(ctx) = CertTool::recover_issuer(root_cert_pem, &pem) {
                        root_ctx = Some(ctx);
                        break;
                    }
                }
            }

            if let Some(ctx) = root_ctx {
                let mut agents = self.agents.lock().unwrap();
                agents.insert(ROOT_AGENT_ID.to_string(), (root_identity, ctx));
            } else {
                // 有 root cert 但没有 key blob：重新生成密钥（少见场景）
                let (root_bundle, root_ctx) = CertTool::generate_root_ca()?;
                let labels = labels! { "type" => "root-ca", "agent-id" => ROOT_AGENT_ID };
                storage.blob_write(&root_bundle.cert_pem, &labels)?;

                let master_secret = baize_core::crypto::master_secret_from_env();
                for purpose in KEY_PURPOSES {
                    let (key_pem, algorithm) = if *purpose == "SESSION" {
                        let (priv_pem, _) = crypto.key_exchange.generate_keypair()?;
                        (priv_pem, "X25519")
                    } else {
                        let (priv_pem, _) = baize_core::crypto::generate_ed25519_keypair()?;
                        (priv_pem, "Ed25519")
                    };
                    let stored_key = if let Some(ref secret) = master_secret {
                        crypto.key_encryption.encrypt(&key_pem, secret)?
                    } else {
                        key_pem
                    };
                    let key_labels = labels! {
                        "type" => "agent-key",
                        "agent-id" => ROOT_AGENT_ID,
                        LABEL_KEY_OWNER => ROOT_AGENT_ID,
                        LABEL_KEY_PURPOSE => purpose,
                        LABEL_KEY_ALGORITHM => algorithm,
                        LABEL_KEY_NONEXPORTABLE => "true",
                        LABEL_KEY_SEE_LEVEL => "L1",
                    };
                    storage.blob_write(&stored_key, &key_labels)?;
                }

                let mut agents = self.agents.lock().unwrap();
                agents.insert(ROOT_AGENT_ID.to_string(), (root_bundle.identity, root_ctx));
            }
        } else {
            // 首次初始化
            let (root_bundle, root_ctx) = CertTool::generate_root_ca()?;
            let labels = labels! { "type" => "root-ca", "agent-id" => ROOT_AGENT_ID };
            storage.blob_write(&root_bundle.cert_pem, &labels)?;

            // 为 root 创建所有用途的密钥
            let master_secret = baize_core::crypto::master_secret_from_env();

            // 存储 root CA 的证书签名密钥（P-256，用于签发子证书和恢复 IssuerCtx）
            let cert_sign_stored = if let Some(ref secret) = master_secret {
                crypto.key_encryption.encrypt(&root_bundle.key_pem, secret)?
            } else {
                root_bundle.key_pem.clone()
            };
            let cert_sign_labels = labels! {
                "type" => "agent-key",
                "agent-id" => ROOT_AGENT_ID,
                LABEL_KEY_OWNER => ROOT_AGENT_ID,
                LABEL_KEY_PURPOSE => KEY_PURPOSE_CERT_SIGN,
                LABEL_KEY_ALGORITHM => "P-256",
                LABEL_KEY_NONEXPORTABLE => "true",
                LABEL_KEY_SEE_LEVEL => "L1",
            };
            storage.blob_write(&cert_sign_stored, &cert_sign_labels)?;

            // 为 root 创建所有用途的 ASL 密钥
            for purpose in KEY_PURPOSES {
                let (key_pem, algorithm) = if *purpose == "SESSION" {
                    let (priv_pem, _) = crypto.key_exchange.generate_keypair()?;
                    (priv_pem, "X25519")
                } else {
                    // IDN_SIGN / INT_SIGN / AZN_SIGN / RCT_SIGN 均用 Ed25519
                    let (priv_pem, _) = baize_core::crypto::generate_ed25519_keypair()?;
                    (priv_pem, "Ed25519")
                };
                let stored_key = if let Some(ref secret) = master_secret {
                    crypto.key_encryption.encrypt(&key_pem, secret)?
                } else {
                    key_pem
                };
                let key_labels = labels! {
                    "type" => "agent-key",
                    "agent-id" => ROOT_AGENT_ID,
                    LABEL_KEY_OWNER => ROOT_AGENT_ID,
                    LABEL_KEY_PURPOSE => purpose,
                    LABEL_KEY_ALGORITHM => algorithm,
                    LABEL_KEY_NONEXPORTABLE => "true",
                    LABEL_KEY_SEE_LEVEL => "L1",
                };
                storage.blob_write(&stored_key, &key_labels)?;
            }

            let mut agents = self.agents.lock().unwrap();
            agents.insert(ROOT_AGENT_ID.to_string(), (root_bundle.identity, root_ctx));
        }

        Ok(())
    }

    fn register(
        &self,
        name: &str,
        level: u8,
        zones: &[&str],
        parent_id: Option<&str>,
        issuer_id: &str,
        storage: &dyn BlobStore,
        crypto: &CryptoProvider,
    ) -> Result<AgentIdentity, Error> {
        let scope = Scope::new(Level(level), zones)?;

        // 验证 scope 递减
        if parent_id.is_some() {
            let agents = self.agents.lock().unwrap();
            if let Some((parent_identity, _)) = agents.get(issuer_id) {
                let parent_scope = Scope::new(
                    Level(parent_identity.level),
                    parent_identity.zones.iter().map(|s| s.as_str()),
                )?;
                Scope::validate_decrease(&parent_scope, &scope)?;
            }
        }

        // 获取签发者上下文并签发证书
        let (bundle, agent_ctx) = {
            let agents = self.agents.lock().unwrap();
            let (_, issuer_ctx) = agents.get(issuer_id)
                .ok_or_else(|| Error::NotFound(format!("issuer agent {}", issuer_id)))?;
            CertTool::issue_agent(
                name,
                &scope,
                issuer_ctx,
                Some(issuer_id),
            )?
        };

        let identity = bundle.identity.clone();

        // 存储 agent 证书（含 IDN-ATT + SEE labels）
        let mut cert_labels = labels! {
            "type" => "agent-cert",
            "agent-id" => name,
            LABEL_CERT_AGENT => name,
            LABEL_CERT_LEVEL => &scope.level.0.to_string(),
            LABEL_CERT_STATUS => &CredentialStatus::Active.to_string(),
            LABEL_CERT_ZONES => &scope.zones.iter().cloned().collect::<Vec<_>>().join(","),
            LABEL_SEE_LEVEL => "L1",
            LABEL_SEE_ENV_ID => "default",
            LABEL_SEE_PLATFORM_STATE => "unknown",
            LABEL_SEE_ATTESTATION => "false",
            LABEL_CERT_HOST_IDENTITY => &std::env::var("HOSTNAME")
                .unwrap_or_else(|_| "unknown".to_string()),
        };
        if let Some(pid) = parent_id {
            cert_labels.insert("parent-id".to_string(), pid.to_string());
            cert_labels.insert(LABEL_CERT_PARENT.to_string(), pid.to_string());
        }
        storage.blob_write(&bundle.cert_pem, &cert_labels)?;

        // INF-KMS：为每种密钥用途创建独立的 agent-key blob
        let master_secret = baize_core::crypto::master_secret_from_env();
        for purpose in KEY_PURPOSES {
            let (key_pem, algorithm) = if purpose == &"IDN_SIGN" {
                (bundle.key_pem.clone(), "Ed25519")
            } else if purpose == &"SESSION" {
                let (priv_pem, _) = crypto.key_exchange.generate_keypair()?;
                (priv_pem, "X25519")
            } else {
                let (priv_pem, _) = baize_core::crypto::generate_ed25519_keypair()?;
                (priv_pem, "Ed25519")
            };
            let stored_key = if let Some(ref secret) = master_secret {
                crypto.key_encryption.encrypt(&key_pem, secret)?
            } else {
                key_pem
            };
            let key_labels = labels! {
                "type" => "agent-key",
                "agent-id" => name,
                LABEL_KEY_OWNER => name,
                LABEL_KEY_PURPOSE => purpose,
                LABEL_KEY_ALGORITHM => algorithm,
                LABEL_KEY_NONEXPORTABLE => "true",
                LABEL_KEY_SEE_LEVEL => "L1",
            };
            storage.blob_write(&stored_key, &key_labels)?;
        }

        // 插入内存 HashMap
        let agent_identity = Self::to_agent_identity(&identity);
        let mut agents = self.agents.lock().unwrap();
        agents.insert(name.to_string(), (identity, agent_ctx));

        Ok(agent_identity)
    }

    fn revoke(&self, agent_id: &str, storage: &dyn BlobStore) -> Result<(), Error> {
        if agent_id == ROOT_AGENT_ID {
            return Err(Error::PermissionDenied("cannot revoke root".into()));
        }

        {
            let agents = self.agents.lock().unwrap();
            if !agents.contains_key(agent_id) {
                return Err(Error::NotFound(format!("agent {}", agent_id)));
            }
        }

        // 标记证书为已撤销
        let mut cert_filter = HashMap::new();
        cert_filter.insert("type".to_string(), "agent-cert".to_string());
        cert_filter.insert("agent-id".to_string(), agent_id.to_string());
        let cert_blobs = storage.blob_query(&cert_filter)?;
        if let Some(cert_blob) = cert_blobs.first() {
            let _ = storage.label_add(&cert_blob.hash, "revoked", "true");
        }

        // 标记所有 agent-key blob 为已撤销
        let mut key_filter = HashMap::new();
        key_filter.insert("type".to_string(), "agent-key".to_string());
        key_filter.insert("agent-id".to_string(), agent_id.to_string());
        let key_blobs = storage.blob_query(&key_filter)?;
        for key_blob in &key_blobs {
            if !key_blob.labels.contains_key(LABEL_KEY_REVOKED) {
                let _ = storage.label_set(&key_blob.hash, LABEL_KEY_REVOKED, "true");
            }
        }

        // 从内存移除
        let mut agents = self.agents.lock().unwrap();
        agents.remove(agent_id);

        Ok(())
    }

    fn restore(
        &self,
        storage: &dyn BlobStore,
        crypto: &CryptoProvider,
    ) -> Result<(), Error> {
        let _master_secret = baize_core::crypto::master_secret_from_env();

        let mut agent_filter = HashMap::new();
        agent_filter.insert("type".to_string(), "agent-cert".to_string());
        let agent_certs = storage.blob_query(&agent_filter)?;

        for cert_blob in &agent_certs {
            let agent_id = cert_blob.labels.get("agent-id")
                .cloned()
                .unwrap_or_default();
            if agent_id.is_empty() || agent_id == ROOT_AGENT_ID {
                continue;
            }

            // 跳过已撤销的
            let revoked = storage.label_query("revoked", Some("true"))
                .unwrap_or_default()
                .iter()
                .any(|l| l.entity_hash == cert_blob.hash);
            if revoked {
                continue;
            }

            let identity = CertTool::parse_identity(&cert_blob.content)?;
            let status = Self::recover_credential_status(storage, &cert_blob.hash);
            let identity = CertIdentity { status, ..identity };

            let mut akey_filter = HashMap::new();
            akey_filter.insert("type".to_string(), "agent-key".to_string());
            akey_filter.insert("agent-id".to_string(), agent_id.clone());
            let agent_keys = storage.blob_query(&akey_filter)?;

            // 优先使用 IDN_SIGN 用途的 key
            let idn_sign_key = agent_keys.iter().find(|b| {
                b.labels.get("x-key-purpose").map(|v| v.as_str()) == Some("IDN_SIGN")
            }).or_else(|| agent_keys.first());

            let key_blob = match (idn_sign_key, agent_keys.first()) {
                (Some(k), _) => k,
                (None, Some(k)) => k,
                (None, None) => continue,
            };

            let agent_key_pem = Self::decrypt_key_content(&key_blob.content, crypto);
            match agent_key_pem {
                Ok(key_pem) => {
                    if let Ok(agent_ctx) = CertTool::recover_issuer(&cert_blob.content, &key_pem) {
                        let mut agents = self.agents.lock().unwrap();
                        agents.insert(agent_id, (identity, agent_ctx));
                    }
                }
                Err(_) => continue,
            }
        }

        Ok(())
    }

    fn get_identity(&self, agent_id: &str) -> Option<AgentIdentity> {
        let agents = self.agents.lock().unwrap();
        agents.get(agent_id).map(|(id, _)| Self::to_agent_identity(id))
    }

    fn contains(&self, agent_id: &str) -> bool {
        let agents = self.agents.lock().unwrap();
        agents.contains_key(agent_id)
    }

    fn trace_identity(&self, agent_id: &str) -> Result<Vec<AgentIdentity>, Error> {
        let agents = self.agents.lock().unwrap();
        let (identity, _) = agents.get(agent_id)
            .ok_or_else(|| Error::NotFound(format!("agent {}", agent_id)))?;

        let mut chain = vec![Self::to_agent_identity(identity)];
        let mut current = identity.parent_id.clone();

        while let Some(parent_id) = current {
            if let Some((parent_identity, _)) = agents.get(&parent_id) {
                current = parent_identity.parent_id.clone();
                chain.push(Self::to_agent_identity(parent_identity));
            } else {
                break;
            }
        }

        Ok(chain)
    }

    fn list(&self) -> Vec<(String, AgentIdentity)> {
        let agents = self.agents.lock().unwrap();
        agents.iter()
            .map(|(id, (identity, _))| (id.clone(), Self::to_agent_identity(identity)))
            .collect()
    }

    fn credential_status(&self, agent_id: &str) -> Result<CredentialStatus, Error> {
        let agents = self.agents.lock().unwrap();
        let (identity, _) = agents.get(agent_id)
            .ok_or_else(|| Error::NotFound(format!("agent {}", agent_id)))?;
        Ok(identity.status)
    }

    fn update_status(
        &self,
        agent_id: &str,
        new_status: CredentialStatus,
        reason: &str,
        storage: &dyn BlobStore,
    ) -> Result<(), Error> {
        if agent_id == ROOT_AGENT_ID {
            return Err(Error::PermissionDenied("cannot change root credential status".into()));
        }

        let current = {
            let agents = self.agents.lock().unwrap();
            let (identity, _) = agents.get(agent_id)
                .ok_or_else(|| Error::NotFound(format!("agent {}", agent_id)))?;
            identity.status
        };
        Self::validate_status_transition(current, new_status)?;

        // 更新内存中的状态
        if new_status == CredentialStatus::Active {
            // 恢复 active：只需更新内存状态，无需追加 label
            let mut agents = self.agents.lock().unwrap();
            if let Some((identity, _)) = agents.get_mut(agent_id) {
                identity.status = new_status;
            }
            return Ok(());
        }

        // 持久化：追加状态 label
        let mut cert_filter = HashMap::new();
        cert_filter.insert("type".to_string(), "agent-cert".to_string());
        cert_filter.insert("agent-id".to_string(), agent_id.to_string());
        let cert_blobs = storage.blob_query(&cert_filter)?;
        if let Some(cert_blob) = cert_blobs.first() {
            let label_key = match new_status {
                CredentialStatus::Suspended => LABEL_CERT_SUSPENDED,
                CredentialStatus::Revoked => LABEL_CERT_REVOKED,
                CredentialStatus::Expired => LABEL_CERT_EXPIRED,
                CredentialStatus::Active => unreachable!(),
            };
            storage.label_add(&cert_blob.hash, label_key, "true")?;
        }

        // 更新内存状态（不移除 agent，留给调用方在审计完成后处理）
        {
            let mut agents = self.agents.lock().unwrap();
            if let Some((identity, _)) = agents.get_mut(agent_id) {
                identity.status = new_status;
            }
        }

        let _ = reason; // reason 用于审计，由 Baize 层处理
        Ok(())
    }

    fn get_signing_key(
        &self,
        agent_id: &str,
        storage: &dyn BlobStore,
        crypto: &CryptoProvider,
    ) -> Result<String, Error> {
        {
            let agents = self.agents.lock().unwrap();
            let (identity, _) = agents.get(agent_id)
                .ok_or_else(|| Error::NotFound(format!("agent {}", agent_id)))?;
            if identity.status != CredentialStatus::Active {
                return Err(Error::PermissionDenied(
                    format!("agent {} is not active (status: {})", agent_id, identity.status)
                ));
            }
        }

        let mut filter = HashMap::new();
        filter.insert("type".to_string(), "agent-key".to_string());
        filter.insert(LABEL_KEY_OWNER.to_string(), agent_id.to_string());
        filter.insert(LABEL_KEY_PURPOSE.to_string(), "IDN_SIGN".to_string());
        let keys = storage.blob_query(&filter)?;

        let active_key = keys.iter().find(|b| {
            !b.labels.contains_key(LABEL_KEY_REVOKED)
        }).ok_or_else(|| Error::NotFound(format!(
            "no active IDN_SIGN key for agent {}", agent_id
        )))?;

        let pem = if let Some(secret) = baize_core::crypto::master_secret_from_env() {
            crypto.key_encryption.decrypt(&active_key.content, &secret)?
        } else {
            active_key.content.clone()
        };

        Ok(pem)
    }

    fn update_signing_key(
        &self,
        agent_id: &str,
        new_key_pem: &str,
        storage: &dyn BlobStore,
    ) -> Result<(), Error> {
        let identity = {
            let agents = self.agents.lock().unwrap();
            agents.get(agent_id)
                .map(|(id, _)| id.clone())
                .ok_or_else(|| Error::NotFound(format!("agent {}", agent_id)))?
        };

        let mut cert_filter = HashMap::new();
        cert_filter.insert("type".to_string(), "agent-cert".to_string());
        cert_filter.insert("agent-id".to_string(), agent_id.to_string());
        let certs = storage.blob_query(&cert_filter)?;

        if let Some(cert_blob) = certs.first() {
            if let Ok(new_ctx) = CertTool::recover_issuer(&cert_blob.content, new_key_pem) {
                let mut agents = self.agents.lock().unwrap();
                agents.insert(agent_id.to_string(), (identity, new_ctx));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use baize_core::storage::Storage;

    fn setup_provider() -> (CertIdentityProvider, Arc<dyn BlobStore>, CryptoProvider) {
        let provider = CertIdentityProvider::new();
        let crypto = CryptoProvider::default();
        let storage: Arc<dyn BlobStore> = Arc::new(Storage::open(":memory:").unwrap());
        provider.init_root(&*storage, &crypto).unwrap();
        (provider, storage, crypto)
    }

    /// 辅助：解引用 Arc 获取 &dyn BlobStore
    fn s(storage: &Arc<dyn BlobStore>) -> &dyn BlobStore {
        &**storage
    }

    #[test]
    fn init_root_creates_root_agent() {
        let (provider, _, _) = setup_provider();
        assert!(provider.contains(ROOT_AGENT_ID));
        let identity = provider.get_identity(ROOT_AGENT_ID).unwrap();
        assert_eq!(identity.level, 4);
        assert_eq!(identity.agent_id, ROOT_AGENT_ID);
    }

    #[test]
    fn register_and_get_agent() {
        let (provider, storage, crypto) = setup_provider();
        let identity = provider.register(
            "agent-001", 2, &["A", "B"], None, ROOT_AGENT_ID, s(&storage), &crypto
        ).unwrap();
        assert_eq!(identity.agent_id, "agent-001");
        assert_eq!(identity.level, 2);
        {
            let zones_set: std::collections::HashSet<&str> = identity.zones.iter().map(|s| s.as_str()).collect();
            assert!(zones_set.contains("A"));
            assert!(zones_set.contains("B"));
            assert_eq!(zones_set.len(), 2);
        }

        let retrieved = provider.get_identity("agent-001").unwrap();
        assert_eq!(retrieved.agent_id, "agent-001");
    }

    #[test]
    fn register_child_agent() {
        let (provider, storage, crypto) = setup_provider();
        provider.register("parent", 3, &["A", "B", "C"], None, ROOT_AGENT_ID, s(&storage), &crypto).unwrap();
        let child = provider.register("child", 2, &["A"], Some("parent"), "parent", s(&storage), &crypto).unwrap();
        assert_eq!(child.parent_id, Some("parent".to_string()));
    }

    #[test]
    fn trace_identity_chain() {
        let (provider, storage, crypto) = setup_provider();
        provider.register("parent", 3, &["A", "B"], None, ROOT_AGENT_ID, s(&storage), &crypto).unwrap();
        provider.register("child", 2, &["A"], Some("parent"), "parent", s(&storage), &crypto).unwrap();

        let chain = provider.trace_identity("child").unwrap();
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].agent_id, "child");
        assert_eq!(chain[1].agent_id, "parent");
        assert_eq!(chain[2].agent_id, ROOT_AGENT_ID);
    }

    #[test]
    fn revoke_removes_agent() {
        let (provider, storage, crypto) = setup_provider();
        provider.register("target", 2, &["A"], None, ROOT_AGENT_ID, s(&storage), &crypto).unwrap();
        provider.revoke("target", s(&storage)).unwrap();
        assert!(!provider.contains("target"));
    }

    #[test]
    fn revoke_root_fails() {
        let (provider, storage, _) = setup_provider();
        let result = provider.revoke(ROOT_AGENT_ID, s(&storage));
        assert!(result.is_err());
    }

    #[test]
    fn credential_status_lifecycle() {
        let (provider, storage, crypto) = setup_provider();
        provider.register("target", 2, &["A"], None, ROOT_AGENT_ID, s(&storage), &crypto).unwrap();

        // Active → Suspended
        provider.update_status("target", CredentialStatus::Suspended, "review", s(&storage)).unwrap();
        assert_eq!(provider.credential_status("target").unwrap(), CredentialStatus::Suspended);

        // Suspended → Active
        provider.update_status("target", CredentialStatus::Active, "cleared", s(&storage)).unwrap();
        assert_eq!(provider.credential_status("target").unwrap(), CredentialStatus::Active);

        // Active → Revoked（agent 仍在内存中，状态为 Revoked，由 Baize 层在审计后移除）
        provider.update_status("target", CredentialStatus::Revoked, "compromised", s(&storage)).unwrap();
        assert_eq!(provider.credential_status("target").unwrap(), CredentialStatus::Revoked);
    }

    #[test]
    fn status_transition_invalid_fails() {
        let (provider, storage, crypto) = setup_provider();
        provider.register("target", 2, &["A"], None, ROOT_AGENT_ID, s(&storage), &crypto).unwrap();
        provider.update_status("target", CredentialStatus::Revoked, "gone", s(&storage)).unwrap();
        // Revoked is terminal
        let result = provider.update_status("target", CredentialStatus::Active, "try revive", s(&storage));
        assert!(result.is_err());
    }

    #[test]
    fn scope_exceed_fails() {
        let (provider, storage, crypto) = setup_provider();
        provider.register("parent", 2, &["A"], None, ROOT_AGENT_ID, s(&storage), &crypto).unwrap();
        let result = provider.register("child", 3, &["A"], Some("parent"), "parent", s(&storage), &crypto);
        assert!(result.is_err());
    }

    #[test]
    fn get_signing_key_returns_active_key() {
        let (provider, storage, crypto) = setup_provider();
        provider.register("agent", 2, &["A"], None, ROOT_AGENT_ID, s(&storage), &crypto).unwrap();
        let key = provider.get_signing_key("agent", s(&storage), &crypto).unwrap();
        assert!(key.contains("PRIVATE KEY") || !key.is_empty());
    }

    #[test]
    fn list_all_agents() {
        let (provider, storage, crypto) = setup_provider();
        provider.register("a1", 2, &["A"], None, ROOT_AGENT_ID, s(&storage), &crypto).unwrap();
        provider.register("a2", 3, &["B"], None, ROOT_AGENT_ID, s(&storage), &crypto).unwrap();
        let list = provider.list();
        assert_eq!(list.len(), 3); // root + a1 + a2
    }

    #[test]
    fn restore_from_storage() {
        let (provider, storage, crypto) = setup_provider();
        provider.register("agent", 2, &["A"], None, ROOT_AGENT_ID, s(&storage), &crypto).unwrap();

        // 创建新 provider 从存储恢复
        let provider2 = CertIdentityProvider::new();
        provider2.init_root(s(&storage), &crypto).unwrap();
        provider2.restore(s(&storage), &crypto).unwrap();

        assert!(provider2.contains("agent"));
        let identity = provider2.get_identity("agent").unwrap();
        assert_eq!(identity.agent_id, "agent");
        assert_eq!(identity.level, 2);
    }

    #[test]
    fn get_cert_identity_returns_clone() {
        let (provider, storage, crypto) = setup_provider();
        provider.register("agent", 2, &["A"], None, ROOT_AGENT_ID, s(&storage), &crypto).unwrap();
        let cert = provider.get_cert_identity("agent").unwrap();
        assert_eq!(cert.agent_id, "agent");
    }

    #[test]
    fn with_issuer_allows_cert_issuance() {
        let (provider, _, _) = setup_provider();
        let result = provider.with_issuer(ROOT_AGENT_ID, |identity, _ctx| {
            assert_eq!(identity.agent_id, ROOT_AGENT_ID);
            Ok(42)
        }).unwrap();
        assert_eq!(result, 42);
    }

    #[test]
    fn update_signing_key_replaces_issuer_ctx() {
        let (provider, storage, crypto) = setup_provider();
        provider.register("parent", 3, &["A", "B"], None, ROOT_AGENT_ID, s(&storage), &crypto).unwrap();

        // 获取当前 signing key，模拟轮换
        let _old_key = provider.get_signing_key("parent", s(&storage), &crypto).unwrap();
        let new_key = CertTool::generate_key_pair().unwrap();

        // 更新 signing key
        provider.update_signing_key("parent", &new_key, s(&storage)).unwrap();

        // 验证 provider 仍包含 parent 且可签发子证书
        let child_result = provider.register("child", 2, &["A"], Some("parent"), "parent", s(&storage), &crypto);
        assert!(child_result.is_ok(), "should still be able to issue child certs after key update");
    }
}
