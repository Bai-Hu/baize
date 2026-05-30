use std::collections::HashMap;

use baize_core::cert::{CertBundle, CertIdentity, CertTool, CredentialStatus};
use baize_core::error::Error;
use baize_core::identity::IdentityProvider;
use baize_core::labels::*;
use baize_core::scope::{Level, Scope};
use baize_core::ROOT_AGENT_ID;

use crate::hook::HookContext;
use super::Baize;
use super::auditor::Auditor;
use super::identity::CertIdentityProvider;

/// Agent 管理接口：注册、撤销、列表、身份追溯
pub trait AgentRegistry {
    /// 注册 Agent
    fn agent_register(
        &mut self,
        caller_id: &str,
        name: &str,
        level: Level,
        zones: Vec<&str>,
        parent_id: Option<&str>,
    ) -> Result<(String, CertBundle), Error>;

    /// 撤销 Agent
    fn agent_revoke(&mut self, caller_id: &str, agent_id: &str) -> Result<(), Error>;

    /// 列出所有 Agent
    fn agent_list(&self) -> Vec<(String, CertIdentity)>;

    /// 身份链追溯：沿证书 parent_id 追溯
    fn trace_identity(&self, agent_id: &str) -> Result<Vec<CertIdentity>, Error>;

    /// 查询凭证状态（IDN-LCM）
    fn credential_status(&self, agent_id: &str) -> Result<CredentialStatus, Error>;

    /// 更新凭证状态（IDN-LCM）
    fn update_credential_status(
        &mut self,
        agent_id: &str,
        new_status: CredentialStatus,
        reason: &str,
    ) -> Result<(), Error>;
}

/// 权限验证接口：写/读权限检查 + Zone 验证
pub trait PermissionGuard {
    /// 验证 agent 身份 + 检查写权限
    fn verify_write_agent(&self, agent_id: &str) -> Result<CertIdentity, Error>;

    /// 验证 agent 身份（读操作：只检查 agent 存在，不限制 level）
    fn verify_read_agent(&self, agent_id: &str) -> Result<CertIdentity, Error>;

    /// Zone 检查：路径首段必须在 agent scope 内
    fn verify_file_zone(identity: &CertIdentity, path: &str) -> Result<(), Error>;

    /// IDN-ATH：验证 agent 持有有效的运行态证明
    fn require_valid_proof(&self, agent_id: &str) -> Result<baize_asl::payload::RuntimeProofContent, Error>;
}

/// 获取 CertIdentityProvider（从 dyn IdentityProvider downcast）
fn cert_provider(identity: &dyn IdentityProvider) -> Option<&CertIdentityProvider> {
    identity.as_any().downcast_ref::<CertIdentityProvider>()
}

impl AgentRegistry for Baize {
    fn agent_register(
        &mut self,
        caller_id: &str,
        name: &str,
        level: Level,
        zones: Vec<&str>,
        parent_id: Option<&str>,
    ) -> Result<(String, CertBundle), Error> {
        let scope = Scope::new(level, zones)?;

        // 权限校验：调用者必须是 root 或指定的 parent
        let issuer_agent_id = parent_id.unwrap_or(ROOT_AGENT_ID);
        if caller_id != ROOT_AGENT_ID && caller_id != issuer_agent_id {
            return Err(Error::PermissionDenied(format!(
                "agent '{}' cannot register child under '{}' (must be root or parent)",
                caller_id, issuer_agent_id
            )));
        }

        // Pre-hook: 验证身份
        let issuer_identity = self.identity.get_identity(issuer_agent_id);
        let ctx = HookContext {
            agent_id: issuer_agent_id.to_string(),
            identity: issuer_identity,
            operation: "agent_register".to_string(),
            scope: Some(scope.clone()),
            params: HashMap::new(),
            result: None,
        };
        let hook_result = self.hooks.run_pre(&ctx);
        if !hook_result.allowed {
            return Err(Error::PermissionDenied(
                hook_result.reason.unwrap_or_else(|| "blocked by hook".to_string())
            ));
        }

        // 使用 CertIdentityProvider 签发证书（需要 IssuerCtx）
        let provider = cert_provider(self.identity.as_ref())
            .ok_or_else(|| Error::Validation(
                "agent registration requires CertIdentityProvider; \
                 custom identity providers must implement their own registration logic".into()
            ))?;

        // 验证 scope 递减
        if parent_id.is_some() {
            let parent_identity = provider.get_cert_identity(issuer_agent_id);
            if let Some(parent_identity) = parent_identity {
                let parent_scope = Scope::new(
                    Level(parent_identity.level),
                    parent_identity.zones.iter().map(|s| s.as_str()),
                )?;
                Scope::validate_decrease(&parent_scope, &scope)?;
            }
        }

        // 获取签发者上下文并签发证书
        let (bundle, agent_ctx) = provider.with_issuer(issuer_agent_id, |_identity, issuer_ctx| {
            CertTool::issue_agent(
                name,
                &scope,
                issuer_ctx,
                Some(issuer_agent_id),
            )
        })?;

        let identity = bundle.identity.clone();

        // 存储 agent 证书（v1: 含 INF-SEE + IDN-ATT labels）
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
        self.storage.blob_write(&bundle.cert_pem, &cert_labels)?;

        // INF-KMS：为每种密钥用途创建独立的 agent-key blob
        let master_secret = baize_core::crypto::master_secret_from_env();
        for purpose in KEY_PURPOSES {
            let (key_pem, algorithm) = if purpose == &"IDN_SIGN" {
                (bundle.key_pem.clone(), "Ed25519")
            } else if purpose == &"SESSION" {
                let (priv_pem, _) = self.crypto.key_exchange.generate_keypair()?;
                (priv_pem, "X25519")
            } else {
                let (priv_pem, _) = baize_core::crypto::generate_ed25519_keypair()?;
                (priv_pem, "Ed25519")
            };
            let stored_key: String = if let Some(ref secret) = master_secret {
                self.crypto.key_encryption.encrypt(&key_pem, secret)?
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
            self.storage.blob_write(&stored_key, &key_labels)?;
        }

        // 创建 workspace
        self.workspace_mgr.create(name)?;

        // 审计
        self.audit("agent_register", name, "success", Some(name))?;

        // Post-hook
        self.hooks.run_post(&ctx, &hook_result);

        // 插入到 provider 内存
        provider.insert_agent(name.to_string(), identity, agent_ctx);

        Ok((name.to_string(), bundle))
    }

    fn agent_revoke(&mut self, caller_id: &str, agent_id: &str) -> Result<(), Error> {
        if !self.identity.contains(agent_id) {
            return Err(Error::NotFound(format!("agent {}", agent_id)));
        }
        if agent_id == ROOT_AGENT_ID {
            return Err(Error::PermissionDenied("cannot revoke root".into()));
        }

        // 权限校验：调用者必须是 root 或目标 agent 的 parent
        if caller_id != ROOT_AGENT_ID {
            let target_identity = self.identity.get_identity(agent_id)
                .ok_or_else(|| Error::NotFound(format!("agent {}", agent_id)))?;
            if target_identity.parent_id.as_deref() != Some(caller_id) {
                return Err(Error::PermissionDenied(format!(
                    "agent '{}' cannot revoke '{}' (must be root or parent)",
                    caller_id, agent_id
                )));
            }
        }

        // 销毁 workspace
        self.workspace_mgr.destroy(agent_id)?;

        // 标记证书为已撤销
        let mut cert_filter = HashMap::new();
        cert_filter.insert("type".to_string(), "agent-cert".to_string());
        cert_filter.insert("agent-id".to_string(), agent_id.to_string());
        let cert_blobs = self.storage.blob_query(&cert_filter)?;
        if let Some(cert_blob) = cert_blobs.first() {
            let _ = self.storage.label_add(&cert_blob.hash, "revoked", "true");
        }

        // INF-KMS：标记所有 agent-key blob 为已撤销
        let mut key_filter = HashMap::new();
        key_filter.insert("type".to_string(), "agent-key".to_string());
        key_filter.insert("agent-id".to_string(), agent_id.to_string());
        let key_blobs = self.storage.blob_query(&key_filter)?;
        for key_blob in &key_blobs {
            if !key_blob.labels.contains_key(LABEL_KEY_REVOKED) {
                let _ = self.storage.label_set(&key_blob.hash, LABEL_KEY_REVOKED, "true");
            }
        }

        // 从 provider 移除
        if let Some(provider) = cert_provider(self.identity.as_ref()) {
            provider.remove_agent(agent_id);
        }

        // 审计
        self.audit("agent_revoke", agent_id, "success", Some(agent_id))?;

        Ok(())
    }

    fn agent_list(&self) -> Vec<(String, CertIdentity)> {
        if let Some(provider) = cert_provider(self.identity.as_ref()) {
            provider.list_cert_identities()
        } else {
            // 非 CertIdentityProvider：从 AgentIdentity 转换
            self.identity.list().into_iter()
                .map(|(id, agent_id)| (id, agent_id.into()))
                .collect()
        }
    }

    fn trace_identity(&self, agent_id: &str) -> Result<Vec<CertIdentity>, Error> {
        let chain = self.identity.trace_identity(agent_id)?;
        Ok(chain.into_iter().map(Into::into).collect())
    }

    fn credential_status(&self, agent_id: &str) -> Result<CredentialStatus, Error> {
        self.identity.credential_status(agent_id)
    }

    fn update_credential_status(
        &mut self,
        agent_id: &str,
        new_status: CredentialStatus,
        reason: &str,
    ) -> Result<(), Error> {
        if agent_id == ROOT_AGENT_ID {
            return Err(Error::PermissionDenied("cannot change root credential status".into()));
        }

        let current = self.identity.credential_status(agent_id)?;

        // 委托给 identity provider 更新（含持久化 + 内存状态更新，但不移除 agent）
        self.identity.update_status(agent_id, new_status, reason, self.store())?;

        // 审计（必须在 agent 移除之前，否则 get_identity 返回 None 导致审计标签缺失）
        self.audit("credential_status_change", agent_id, &format!("{:?}→{:?}: {}", current, new_status, reason), Some(agent_id))?;

        // revoked / expired：审计完成后销毁 workspace + 从活跃列表移除
        if new_status == CredentialStatus::Revoked || new_status == CredentialStatus::Expired {
            let _ = self.workspace_mgr.destroy(agent_id);
            if let Some(provider) = cert_provider(self.identity.as_ref()) {
                provider.remove_agent(agent_id);
            }
        }

        Ok(())
    }
}

/// INF-KMS 密钥管理接口
pub trait KmsManager {
    /// 按 purpose 获取 agent 的活跃密钥（解密后的 PEM）
    fn kms_get_active_key(&self, agent_id: &str, purpose: &str) -> Result<String, Error>;

    /// 轮换指定用途的密钥，返回新密钥 blob 的 hash
    fn kms_rotate_key(&mut self, agent_id: &str, purpose: &str) -> Result<String, Error>;
}

impl KmsManager for Baize {
    fn kms_get_active_key(&self, agent_id: &str, purpose: &str) -> Result<String, Error> {
        if purpose == "IDN_SIGN" {
            return self.identity.get_signing_key(agent_id, self.store(), &self.crypto);
        }

        // 非 IDN_SIGN 用途：直接查询 storage
        let status = self.identity.credential_status(agent_id)?;
        if status != CredentialStatus::Active {
            return Err(Error::PermissionDenied(format!("agent {} is not active (status: {})", agent_id, status)));
        }

        let mut filter = HashMap::new();
        filter.insert("type".to_string(), "agent-key".to_string());
        filter.insert(LABEL_KEY_OWNER.to_string(), agent_id.to_string());
        filter.insert(LABEL_KEY_PURPOSE.to_string(), purpose.to_string());
        let keys = self.storage.blob_query(&filter)?;

        let active_key = keys.iter().find(|b| {
            !b.labels.contains_key(LABEL_KEY_REVOKED)
        }).ok_or_else(|| Error::NotFound(format!(
            "no active key for agent {} purpose {}", agent_id, purpose
        )))?;

        let pem = if let Some(secret) = baize_core::crypto::master_secret_from_env() {
            self.crypto.key_encryption.decrypt(&active_key.content, &secret)?
        } else {
            active_key.content.clone()
        };

        Ok(pem)
    }

    fn kms_rotate_key(&mut self, agent_id: &str, purpose: &str) -> Result<String, Error> {
        if agent_id == ROOT_AGENT_ID {
            return Err(Error::PermissionDenied("cannot rotate root keys".into()));
        }
        let status = self.identity.credential_status(agent_id)?;
        if status != CredentialStatus::Active {
            return Err(Error::PermissionDenied(
                format!("agent {} is not active (status: {}), cannot rotate keys", agent_id, status)
            ));
        }
        if !KEY_PURPOSES.contains(&purpose) {
            return Err(Error::Validation(format!("invalid key purpose: {}", purpose)));
        }

        // 撤销当前活跃 key
        let mut filter = HashMap::new();
        filter.insert("type".to_string(), "agent-key".to_string());
        filter.insert(LABEL_KEY_OWNER.to_string(), agent_id.to_string());
        filter.insert(LABEL_KEY_PURPOSE.to_string(), purpose.to_string());
        let existing_keys = self.storage.blob_query(&filter)?;

        for old_key in &existing_keys {
            if !old_key.labels.contains_key(LABEL_KEY_REVOKED) {
                self.storage.label_set(&old_key.hash, LABEL_KEY_REVOKED, "true")?;
            }
        }

        // 生成新 key
        let (key_pem, algorithm) = if purpose == "SESSION" {
            let (priv_pem, _) = self.crypto.key_exchange.generate_keypair()?;
            (priv_pem, "X25519")
        } else {
            let (priv_pem, _) = baize_core::crypto::generate_ed25519_keypair()?;
            (priv_pem, "Ed25519")
        };

        // 加密并存储
        let master_secret = baize_core::crypto::master_secret_from_env();
        let stored_key = if let Some(ref secret) = master_secret {
            self.crypto.key_encryption.encrypt(&key_pem, secret)?
        } else {
            key_pem.clone()
        };

        let key_labels = labels! {
            "type" => "agent-key",
            "agent-id" => agent_id,
            LABEL_KEY_OWNER => agent_id,
            LABEL_KEY_PURPOSE => purpose,
            LABEL_KEY_ALGORITHM => algorithm,
            LABEL_KEY_NONEXPORTABLE => "true",
            LABEL_KEY_SEE_LEVEL => "L1",
        };
        let blob = self.storage.blob_write(&stored_key, &key_labels)?;

        // IDN_SIGN 轮换时更新内存中 IssuerCtx
        if purpose == "IDN_SIGN" {
            self.identity.update_signing_key(agent_id, &key_pem, self.store())?;
        }

        self.audit("key_rotate", agent_id, &format!("purpose={}", purpose), Some(agent_id))?;

        Ok(blob.hash)
    }
}

impl PermissionGuard for Baize {
    fn verify_write_agent(&self, agent_id: &str) -> Result<CertIdentity, Error> {
        let agent_identity = self.identity.get_identity(agent_id)
            .ok_or_else(|| Error::NeedUserDecision(
                format!("agent '{}' not found. Register the agent first.", agent_id)
            ))?;

        if agent_identity.level < 1 {
            return Err(Error::PermissionDenied(
                format!("agent {} is Level 0 (sandbox), cannot write. Need elevation to Level >= 1.", agent_id)
            ));
        }

        match agent_identity.status {
            CredentialStatus::Active => {},
            CredentialStatus::Suspended => return Err(Error::PermissionDenied(
                format!("agent {} is suspended", agent_id)
            )),
            CredentialStatus::Revoked => return Err(Error::CredentialExpired(
                format!("agent {} is revoked", agent_id)
            )),
            CredentialStatus::Expired => return Err(Error::CredentialExpired(
                format!("agent {} is expired", agent_id)
            )),
        }

        Ok(agent_identity.into())
    }

    fn verify_read_agent(&self, agent_id: &str) -> Result<CertIdentity, Error> {
        let agent_identity = self.identity.get_identity(agent_id)
            .ok_or_else(|| Error::NeedUserDecision(
                format!("agent '{}' not found. Register the agent first.", agent_id)
            ))?;

        match agent_identity.status {
            CredentialStatus::Active | CredentialStatus::Suspended => {},
            CredentialStatus::Revoked => return Err(Error::CredentialExpired(
                format!("agent {} is revoked", agent_id)
            )),
            CredentialStatus::Expired => return Err(Error::CredentialExpired(
                format!("agent {} is expired", agent_id)
            )),
        }

        Ok(agent_identity.into())
    }

    fn verify_file_zone(identity: &CertIdentity, path: &str) -> Result<(), Error> {
        let Some((zone, _)) = path.split_once('/') else { return Ok(()); };
        if identity.zones.iter().any(|z| z == "*") { return Ok(()); }
        if !identity.zones.contains(&zone.to_string()) {
            return Err(Error::PermissionDenied(
                format!("agent {} scope {:?} does not cover zone '{}' for path '{}'",
                    identity.agent_id, identity.zones, zone, path)
            ));
        }
        Ok(())
    }

    fn require_valid_proof(&self, agent_id: &str) -> Result<baize_asl::payload::RuntimeProofContent, Error> {
        // 1. 查找该 agent 所有 runtime-proof blob
        let mut filter = HashMap::new();
        filter.insert("type".to_string(), "runtime-proof".to_string());
        filter.insert(LABEL_PROOF_AGENT.to_string(), agent_id.to_string());
        let proofs = self.storage.blob_query(&filter)?;

        if proofs.is_empty() {
            return Err(Error::ProofRequired(
                format!("agent {} has no runtime proof", agent_id)
            ));
        }

        // 2. 找到最新的 proof（按 issued_at datetime 解析比较，解析失败视为最旧）
        let mut latest_proof: Option<baize_asl::payload::RuntimeProofContent> = None;
        let mut latest_issued_at: Option<chrono::DateTime<chrono::Utc>> = None;
        for blob in &proofs {
            if let Ok(proof) = serde_json::from_str::<baize_asl::payload::RuntimeProofContent>(&blob.content) {
                let issued = chrono::DateTime::parse_from_rfc3339(&proof.issued_at)
                    .map(|dt| dt.with_timezone(&chrono::Utc))
                    .ok();
                let is_newer = match (&latest_issued_at, &issued) {
                    (Some(prev), Some(curr)) => curr > prev,
                    (Some(_), None) => false, // 当前 proof 解析失败，不替换
                    (None, _) => true,         // 尚无候选，取当前
                };
                if is_newer {
                    latest_issued_at = issued;
                    latest_proof = Some(proof);
                }
            }
        }

        let proof = latest_proof.ok_or_else(|| Error::ProofRequired(
            format!("agent {} has no parseable runtime proof", agent_id)
        ))?;

        // 3. 检查未过期（fail-closed）
        let expired = chrono::DateTime::parse_from_rfc3339(&proof.expires_at)
            .map(|dt| dt < chrono::Utc::now())
            .unwrap_or(true);
        if expired {
            return Err(Error::ProofRequired(
                format!("agent {} runtime proof expired at {}", agent_id, proof.expires_at)
            ));
        }

        // 4. 验证 credential_digest 匹配当前 agent-cert blob
        let mut cert_filter = HashMap::new();
        cert_filter.insert("type".to_string(), "agent-cert".to_string());
        cert_filter.insert("agent-id".to_string(), agent_id.to_string());
        let certs = self.storage.blob_query(&cert_filter)?;
        let current_cert_hash = certs.first()
            .map(|c| c.hash.clone())
            .unwrap_or_default();

        if proof.credential_digest != current_cert_hash {
            return Err(Error::ProofRequired(
                format!("agent {} proof credential_digest mismatch", agent_id)
            ));
        }

        // 5. 验证 binding_context_digest 匹配重新计算的值
        let cert_labels = certs.first()
            .map(|c| c.labels.clone())
            .unwrap_or_default();
        let expected_digest = baize_asl::AslAdapter::compute_binding_context_digest(
            &cert_labels,
            &proof.instance_state_attributes,
        );

        if proof.binding_context_digest != expected_digest {
            return Err(Error::ProofRequired(
                format!("agent {} proof binding_context_digest mismatch", agent_id)
            ));
        }

        Ok(proof)
    }
}

impl Baize {
    /// v2 Phase 1.3: 检查 agent 是否可访问指定 path 的 zone（含 elevation 授予的临时 zone）
    pub(super) fn is_zone_accessible(
        &self,
        agent_id: &str,
        identity: &CertIdentity,
        path: &str,
    ) -> Result<(), Error> {
        // 1. 快速路径：agent 自身 zones 覆盖
        if Self::verify_file_zone(identity, path).is_ok() {
            return Ok(());
        }

        // 2. 查询当前有效的 elevation
        let zone = path.split_once('/').map(|(z, _)| z).unwrap_or(path);

        let mut filter = HashMap::new();
        filter.insert("type".to_string(), "elevation-request".to_string());
        filter.insert("elevation-agent".to_string(), agent_id.to_string());
        filter.insert("elevation-approved".to_string(), "true".to_string());

        let elevations = self.storage.blob_query(&filter)?;

        for elev in &elevations {
            // 跳过已归还/撤销的
            if let Some(status) = elev.labels.get("elevation-status") {
                if status == "Returned" || status == "Revoked" {
                    continue;
                }
            }

            // 跳过已过期的（解析失败视为已过期，fail-closed）
            if let Some(expires) = elev.labels.get("elevation-expires") {
                if super::is_timestamp_expired(expires) {
                    continue;
                }
            }

            // 检查 zone 是否在 elevation 授予的 zones 内
            if let Some(zones_str) = elev.labels.get("elevation-zones") {
                if let Ok(zones) = serde_json::from_str::<Vec<String>>(zones_str) {
                    if zones.iter().any(|z| z == zone || z == "*") {
                        return Ok(());
                    }
                }
            }
        }

        Err(Error::PermissionDenied(
            format!("agent {} scope {:?} does not cover zone '{}' (no active elevation)",
                agent_id, identity.zones, zone)
        ))
    }
}

#[cfg(test)]
mod v1_tests {
    use super::*;
    use baize_core::scope::Level;

    fn setup() -> Baize {
        Baize::init_in_memory().unwrap()
    }

    // ─── INF-KMS 测试 ───

    #[test]
    fn agent_register_creates_5_key_blobs() {
        let mut baize = setup();
        baize.agent_register("baize-root", "kms-agent", Level(2), vec!["A"], None).unwrap();

        let mut filter = HashMap::new();
        filter.insert("type".to_string(), "agent-key".to_string());
        filter.insert("agent-id".to_string(), "kms-agent".to_string());
        let keys = baize.storage.blob_query(&filter).unwrap();

        assert_eq!(keys.len(), 5, "should create 5 key blobs for 5 purposes");
    }

    #[test]
    fn agent_key_purposes_are_correct() {
        let mut baize = setup();
        baize.agent_register("baize-root", "purpose-agent", Level(2), vec!["A"], None).unwrap();

        for purpose in KEY_PURPOSES {
            let mut filter = HashMap::new();
            filter.insert("type".to_string(), "agent-key".to_string());
            filter.insert("agent-id".to_string(), "purpose-agent".to_string());
            filter.insert(LABEL_KEY_PURPOSE.to_string(), purpose.to_string());
            let keys = baize.storage.blob_query(&filter).unwrap();
            assert_eq!(keys.len(), 1, "should have exactly 1 key for purpose {}", purpose);

            let key = &keys[0];
            assert_eq!(key.labels.get(LABEL_KEY_OWNER).unwrap(), "purpose-agent");
            let expected_algo = if *purpose == "SESSION" { "X25519" } else { "Ed25519" };
            assert_eq!(key.labels.get(LABEL_KEY_ALGORITHM).unwrap(), expected_algo,
                "purpose {} should use {}", purpose, expected_algo);
            assert_eq!(key.labels.get(LABEL_KEY_NONEXPORTABLE).unwrap(), "true");
            assert_eq!(key.labels.get(LABEL_KEY_SEE_LEVEL).unwrap(), "L1");
        }
    }

    // ─── IDN-ATT 测试 ───

    #[test]
    fn agent_cert_has_idn_att_labels() {
        let mut baize = setup();
        baize.agent_register("baize-root", "att-agent", Level(3), vec!["A", "B"], None).unwrap();

        let mut filter = HashMap::new();
        filter.insert("type".to_string(), "agent-cert".to_string());
        filter.insert("agent-id".to_string(), "att-agent".to_string());
        let certs = baize.storage.blob_query(&filter).unwrap();
        assert_eq!(certs.len(), 1);

        let cert = &certs[0];
        // 主体状态属性
        assert_eq!(cert.labels.get(LABEL_CERT_AGENT).unwrap(), "att-agent");
        assert_eq!(cert.labels.get(LABEL_CERT_LEVEL).unwrap(), "3");
        assert_eq!(cert.labels.get(LABEL_CERT_STATUS).unwrap(), "active");
        assert!(cert.labels.get(LABEL_CERT_ZONES).unwrap().contains("A"));
        assert!(cert.labels.get(LABEL_CERT_ZONES).unwrap().contains("B"));
        assert!(cert.labels.get(LABEL_CERT_PARENT).is_none()); // root agent has no parent
    }

    #[test]
    fn agent_cert_has_see_labels() {
        let mut baize = setup();
        baize.agent_register("baize-root", "see-agent", Level(2), vec!["A"], None).unwrap();

        let mut filter = HashMap::new();
        filter.insert("type".to_string(), "agent-cert".to_string());
        filter.insert("agent-id".to_string(), "see-agent".to_string());
        let certs = baize.storage.blob_query(&filter).unwrap();

        let cert = &certs[0];
        assert_eq!(cert.labels.get(LABEL_SEE_LEVEL).unwrap(), "L1");
        assert_eq!(cert.labels.get(LABEL_SEE_ENV_ID).unwrap(), "default");
        assert_eq!(cert.labels.get(LABEL_SEE_PLATFORM_STATE).unwrap(), "unknown");
        assert_eq!(cert.labels.get(LABEL_SEE_ATTESTATION).unwrap(), "false");
        assert!(cert.labels.contains_key(LABEL_CERT_HOST_IDENTITY));
    }

    #[test]
    fn child_agent_has_parent_label() {
        let mut baize = setup();
        baize.agent_register("baize-root", "parent", Level(3), vec!["A", "B"], None).unwrap();
        baize.agent_register("baize-root", "child", Level(2), vec!["A"], Some("parent")).unwrap();

        let mut filter = HashMap::new();
        filter.insert("type".to_string(), "agent-cert".to_string());
        filter.insert("agent-id".to_string(), "child".to_string());
        let certs = baize.storage.blob_query(&filter).unwrap();

        let cert = &certs[0];
        assert_eq!(cert.labels.get(LABEL_CERT_PARENT).unwrap(), "parent");
        assert_eq!(cert.labels.get(LABEL_CERT_AGENT).unwrap(), "child");
    }

    // ─── IDN-LCM 测试 ───

    #[test]
    fn credential_status_default_is_active() {
        let mut baize = setup();
        baize.agent_register("baize-root", "lcm-agent", Level(2), vec!["A"], None).unwrap();
        let status = baize.credential_status("lcm-agent").unwrap();
        assert_eq!(status, CredentialStatus::Active);
    }

    #[test]
    fn suspend_active_agent() {
        let mut baize = setup();
        baize.agent_register("baize-root", "target", Level(2), vec!["A"], None).unwrap();

        baize.update_credential_status("target", CredentialStatus::Suspended, "security review").unwrap();
        assert_eq!(baize.credential_status("target").unwrap(), CredentialStatus::Suspended);
    }

    #[test]
    fn revoke_active_agent() {
        let mut baize = setup();
        baize.agent_register("baize-root", "target", Level(2), vec!["A"], None).unwrap();

        baize.update_credential_status("target", CredentialStatus::Revoked, "compromised").unwrap();
        // revoked agent removed from active list
        assert!(baize.credential_status("target").is_err());
    }

    #[test]
    fn reactivate_suspended_agent() {
        let mut baize = setup();
        baize.agent_register("baize-root", "target", Level(2), vec!["A"], None).unwrap();

        baize.update_credential_status("target", CredentialStatus::Suspended, "review").unwrap();
        baize.update_credential_status("target", CredentialStatus::Active, "cleared").unwrap();
        assert_eq!(baize.credential_status("target").unwrap(), CredentialStatus::Active);
    }

    #[test]
    fn expire_suspended_agent() {
        let mut baize = setup();
        baize.agent_register("baize-root", "target", Level(2), vec!["A"], None).unwrap();

        baize.update_credential_status("target", CredentialStatus::Suspended, "review").unwrap();
        baize.update_credential_status("target", CredentialStatus::Expired, "timeout").unwrap();
        // expired agent removed from active list
        assert!(baize.credential_status("target").is_err());
    }

    #[test]
    fn expire_active_agent() {
        // 协议 §7.3：任意 → expired
        let mut baize = setup();
        baize.agent_register("baize-root", "target", Level(2), vec!["A"], None).unwrap();

        baize.update_credential_status("target", CredentialStatus::Expired, "natural expiry").unwrap();
        assert!(baize.credential_status("target").is_err());
    }

    #[test]
    fn invalid_transition_active_to_active_ok() {
        // 幂等：同状态转换应成功
        let mut baize = setup();
        baize.agent_register("baize-root", "target", Level(2), vec!["A"], None).unwrap();
        let result = baize.update_credential_status("target", CredentialStatus::Active, "no-op");
        assert!(result.is_ok());
    }

    #[test]
    fn invalid_transition_revoked_to_active_fails() {
        let mut baize = setup();
        baize.agent_register("baize-root", "target", Level(2), vec!["A"], None).unwrap();
        baize.update_credential_status("target", CredentialStatus::Revoked, "compromised").unwrap();
        // target already removed, so this should fail with NotFound
        assert!(baize.credential_status("target").is_err());
    }

    #[test]
    fn cannot_change_root_status() {
        let mut baize = setup();
        let result = baize.update_credential_status(ROOT_AGENT_ID, CredentialStatus::Suspended, "test");
        assert!(result.is_err());
    }

    #[test]
    fn status_suspended_persists_label() {
        let mut baize = setup();
        baize.agent_register("baize-root", "persist", Level(2), vec!["A"], None).unwrap();
        baize.update_credential_status("persist", CredentialStatus::Suspended, "audit").unwrap();

        // 直接查询 cert blob 的 labels 验证持久化
        let mut filter = HashMap::new();
        filter.insert("type".to_string(), "agent-cert".to_string());
        filter.insert("agent-id".to_string(), "persist".to_string());
        let certs = baize.storage.blob_query(&filter).unwrap();
        let cert_hash = &certs[0].hash;

        let labels = baize.storage.label_query_for_entity(cert_hash).unwrap();
        assert!(labels.iter().any(|l| l.key == LABEL_CERT_SUSPENDED && l.value == "true"));
    }

    // ─── IDN-TRC 测试 ───

    #[test]
    fn trace_identity_includes_status() {
        let mut baize = setup();
        baize.agent_register("baize-root", "parent", Level(3), vec!["A", "B"], None).unwrap();
        baize.agent_register("baize-root", "child", Level(2), vec!["A"], Some("parent")).unwrap();

        let chain = baize.trace_identity("child").unwrap();
        assert_eq!(chain.len(), 3);
        // 每个节点都应有 status
        for node in &chain {
            assert_eq!(node.status, CredentialStatus::Active);
        }
    }

    #[test]
    fn trace_identity_shows_suspended_status() {
        let mut baize = setup();
        baize.agent_register("baize-root", "parent", Level(3), vec!["A"], None).unwrap();
        baize.agent_register("baize-root", "child", Level(2), vec!["A"], Some("parent")).unwrap();

        // suspend parent
        baize.update_credential_status("parent", CredentialStatus::Suspended, "review").unwrap();

        let chain = baize.trace_identity("child").unwrap();
        // child → parent (suspended) → root
        assert_eq!(chain[0].status, CredentialStatus::Active);
        assert_eq!(chain[1].status, CredentialStatus::Suspended);
        assert_eq!(chain[2].status, CredentialStatus::Active);
    }

    // ─── INF-KMS Phase 2 测试 ───

    #[test]
    fn key_rotation_creates_new_key() {
        let mut baize = setup();
        baize.agent_register("baize-root", "rot-agent", Level(2), vec!["A"], None).unwrap();

        let old_hash = {
            let mut f = HashMap::new();
            f.insert("type".into(), "agent-key".into());
            f.insert(LABEL_KEY_OWNER.into(), "rot-agent".into());
            f.insert(LABEL_KEY_PURPOSE.into(), "IDN_SIGN".into());
            let keys = baize.storage.blob_query(&f).unwrap();
            keys[0].hash.clone()
        };

        let new_hash = baize.kms_rotate_key("rot-agent", "IDN_SIGN").unwrap();
        assert_ne!(new_hash, old_hash, "rotation should produce a different key blob");
    }

    #[test]
    fn key_rotation_revokes_old_key() {
        let mut baize = setup();
        baize.agent_register("baize-root", "rot-agent", Level(2), vec!["A"], None).unwrap();

        baize.kms_rotate_key("rot-agent", "INT_SIGN").unwrap();

        let mut f = HashMap::new();
        f.insert("type".into(), "agent-key".into());
        f.insert(LABEL_KEY_OWNER.into(), "rot-agent".into());
        f.insert(LABEL_KEY_PURPOSE.into(), "INT_SIGN".into());
        let keys = baize.storage.blob_query(&f).unwrap();
        assert_eq!(keys.len(), 2, "should have old + new key");

        let revoked = keys.iter().find(|k| k.labels.contains_key(LABEL_KEY_REVOKED)).unwrap();
        assert_eq!(revoked.labels.get(LABEL_KEY_REVOKED).unwrap(), "true");

        let active = keys.iter().find(|k| !k.labels.contains_key(LABEL_KEY_REVOKED)).unwrap();
        assert!(active.labels.get(LABEL_KEY_REVOKED).is_none());
    }

    #[test]
    fn key_rotation_idn_sign_updates_issuer_ctx() {
        let mut baize = setup();
        baize.agent_register("baize-root", "parent", Level(3), vec!["A", "B"], None).unwrap();

        baize.kms_rotate_key("parent", "IDN_SIGN").unwrap();

        // 轮换后 parent 应仍能签发子 agent
        baize.agent_register("baize-root", "child", Level(2), vec!["A"], Some("parent")).unwrap();
        assert!(baize.identity.contains("child"));
    }

    #[test]
    fn rotate_root_fails() {
        let mut baize = setup();
        let result = baize.kms_rotate_key(ROOT_AGENT_ID, "IDN_SIGN");
        assert!(result.is_err());
        match result {
            Err(Error::PermissionDenied(msg)) => assert!(msg.contains("root")),
            other => panic!("expected PermissionDenied, got {:?}", other),
        }
    }

    #[test]
    fn rotate_nonexistent_agent_fails() {
        let mut baize = setup();
        let result = baize.kms_rotate_key("ghost", "IDN_SIGN");
        assert!(result.is_err());
    }

    #[test]
    fn rotate_invalid_purpose_fails() {
        let mut baize = setup();
        baize.agent_register("baize-root", "rot-agent", Level(2), vec!["A"], None).unwrap();
        let result = baize.kms_rotate_key("rot-agent", "INVALID_PURPOSE");
        assert!(result.is_err());
        match result {
            Err(Error::Validation(msg)) => assert!(msg.contains("invalid key purpose")),
            other => panic!("expected Validation, got {:?}", other),
        }
    }

    #[test]
    fn revoke_destroys_all_keys() {
        let mut baize = setup();
        baize.agent_register("baize-root", "doomed", Level(2), vec!["A"], None).unwrap();
        baize.agent_revoke("baize-root", "doomed").unwrap();

        let mut f = HashMap::new();
        f.insert("type".into(), "agent-key".into());
        f.insert("agent-id".into(), "doomed".into());
        let keys = baize.storage.blob_query(&f).unwrap();
        assert_eq!(keys.len(), 5, "revoked agent should still have 5 key blobs");

        for key in &keys {
            assert!(key.labels.contains_key(LABEL_KEY_REVOKED),
                "all keys should be revoked, but {:?} is not", key.hash);
        }
    }

    #[test]
    fn kms_get_active_key_excludes_revoked() {
        let mut baize = setup();
        baize.agent_register("baize-root", "key-agent", Level(2), vec!["A"], None).unwrap();

        let old_key = baize.kms_get_active_key("key-agent", "IDN_SIGN").unwrap();
        baize.kms_rotate_key("key-agent", "IDN_SIGN").unwrap();
        let new_key = baize.kms_get_active_key("key-agent", "IDN_SIGN").unwrap();

        assert_ne!(old_key, new_key, "active key should change after rotation");
    }

    #[test]
    fn kms_get_active_key_no_revoked_returns_not_found() {
        let mut baize = setup();
        baize.agent_register("baize-root", "temp", Level(2), vec!["A"], None).unwrap();
        baize.agent_revoke("baize-root", "temp").unwrap();

        let result = baize.kms_get_active_key("temp", "IDN_SIGN");
        assert!(result.is_err(), "revoked agent should have no active key");
    }

    // ─── Phase 4: IDN-ATH proof 验证测试 ───

    /// 辅助：为 agent 生成一个合法的 runtime-proof blob
    fn write_valid_proof(baize: &mut Baize, agent_id: &str) -> String {
        let mut cert_filter = HashMap::new();
        cert_filter.insert("type".to_string(), "agent-cert".to_string());
        cert_filter.insert("agent-id".to_string(), agent_id.to_string());
        let certs = baize.storage.blob_query(&cert_filter).unwrap();
        let cert_hash = certs[0].hash.clone();
        let cert_labels = certs[0].labels.clone();

        let instance_state = serde_json::json!({"instance_id": agent_id, "instance_status": "running"});
        let binding_digest = baize_asl::AslAdapter::compute_binding_context_digest(
            &cert_labels, &instance_state,
        );

        let now = chrono::Utc::now();
        let proof = baize_asl::payload::RuntimeProofContent {
            proof_id: format!("proof-{}", now.timestamp_millis()),
            credential_digest: cert_hash.clone(),
            instance_state_attributes: instance_state,
            binding_context_digest: binding_digest,
            proof_anchor_mode: baize_asl::payload::ProofAnchorMode::CredentialAnchored,
            issued_at: now.to_rfc3339(),
            expires_at: (now + chrono::Duration::minutes(5)).to_rfc3339(),
        };
        let proof_labels = HashMap::from([
            ("type".to_string(), "runtime-proof".to_string()),
            (LABEL_PROOF_AGENT.to_string(), agent_id.to_string()),
            (LABEL_PROOF_CREDENTIAL.to_string(), cert_hash.clone()),
        ]);
        baize.storage.blob_write(&serde_json::to_string(&proof).unwrap(), &proof_labels).unwrap();
        cert_hash
    }

    #[test]
    fn require_valid_proof_no_proof_fails() {
        let mut baize = setup();
        baize.agent_register("baize-root", "prover", Level(3), vec!["A"], None).unwrap();

        let result = baize.require_valid_proof("prover");
        assert!(result.is_err());
        match result {
            Err(Error::ProofRequired(msg)) => assert!(msg.contains("no runtime proof")),
            other => panic!("expected ProofRequired, got {:?}", other),
        }
    }

    #[test]
    fn require_valid_proof_expired_proof_fails() {
        let mut baize = setup();
        baize.agent_register("baize-root", "prover", Level(3), vec!["A"], None).unwrap();

        // 写一个已过期的 proof
        let mut cert_filter = HashMap::new();
        cert_filter.insert("type".to_string(), "agent-cert".to_string());
        cert_filter.insert("agent-id".to_string(), "prover".to_string());
        let certs = baize.storage.blob_query(&cert_filter).unwrap();
        let cert_hash = certs[0].hash.clone();
        let cert_labels = certs[0].labels.clone();

        let instance_state = serde_json::json!({"instance_id": "prover"});
        let binding_digest = baize_asl::AslAdapter::compute_binding_context_digest(
            &cert_labels, &instance_state,
        );

        let now = chrono::Utc::now();
        let proof = baize_asl::payload::RuntimeProofContent {
            proof_id: "proof-expired".to_string(),
            credential_digest: cert_hash,
            instance_state_attributes: instance_state,
            binding_context_digest: binding_digest,
            proof_anchor_mode: baize_asl::payload::ProofAnchorMode::CredentialAnchored,
            issued_at: (now - chrono::Duration::minutes(10)).to_rfc3339(),
            expires_at: (now - chrono::Duration::minutes(5)).to_rfc3339(),
        };
        let proof_labels = HashMap::from([
            ("type".to_string(), "runtime-proof".to_string()),
            (LABEL_PROOF_AGENT.to_string(), "prover".to_string()),
            (LABEL_PROOF_CREDENTIAL.to_string(), proof.credential_digest.clone()),
        ]);
        baize.storage.blob_write(&serde_json::to_string(&proof).unwrap(), &proof_labels).unwrap();

        let result = baize.require_valid_proof("prover");
        assert!(result.is_err());
        match result {
            Err(Error::ProofRequired(msg)) => assert!(msg.contains("expired"), "got: {}", msg),
            other => panic!("expected ProofRequired, got {:?}", other),
        }
    }

    #[test]
    fn require_valid_proof_credential_mismatch_fails() {
        let mut baize = setup();
        baize.agent_register("baize-root", "prover", Level(3), vec!["A"], None).unwrap();

        let mut cert_filter = HashMap::new();
        cert_filter.insert("type".to_string(), "agent-cert".to_string());
        cert_filter.insert("agent-id".to_string(), "prover".to_string());
        let certs = baize.storage.blob_query(&cert_filter).unwrap();
        let cert_labels = certs[0].labels.clone();

        let instance_state = serde_json::json!({"instance_id": "prover"});
        let binding_digest = baize_asl::AslAdapter::compute_binding_context_digest(
            &cert_labels, &instance_state,
        );

        let now = chrono::Utc::now();
        let proof = baize_asl::payload::RuntimeProofContent {
            proof_id: "proof-mismatch".to_string(),
            credential_digest: "sha256:wrong-cert-hash".to_string(), // 不匹配
            instance_state_attributes: instance_state,
            binding_context_digest: binding_digest,
            proof_anchor_mode: baize_asl::payload::ProofAnchorMode::CredentialAnchored,
            issued_at: now.to_rfc3339(),
            expires_at: (now + chrono::Duration::minutes(5)).to_rfc3339(),
        };
        let proof_labels = HashMap::from([
            ("type".to_string(), "runtime-proof".to_string()),
            (LABEL_PROOF_AGENT.to_string(), "prover".to_string()),
            (LABEL_PROOF_CREDENTIAL.to_string(), "sha256:wrong-cert-hash".to_string()),
        ]);
        baize.storage.blob_write(&serde_json::to_string(&proof).unwrap(), &proof_labels).unwrap();

        let result = baize.require_valid_proof("prover");
        assert!(result.is_err());
        match result {
            Err(Error::ProofRequired(msg)) => assert!(msg.contains("credential_digest mismatch"), "got: {}", msg),
            other => panic!("expected ProofRequired, got {:?}", other),
        }
    }

    #[test]
    fn require_valid_proof_valid_succeeds() {
        let mut baize = setup();
        baize.agent_register("baize-root", "prover", Level(3), vec!["A"], None).unwrap();

        write_valid_proof(&mut baize, "prover");

        let result = baize.require_valid_proof("prover");
        assert!(result.is_ok(), "valid proof should succeed: {:?}", result);
        assert!(result.unwrap().proof_id.contains("proof-"));
    }

    #[test]
    fn require_valid_proof_selects_latest() {
        let mut baize = setup();
        baize.agent_register("baize-root", "prover", Level(3), vec!["A"], None).unwrap();

        let mut cert_filter = HashMap::new();
        cert_filter.insert("type".to_string(), "agent-cert".to_string());
        cert_filter.insert("agent-id".to_string(), "prover".to_string());
        let certs = baize.storage.blob_query(&cert_filter).unwrap();
        let cert_hash = certs[0].hash.clone();
        let cert_labels = certs[0].labels.clone();

        let instance_state = serde_json::json!({"instance_id": "prover"});
        let binding_digest = baize_asl::AslAdapter::compute_binding_context_digest(
            &cert_labels, &instance_state,
        );

        // 先写一个过期的 proof
        let now = chrono::Utc::now();
        let old_proof = baize_asl::payload::RuntimeProofContent {
            proof_id: "proof-old".to_string(),
            credential_digest: cert_hash.clone(),
            instance_state_attributes: instance_state.clone(),
            binding_context_digest: binding_digest.clone(),
            proof_anchor_mode: baize_asl::payload::ProofAnchorMode::CredentialAnchored,
            issued_at: (now - chrono::Duration::minutes(10)).to_rfc3339(),
            expires_at: (now - chrono::Duration::minutes(5)).to_rfc3339(),
        };
        let old_labels = HashMap::from([
            ("type".to_string(), "runtime-proof".to_string()),
            (LABEL_PROOF_AGENT.to_string(), "prover".to_string()),
            (LABEL_PROOF_CREDENTIAL.to_string(), cert_hash.clone()),
        ]);
        baize.storage.blob_write(&serde_json::to_string(&old_proof).unwrap(), &old_labels).unwrap();

        // 再写一个有效的 proof
        write_valid_proof(&mut baize, "prover");

        let result = baize.require_valid_proof("prover");
        assert!(result.is_ok(), "should pick latest (valid) proof: {:?}", result);
        let proof = result.unwrap();
        assert_ne!(proof.proof_id, "proof-old", "should pick the newer proof");
    }
}
