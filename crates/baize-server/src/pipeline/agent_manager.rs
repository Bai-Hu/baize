use std::collections::HashMap;

use baize_core::cert::{CertBundle, CertIdentity, CertTool};
use baize_core::error::Error;
use baize_core::scope::{Level, Scope};
use baize_core::ROOT_AGENT_ID;

use crate::hook::HookContext;
use super::Baize;
use super::auditor::Auditor;

/// Agent 管理接口：注册、撤销、列表、身份追溯
pub trait AgentRegistry {
    /// 注册 Agent
    fn agent_register(
        &mut self,
        name: &str,
        level: Level,
        zones: Vec<&str>,
        parent_id: Option<&str>,
    ) -> Result<(String, CertBundle), Error>;

    /// 撤销 Agent
    fn agent_revoke(&mut self, agent_id: &str) -> Result<(), Error>;

    /// 列出所有 Agent
    fn agent_list(&self) -> Vec<(String, CertIdentity)>;

    /// 身份链追溯：沿证书 parent_id 追溯
    fn trace_identity(&self, agent_id: &str) -> Result<Vec<CertIdentity>, Error>;
}

/// 权限验证接口：写/读权限检查 + Zone 验证
pub trait PermissionGuard {
    /// 验证 agent 身份 + 检查写权限
    fn verify_write_agent(&self, agent_id: &str) -> Result<CertIdentity, Error>;

    /// 验证 agent 身份（读操作：只检查 agent 存在，不限制 level）
    fn verify_read_agent(&self, agent_id: &str) -> Result<CertIdentity, Error>;

    /// Zone 检查：路径首段必须在 agent scope 内
    fn verify_file_zone(identity: &CertIdentity, path: &str) -> Result<(), Error>;
}

impl AgentRegistry for Baize {
    fn agent_register(
        &mut self,
        name: &str,
        level: Level,
        zones: Vec<&str>,
        parent_id: Option<&str>,
    ) -> Result<(String, CertBundle), Error> {
        let scope = Scope::new(level, zones)?;

        // Pre-hook: 验证身份
        let issuer_agent_id = parent_id.unwrap_or(ROOT_AGENT_ID);
        let issuer_identity = self.agents.get(issuer_agent_id)
            .map(|(id, _)| id.clone());
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

        // 验证 scope 递减
        if parent_id.is_some() {
            if let Some((parent_identity, _)) = self.agents.get(issuer_agent_id) {
                let parent_scope = Scope::new(
                    Level(parent_identity.level),
                    parent_identity.zones.iter().map(|s| s.as_str()),
                )?;
                Scope::validate_decrease(&parent_scope, &scope)?;
            }
        }

        // 获取签发者上下文
        let issuer_entry = self.agents.get(issuer_agent_id)
            .ok_or_else(|| Error::NotFound(format!("issuer agent {}", issuer_agent_id)))?;
        let issuer_ctx = &issuer_entry.1;

        // 签发证书
        let (bundle, agent_ctx) = CertTool::issue_agent(
            name,
            &scope,
            issuer_ctx,
            Some(issuer_agent_id),
        )?;

        let identity = bundle.identity.clone();

        // 存储 agent 证书
        let mut cert_labels = labels! {
            "type" => "agent-cert",
            "agent-id" => name,
        };
        if let Some(pid) = parent_id {
            cert_labels.insert("parent-id".to_string(), pid.to_string());
        }
        self.storage.blob_write(&bundle.cert_pem, &cert_labels)?;

        // 存储 agent 私钥
        let key_labels = labels! {
            "type" => "agent-key",
            "agent-id" => name,
        };
        self.storage.blob_write(&bundle.key_pem, &key_labels)?;

        // 创建 workspace
        self.workspace_mgr.create(name)?;

        // 审计
        self.audit("agent_register", name, "success", Some(name))?;

        // Post-hook
        self.hooks.run_post(&ctx, &hook_result);

        self.agents.insert(name.to_string(), (identity, agent_ctx));

        Ok((name.to_string(), bundle))
    }

    fn agent_revoke(&mut self, agent_id: &str) -> Result<(), Error> {
        if !self.agents.contains_key(agent_id) {
            return Err(Error::NotFound(format!("agent {}", agent_id)));
        }
        if agent_id == ROOT_AGENT_ID {
            return Err(Error::PermissionDenied("cannot revoke root".into()));
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

        // 移除 agent
        self.agents.remove(agent_id);

        // 审计
        self.audit("agent_revoke", agent_id, "success", Some(agent_id))?;

        Ok(())
    }

    fn agent_list(&self) -> Vec<(String, CertIdentity)> {
        self.agents.iter()
            .map(|(id, (identity, _))| (id.clone(), identity.clone()))
            .collect()
    }

    fn trace_identity(&self, agent_id: &str) -> Result<Vec<CertIdentity>, Error> {
        let (identity, _) = self.agents.get(agent_id)
            .ok_or_else(|| Error::NotFound(format!("agent {}", agent_id)))?;

        let mut chain = vec![identity.clone()];
        let mut current = identity.parent_id.clone();

        while let Some(parent_id) = current {
            if let Some((parent_identity, _)) = self.agents.get(&parent_id) {
                current = parent_identity.parent_id.clone();
                chain.push(parent_identity.clone());
            } else {
                break;
            }
        }

        Ok(chain)
    }
}

impl PermissionGuard for Baize {
    fn verify_write_agent(&self, agent_id: &str) -> Result<CertIdentity, Error> {
        let (identity, _) = self.agents.get(agent_id)
            .ok_or_else(|| Error::NeedUserDecision(
                format!("agent '{}' not found. Register the agent first.", agent_id)
            ))?;

        if identity.level < 1 {
            return Err(Error::PermissionDenied(
                format!("agent {} is Level 0 (sandbox), cannot write. Need elevation to Level >= 1.", agent_id)
            ));
        }

        Ok(identity.clone())
    }

    fn verify_read_agent(&self, agent_id: &str) -> Result<CertIdentity, Error> {
        let (identity, _) = self.agents.get(agent_id)
            .ok_or_else(|| Error::NeedUserDecision(
                format!("agent '{}' not found. Register the agent first.", agent_id)
            ))?;
        Ok(identity.clone())
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
}
