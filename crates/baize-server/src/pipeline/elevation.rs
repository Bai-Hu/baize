use std::collections::HashMap;

use baize_core::error::Error;
use baize_core::scope::{ElevationMode, ElevationRequest, ElevationStatus, Level, Scope};
use baize_core::ROOT_AGENT_ID;

use super::Baize;
use super::auditor::Auditor;

/// 借权管理接口：申请、审批、归还、列表
pub trait ElevationManager {
    /// 申请借权
    fn elevation_request(
        &mut self,
        agent_id: &str,
        zones: Vec<&str>,
        mode: ElevationMode,
        reason: &str,
        duration: Option<&str>,
    ) -> Result<String, Error>;

    /// 审批借权
    fn elevation_approve(&mut self, request_hash: &str, approver: &str) -> Result<(), Error>;

    /// 归还借权
    fn elevation_return(
        &mut self,
        request_hash: &str,
        agent_id: &str,
        caller: &str,
    ) -> Result<(), Error>;

    /// 列出借权请求
    fn elevation_list(&self) -> Result<Vec<ElevationRequest>, Error>;
}

impl Baize {
    /// 审批权限校验：baize-root 可批任何请求；parent agent 只能批 scope 内请求
    pub(super) fn validate_approver(
        &self,
        approver: &str,
        request_agent_id: &str,
        request_zones: &std::collections::HashSet<String>,
    ) -> Result<(), Error> {
        // baize-root 可批任何请求
        if approver == ROOT_AGENT_ID {
            return Ok(());
        }

        // approver 必须存在
        let (approver_identity, _) = self.agents.get(approver)
            .ok_or_else(|| Error::NotFound(format!("approver agent {}", approver)))?;

        // approver 必须是 requester 的 parent
        let (requester_identity, _) = self.agents.get(request_agent_id)
            .ok_or_else(|| Error::NotFound(format!("requester agent {}", request_agent_id)))?;

        let is_parent = requester_identity.parent_id.as_deref() == Some(approver);
        if !is_parent {
            return Err(Error::PermissionDenied(
                format!("{} is not the parent of {}, only parent or baize-root can approve",
                    approver, request_agent_id)
            ));
        }

        // 检查请求的 zones 是否在 approver scope 内
        let approver_scope = Scope::new(
            Level(approver_identity.level),
            approver_identity.zones.iter().map(|s| s.as_str()),
        )?;

        let all_in_scope = request_zones.iter().all(|z| {
            approver_scope.zones.contains(z) || approver_scope.zones.contains("*")
        });

        if !all_in_scope {
            return Err(Error::PermissionDenied(
                format!("requested zones {:?} exceed approver {} scope, only baize-root can approve",
                    request_zones, approver)
            ));
        }

        Ok(())
    }

    /// 主动清理已过期的借权：标记为 Expired + 清理 workspace
    pub(super) fn elevation_cleanup_expired(&self) -> Result<usize, Error> {
        let mut filter = HashMap::new();
        filter.insert("type".to_string(), "elevation-request".to_string());
        filter.insert("elevation-approved".to_string(), "true".to_string());

        let blobs = self.storage.blob_query(&filter)?;
        let mut expired_count = 0;

        for blob in &blobs {
            // 已有显式状态（Returned/Revoked）→ 跳过
            if blob.labels.contains_key("elevation-status") {
                continue;
            }

            if let Some(expires_str) = blob.labels.get("elevation-expires") {
                if let Ok(expires) = chrono::DateTime::parse_from_rfc3339(expires_str) {
                    if chrono::Utc::now() > expires {
                        // 标记为 Expired
                        let _ = self.storage.label_add(&blob.hash, "elevation-status", "Expired");
                        expired_count += 1;
                    }
                }
            }
        }

        Ok(expired_count)
    }
}

impl ElevationManager for Baize {
    fn elevation_request(
        &mut self,
        agent_id: &str,
        zones: Vec<&str>,
        mode: ElevationMode,
        reason: &str,
        duration: Option<&str>,
    ) -> Result<String, Error> {
        // 主动清理已过期的借权
        let _ = self.elevation_cleanup_expired();

        // 验证 agent 存在
        let _ = self.agents.get(agent_id)
            .ok_or_else(|| Error::NotFound(format!("agent {}", agent_id)))?;

        let zones_vec: Vec<String> = zones.iter().map(|s| s.to_string()).collect();
        let zones_str = serde_json::to_string(&zones_vec)
            .unwrap_or_else(|_| "[]".to_string());
        let mode_str = match mode {
            ElevationMode::ReadOnly => "readonly",
            ElevationMode::WriteOnly => "write",
            ElevationMode::ReadWrite => "readwrite",
        };
        let created_at = chrono::Utc::now().to_rfc3339();

        let content = serde_json::json!({
            "agent": agent_id,
            "zones": zones_vec,
            "mode": mode_str,
            "reason": reason,
            "time": created_at,
        }).to_string();

        let mut lbls = labels! {
            "type" => "elevation-request",
            "elevation-agent" => agent_id,
            "elevation-zones" => &zones_str,
            "elevation-mode" => &mode_str,
            "elevation-reason" => reason,
            "elevation-time" => &created_at,
        };
        if let Some(dur) = duration {
            let _ = baize_core::scope::parse_duration(dur)
                .ok_or_else(|| Error::Validation(
                    format!("invalid duration '{}', expected: <number>m or <number>h", dur)
                ))?;
            lbls.insert("elevation-duration".to_string(), dur.to_string());
        }

        let blob = self.storage.blob_write(&content, &lbls)?;

        self.audit("elevation_request", agent_id, "pending", Some(&blob.hash))?;

        Ok(blob.hash)
    }

    fn elevation_approve(&mut self, request_hash: &str, approver: &str) -> Result<(), Error> {
        let blob = self.storage.blob_read(request_hash)?;

        // 检查是否已审批
        if blob.labels.contains_key("elevation-approved") {
            return Err(Error::Conflict("request already approved".into()));
        }

        // 检查是否已归还/撤销
        if let Some(status) = blob.labels.get("elevation-status") {
            if status == "Returned" || status == "Revoked" {
                return Err(Error::Conflict(
                    format!("request is {}, cannot approve", status)
                ));
            }
        }

        // 审批路由
        let request_agent_id = blob.labels.get("elevation-agent")
            .cloned()
            .unwrap_or_default();
        let request_zones_str = blob.labels.get("elevation-zones")
            .cloned()
            .unwrap_or_else(|| "[]".to_string());
        let request_zones: std::collections::HashSet<String> =
            serde_json::from_str(&request_zones_str).unwrap_or_default();
        self.validate_approver(approver, &request_agent_id, &request_zones)?;

        // 追加审批标记
        self.storage.label_add(request_hash, "elevation-approved", "true")?;
        self.storage.label_add(request_hash, "elevation-approver", approver)?;

        // 若有 duration，计算过期时间
        if let Some(dur_str) = blob.labels.get("elevation-duration") {
            let dur = baize_core::scope::parse_duration(dur_str)
                .ok_or_else(|| Error::Internal(anyhow::anyhow!("stored duration invalid")))?;
            let expires_at = chrono::Utc::now() + dur;
            self.storage.label_add(request_hash, "elevation-expires", &expires_at.to_rfc3339())?;
        }

        self.audit("elevation_approve", approver, "success", Some(request_hash))?;

        Ok(())
    }

    fn elevation_return(
        &mut self,
        request_hash: &str,
        agent_id: &str,
        caller: &str,
    ) -> Result<(), Error> {
        // caller 必须是 agent 本人或 root
        if caller != agent_id && caller != ROOT_AGENT_ID {
            return Err(Error::PermissionDenied(
                format!("only {} or baize-root can return this elevation", agent_id)
            ));
        }

        let blob = self.storage.blob_read(request_hash)?;

        // 验证是借权请求
        if blob.labels.get("type") != Some(&"elevation-request".to_string()) {
            return Err(Error::Validation("not an elevation request".into()));
        }

        // 验证 agent 匹配
        if blob.labels.get("elevation-agent") != Some(&agent_id.to_string()) {
            return Err(Error::Validation("elevation agent mismatch".into()));
        }

        // 必须已审批
        if !blob.labels.contains_key("elevation-approved") {
            return Err(Error::Validation("elevation is not approved, cannot return".into()));
        }

        // 不能重复归还或撤销
        if let Some(status) = blob.labels.get("elevation-status") {
            match status.as_str() {
                "Returned" => return Err(Error::Validation("elevation already returned".into())),
                "Revoked" => return Err(Error::Validation("elevation is revoked, cannot return".into())),
                _ => {}
            }
        }

        // 获取 agent 当前 scope → 清理 workspace
        let (identity, _) = self.agents.get(agent_id)
            .ok_or_else(|| Error::NotFound(format!("agent {}", agent_id)))?;
        let agent_scope = Scope::new(
            Level(identity.level),
            identity.zones.iter().map(|s| s.as_str()),
        )?;

        let cleaned = self.workspace_mgr.clean(agent_id, &agent_scope)?;

        // 标记为 Returned
        self.storage.label_add(request_hash, "elevation-status", "Returned")?;

        self.audit("elevation_return", agent_id, &format!("success(cleaned {})", cleaned), Some(request_hash))?;

        Ok(())
    }

    fn elevation_list(&self) -> Result<Vec<ElevationRequest>, Error> {
        let mut filter = HashMap::new();
        filter.insert("type".to_string(), "elevation-request".to_string());
        let blobs = self.storage.blob_query(&filter)?;

        let mut requests = Vec::new();
        for blob in blobs {
            let zones: std::collections::HashSet<String> = blob.labels.get("elevation-zones")
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_default();

            let mode = blob.labels.get("elevation-mode")
                .and_then(|s| ElevationMode::from_str_lower(s))
                .unwrap_or(ElevationMode::ReadOnly);

            let mut status = if blob.labels.contains_key("elevation-approved") {
                ElevationStatus::Approved
            } else {
                ElevationStatus::Pending
            };

            // Lazy expiry
            if status == ElevationStatus::Approved {
                if let Some(expires_str) = blob.labels.get("elevation-expires") {
                    if let Ok(expires) = expires_str.parse::<chrono::DateTime<chrono::Utc>>() {
                        if chrono::Utc::now() > expires {
                            status = ElevationStatus::Expired;
                        }
                    }
                }
            }

            // 显式状态覆盖
            if let Some(explicit_status) = blob.labels.get("elevation-status") {
                match explicit_status.as_str() {
                    "Returned" => status = ElevationStatus::Returned,
                    "Revoked" => status = ElevationStatus::Revoked,
                    _ => {}
                }
            }

            requests.push(ElevationRequest {
                id: blob.hash.clone(),
                agent_id: blob.labels.get("elevation-agent")
                    .cloned()
                    .unwrap_or_default(),
                requested_zones: zones,
                mode,
                reason: blob.labels.get("elevation-reason")
                    .cloned()
                    .unwrap_or_default(),
                status,
                created_at: blob.labels.get("elevation-time")
                    .cloned()
                    .unwrap_or_default(),
                expires_at: blob.labels.get("elevation-expires").cloned(),
            });
        }

        Ok(requests)
    }
}
