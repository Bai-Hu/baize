//! 传导式审批引擎 — 门控、传导链、replay 逻辑
//!
//! Phase 4.2：实现 ApprovalManager trait for Baize。
//! 审批请求沿 agent 树向上传导（hop-by-hop），每一跳可 AutoPassed/Approved/Rejected/Escalated。

use std::sync::atomic::{AtomicU64, Ordering};

use baize_core::approval::{
    ApprovalAction, ApprovalHop, ApprovalRequest, ApprovalStatus, HopDecision,
    PendingOperation, PreAuthorization,
};
use baize_core::error::Error;
use baize_core::ROOT_AGENT_ID;

use super::ApprovalManager;
use crate::pipeline::Baize;
use crate::pipeline::auditor::Auditor;
use crate::pipeline::approval::policy::RuleBasedPolicy;

// ─── ID 生成 ───

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);
static PREAUTH_COUNTER: AtomicU64 = AtomicU64::new(0);

fn next_request_id() -> String {
    let n = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("apr-{}", n)
}

fn next_preauth_id() -> String {
    let n = PREAUTH_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("pre-{}", n)
}

// ─── Baize 辅助方法 ───

impl Baize {
    /// 沿 parent 链传播审批请求，auto 级别自动通过，非 auto 级别停止
    ///
    /// 返回 true 表示全链自动通过（请求自动批准），false 表示停在某个 manual 级别
    fn propagate_chain(
        &self,
        req: &mut ApprovalRequest,
    ) -> bool {
        let start_agent_id = match req.pending_at.as_ref() {
            Some(id) => id.clone(),
            None => return true, // 无 parent → 自动批准
        };

        let mut current_id = start_agent_id;
        loop {
            let identity = match self.identity.get_identity(&current_id) {
                Some(id) => id,
                None => {
                    // 链断裂：parent_id 指向不存在的 agent
                    // 标记请求为 Rejected，避免永久挂起
                    req.status = ApprovalStatus::Rejected;
                    req.pending_at = None;
                    req.chain.push(ApprovalHop {
                        agent_id: current_id.clone(),
                        level: 0,
                        decision: HopDecision::Rejected,
                        note: "chain broken: agent not found".into(),
                        decided_at: chrono::Utc::now().to_rfc3339(),
                    });
                    return false;
                }
            };

            let is_auto = self.approval_policy.is_auto(
                &req.action,
                req.requester_level,
                identity.level,
            );

            if is_auto {
                req.chain.push(ApprovalHop {
                    agent_id: current_id.clone(),
                    level: identity.level,
                    decision: HopDecision::AutoPassed,
                    note: String::new(),
                    decided_at: chrono::Utc::now().to_rfc3339(),
                });

                // 继续上传
                match identity.parent_id {
                    Some(parent) => current_id = parent,
                    None => {
                        // 已到 root，全链 auto → 自动批准
                        req.pending_at = None;
                        return true;
                    }
                }
            } else {
                // 非 auto → 停在当前级
                req.pending_at = Some(current_id);
                return false;
            }
        }
    }

    /// 验证 approver 是否有权处理请求（pending_at == approver 或 root）
    fn validate_approval_approver(
        &self,
        approver_id: &str,
        req: &ApprovalRequest,
    ) -> Result<(), Error> {
        if approver_id == ROOT_AGENT_ID {
            return Ok(());
        }
        match req.pending_at.as_ref() {
            Some(pending) if pending == approver_id => Ok(()),
            Some(pending) => Err(Error::PermissionDenied(format!(
                "request {} is pending at '{}', not '{}'",
                req.id, pending, approver_id
            ))),
            None => Err(Error::Validation(format!(
                "request {} is not pending at any agent",
                req.id
            ))),
        }
    }

    /// 从规则中获取 max_grant_count（取最高 level 的配置，若无则默认 1）
    fn max_grant_from_rule(rule: &Option<baize_core::approval::ApprovalRule>) -> u32 {
        rule.as_ref()
            .and_then(|r| {
                r.levels.iter().map(|lc| lc.max_grant_count).max()
            })
            .unwrap_or(1)
    }

    /// 审批通过后 replay 冻结的操作
    ///
    /// 从 ApprovalRequest 中反序列化 PendingOperation，分派到对应的 execute_* 方法执行。
    /// 执行成功后消耗一次使用权。
    pub(crate) fn replay_operation(&self, req: &ApprovalRequest) -> Result<(), Error> {
        let op: PendingOperation = serde_json::from_str(&req.operation_payload)
            .map_err(|e| Error::Internal(anyhow::anyhow!("deserialize pending operation: {}", e)))?;
        match op {
            PendingOperation::Push { agent_id, message, ref_name } => {
                self.execute_push(&agent_id, &message, ref_name.as_deref())?;
            }
            PendingOperation::FileWrite { agent_id, path, content, labels } => {
                self.execute_file_write(&agent_id, &path, &content, labels.as_ref())?;
            }
            PendingOperation::FileDelete { agent_id, path } => {
                self.execute_file_delete(&agent_id, &path)?;
            }
            PendingOperation::BlobWrite { agent_id, content, labels } => {
                self.execute_blob_write(&agent_id, &content, &labels)?;
            }
            // ASL / session / key rotation 等操作暂不支持 replay
            other => {
                return Err(Error::Validation(format!(
                    "replay not supported for operation: {:?}", other
                )));
            }
        }
        self.approval_consume(&req.id)?;
        Ok(())
    }
}

// ─── ApprovalManager 实现 ───

impl ApprovalManager for Baize {
    fn check_approval_gate(
        &self,
        agent_id: &str,
        action: &ApprovalAction,
        operation: &PendingOperation,
    ) -> Result<(), Error> {
        // 1. 验证 agent 存在
        let identity = self.identity.get_identity(agent_id)
            .ok_or_else(|| Error::NeedUserDecision(format!(
                "agent '{}' not found, cannot check approval gate", agent_id
            )))?;

        // 2. 查找预授权
        if let Some(pa) = self.approval_store.find_preauth(agent_id, action)? {
            if pa.remaining_count > 0 {
                self.approval_store.decrement_preauth(&pa.id)?;
                self.audit("approval_preauth_consumed", agent_id, "ok", Some(&pa.id))?;
                return Ok(());
            }
        }

        // 3. 查找活跃已批准请求（精准过滤，避免全量扫描）
        if let Some(active_req) = self.approval_store.find_active_for(agent_id, action)? {
            self.approval_store.decrement_remaining(&active_req.id)?;
            self.audit("approval_consumed", agent_id, "ok", Some(&active_req.id))?;
            return Ok(());
        }

        // 4. 查找策略规则 → None → 自动通过
        let rule = self.approval_policy.get_rule(action, identity.level);
        if rule.is_none() {
            return Ok(());
        }

        // 5. 创建审批请求
        let now = chrono::Utc::now().to_rfc3339();
        let operation_payload = serde_json::to_string(operation)
            .map_err(|e| Error::Internal(anyhow::anyhow!("serialize pending operation: {}", e)))?;

        let expires_at = self.approval_policy.timeout(action)
            .map(|secs| {
                let expires = chrono::Utc::now() + chrono::Duration::seconds(secs as i64);
                expires.to_rfc3339()
            });

        let mut req = ApprovalRequest {
            id: next_request_id(),
            requester_id: agent_id.to_string(),
            requester_level: identity.level,
            action: action.clone(),
            operation_payload,
            chain: vec![],
            status: ApprovalStatus::Pending,
            pending_at: identity.parent_id.clone(),
            granted_count: 0,
            remaining_count: 0,
            created_at: now,
            expires_at,
        };

        // 6. 传导链传播
        let all_auto = self.propagate_chain(&mut req);

        // 链断裂：propagate_chain 已标记 Rejected
        if req.status == ApprovalStatus::Rejected {
            self.approval_store.create_request(&req)?;
            self.audit("approval_chain_broken", agent_id, "rejected", Some(&req.id))?;
            return Err(Error::Validation(format!(
                "approval chain broken: agent in chain not found (request {})", req.id
            )));
        }

        if all_auto {
            // 全链 auto → 自动批准
            let grant = Self::max_grant_from_rule(&rule);
            req.status = ApprovalStatus::Approved;
            req.granted_count = grant;
            req.remaining_count = grant;
            req.pending_at = None;
        }

        // 7. 存储请求
        self.approval_store.create_request(&req)?;

        if all_auto {
            // 自动批准 → 操作可直接执行
            self.audit("approval_auto_approved", agent_id, "ok", Some(&req.id))?;
            return Ok(());
        }

        // 8. 需要人工审批
        self.audit("approval_pending", agent_id, "pending", Some(&req.id))?;
        Err(Error::ApprovalPending(req.id))
    }

    fn approval_approve(
        &self,
        request_id: &str,
        approver_id: &str,
        granted_count: u32,
        note: Option<&str>,
    ) -> Result<ApprovalStatus, Error> {
        let mut req = self.approval_store.get_request(request_id)?
            .ok_or_else(|| Error::NotFound(format!("approval request {}", request_id)))?;

        // 验证状态
        if req.status != ApprovalStatus::Pending {
            return Err(Error::Conflict(format!(
                "request {} is {}, cannot approve",
                request_id, req.status
            )));
        }

        // 验证 approver
        self.validate_approval_approver(approver_id, &req)?;

        // 添加 Approved hop
        req.chain.push(ApprovalHop {
            agent_id: approver_id.to_string(),
            level: self.identity.get_identity(approver_id)
                .map(|id| id.level)
                .unwrap_or(0),
            decision: HopDecision::Approved { granted_count },
            note: note.unwrap_or("").to_string(),
            decided_at: chrono::Utc::now().to_rfc3339(),
        });

        req.status = ApprovalStatus::Approved;
        req.granted_count = granted_count;
        req.remaining_count = granted_count;
        req.pending_at = None;

        self.approval_store.update_request(&req)?;

        // 审批通过后自动 replay 冻结的操作
        // replay 失败不阻塞审批（审批记录的是授权决策，执行可能因环境变化而失败）
        match self.replay_operation(&req) {
            Ok(()) => {
                self.audit("approval_replay", approver_id, "replay_success", Some(request_id))?;
            }
            Err(ref e) => {
                self.audit("approval_replay_failed", approver_id, &format!("error: {}", e), Some(request_id))?;
            }
        }

        self.audit("approval_approve", approver_id, "approved", Some(request_id))?;

        Ok(req.status)
    }

    fn approval_reject(
        &self,
        request_id: &str,
        approver_id: &str,
        reason: Option<&str>,
    ) -> Result<ApprovalStatus, Error> {
        let mut req = self.approval_store.get_request(request_id)?
            .ok_or_else(|| Error::NotFound(format!("approval request {}", request_id)))?;

        if req.status != ApprovalStatus::Pending {
            return Err(Error::Conflict(format!(
                "request {} is {}, cannot reject",
                request_id, req.status
            )));
        }

        self.validate_approval_approver(approver_id, &req)?;

        req.chain.push(ApprovalHop {
            agent_id: approver_id.to_string(),
            level: self.identity.get_identity(approver_id)
                .map(|id| id.level)
                .unwrap_or(0),
            decision: HopDecision::Rejected,
            note: reason.unwrap_or("").to_string(),
            decided_at: chrono::Utc::now().to_rfc3339(),
        });

        req.status = ApprovalStatus::Rejected;
        req.pending_at = None;

        self.approval_store.update_request(&req)?;
        self.audit("approval_reject", approver_id, "rejected", Some(request_id))?;

        Ok(req.status)
    }

    fn approval_escalate(
        &self,
        request_id: &str,
        approver_id: &str,
        reason: Option<&str>,
    ) -> Result<ApprovalStatus, Error> {
        let mut req = self.approval_store.get_request(request_id)?
            .ok_or_else(|| Error::NotFound(format!("approval request {}", request_id)))?;

        if req.status != ApprovalStatus::Pending {
            return Err(Error::Conflict(format!(
                "request {} is {}, cannot escalate",
                request_id, req.status
            )));
        }

        self.validate_approval_approver(approver_id, &req)?;

        // 获取 approver 的 parent
        let approver_identity = self.identity.get_identity(approver_id)
            .ok_or_else(|| Error::NotFound(format!("approver agent {}", approver_id)))?;

        let parent_id = approver_identity.parent_id.as_ref()
            .ok_or_else(|| Error::Validation(
                "cannot escalate beyond root (no parent)".into()
            ))?;

        // 添加 Escalated hop
        req.chain.push(ApprovalHop {
            agent_id: approver_id.to_string(),
            level: approver_identity.level,
            decision: HopDecision::Escalated,
            note: reason.unwrap_or("").to_string(),
            decided_at: chrono::Utc::now().to_rfc3339(),
        });

        // 移动 pending_at 到 approver 的 parent
        req.pending_at = Some(parent_id.clone());

        // 从新位置继续传导
        let rule = self.approval_policy.get_rule(&req.action, req.requester_level);
        let all_auto = self.propagate_chain(&mut req);

        // 链断裂检测
        if req.status == ApprovalStatus::Rejected {
            self.approval_store.update_request(&req)?;
            self.audit("approval_chain_broken", approver_id, "rejected", Some(request_id))?;
            return Ok(req.status);
        }

        if all_auto {
            let grant = Self::max_grant_from_rule(&rule);
            req.status = ApprovalStatus::Approved;
            req.granted_count = grant;
            req.remaining_count = grant;
            req.pending_at = None;
        }

        self.approval_store.update_request(&req)?;
        self.audit("approval_escalate", approver_id, "escalated", Some(request_id))?;

        Ok(req.status)
    }

    fn approval_pending(&self, agent_id: &str) -> Result<Vec<ApprovalRequest>, Error> {
        self.approval_store.list_pending_for(agent_id)
    }

    fn approval_show(&self, request_id: &str, caller_id: &str) -> Result<ApprovalRequest, Error> {
        let req = self.approval_store.get_request(request_id)?
            .ok_or_else(|| Error::NotFound(format!("approval request {}", request_id)))?;

        // 访问控制：root、请求者、当前待审批人可查看
        let is_root = caller_id == ROOT_AGENT_ID;
        let is_requester = req.requester_id == caller_id;
        let is_pending_at = req.pending_at.as_deref() == Some(caller_id);
        // 传导链中参与过的 agent 也可查看
        let is_in_chain = req.chain.iter().any(|hop| hop.agent_id == caller_id);

        if !is_root && !is_requester && !is_pending_at && !is_in_chain {
            return Err(Error::PermissionDenied(format!(
                "agent '{}' is not authorized to view request '{}'",
                caller_id, request_id
            )));
        }

        Ok(req)
    }

    fn approval_consume(&self, request_id: &str) -> Result<u32, Error> {
        let req = self.approval_store.get_request(request_id)?
            .ok_or_else(|| Error::NotFound(format!("approval request {}", request_id)))?;

        if req.status != ApprovalStatus::Approved {
            return Err(Error::Validation(format!(
                "request {} is {}, cannot consume (must be Approved)",
                request_id, req.status
            )));
        }

        let remaining = self.approval_store.decrement_remaining(request_id)?;
        Ok(remaining)
    }

    fn approval_preauth(
        &self,
        granter_id: &str,
        grantee_id: &str,
        action: &ApprovalAction,
        count: u32,
    ) -> Result<PreAuthorization, Error> {
        let granter = self.identity.get_identity(granter_id)
            .ok_or_else(|| Error::NotFound(format!("granter agent {}", granter_id)))?;
        let grantee = self.identity.get_identity(grantee_id)
            .ok_or_else(|| Error::NotFound(format!("grantee agent {}", grantee_id)))?;

        // 验证 granter 权限：root 或 level > grantee level
        if granter_id != ROOT_AGENT_ID && granter.level <= grantee.level {
            return Err(Error::PermissionDenied(format!(
                "granter '{}' (level {}) must have higher level than grantee '{}' (level {})",
                granter_id, granter.level, grantee_id, grantee.level
            )));
        }

        let preauth = PreAuthorization {
            id: next_preauth_id(),
            granter_id: granter_id.to_string(),
            grantee_id: grantee_id.to_string(),
            action: action.clone(),
            granted_count: count,
            remaining_count: count,
            created_at: chrono::Utc::now().to_rfc3339(),
        };

        self.approval_store.create_preauth(&preauth)?;
        self.audit("approval_preauth_created", granter_id, "ok", Some(&preauth.id))?;

        Ok(preauth)
    }

    fn approval_list_preauth(&self, agent_id: &str) -> Result<Vec<PreAuthorization>, Error> {
        self.approval_store.list_preauth_for(agent_id)
    }

    fn approval_delete_preauth(&self, preauth_id: &str, caller_id: &str) -> Result<(), Error> {
        // 验证调用者权限：root 或授权者可删除
        if caller_id != ROOT_AGENT_ID {
            let preauths = self.approval_store.list_preauth_for(caller_id)?;
            let owns = preauths.iter().any(|pa| pa.id == preauth_id);
            if !owns {
                return Err(Error::PermissionDenied(format!(
                    "only root or the granter can delete pre-authorization '{}'",
                    preauth_id
                )));
            }
        }
        self.approval_store.delete_preauth(preauth_id)?;
        self.audit("approval_preauth_deleted", caller_id, "ok", Some(preauth_id))?;
        Ok(())
    }

    fn approval_policy_get(&self) -> Vec<baize_core::approval::ApprovalRule> {
        self.approval_policy.as_any()
            .downcast_ref::<RuleBasedPolicy>()
            .map(|p| p.rules_snapshot())
            .unwrap_or_default()
    }

    fn approval_policy_update(&self, rules: Vec<baize_core::approval::ApprovalRule>) -> Result<(), Error> {
        self.approval_policy.as_any()
            .downcast_ref::<RuleBasedPolicy>()
            .ok_or_else(|| Error::Validation("cannot update auto-approve policy".into()))
            .map(|p| p.set_rules(rules))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::collections::HashMap;

    use super::*;
    use baize_core::approval::{ApprovalLevelConfig, ApprovalRule};
    use baize_core::scope::Level;
    use crate::pipeline::agent_manager::AgentRegistry;
    use crate::pipeline::approval::policy::RuleBasedPolicy;
    use crate::pipeline::ApprovalManager;
    use crate::pipeline::FileSync;
    use crate::pipeline::DataOps;

    /// 辅助：创建 3 级 agent 树 root → parent(L3) → child(L2)
    fn setup_tree() -> Baize {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("baize-root", "parent", Level(3), vec!["A", "B", "C"], None).unwrap();
        baize.agent_register("baize-root", "child", Level(2), vec!["A"], Some("parent")).unwrap();
        baize
    }

    /// 辅助：创建带 RuleBasedPolicy 的 3 级 agent 树
    fn setup_tree_with_rules(rules: Vec<ApprovalRule>) -> Baize {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("baize-root", "parent", Level(3), vec!["A", "B", "C"], None).unwrap();
        baize.agent_register("baize-root", "child", Level(2), vec!["A"], Some("parent")).unwrap();
        baize.approval_policy = Arc::new(RuleBasedPolicy::new(rules));
        baize
    }

    /// 标准规则：Push 需要 L3 手动审批
    fn push_rule(auto: bool) -> Vec<ApprovalRule> {
        vec![ApprovalRule {
            action: ApprovalAction::Push,
            level_range: (0, 2),
            levels: vec![
                ApprovalLevelConfig { level: 3, auto, max_grant_count: 5 },
                ApprovalLevelConfig { level: 4, auto, max_grant_count: 5 }, // root
            ],
            timeout_secs: None,
        }]
    }

    fn sample_push_op(agent_id: &str) -> PendingOperation {
        PendingOperation::Push {
            agent_id: agent_id.to_string(),
            message: "deploy v2".to_string(),
            ref_name: Some("main".to_string()),
        }
    }

    // ─── check_approval_gate ───

    #[test]
    fn test_gate_auto_approve_no_rule() {
        let baize = setup_tree();
        // AutoApprovePolicy: 无规则 → 所有操作自动通过
        let op = sample_push_op("child");
        let result = baize.check_approval_gate("child", &ApprovalAction::Push, &op);
        assert!(result.is_ok(), "no rule should auto-approve, got {:?}", result);
    }

    #[test]
    fn test_gate_preauth_hit() {
        let baize = setup_tree();
        // root 给 child 预授权 2 次 Push
        baize.approval_preauth("baize-root", "child", &ApprovalAction::Push, 2).unwrap();

        let op = sample_push_op("child");
        // 第 1 次应通过（预授权消耗）
        assert!(baize.check_approval_gate("child", &ApprovalAction::Push, &op).is_ok());
        // 第 2 次也应通过
        assert!(baize.check_approval_gate("child", &ApprovalAction::Push, &op).is_ok());
    }

    #[test]
    fn test_gate_preauth_exhausted() {
        let baize = setup_tree_with_rules(push_rule(false));
        // root 给 child 1 次预授权
        baize.approval_preauth("baize-root", "child", &ApprovalAction::Push, 1).unwrap();

        let op = sample_push_op("child");
        // 第 1 次通过（预授权）
        assert!(baize.check_approval_gate("child", &ApprovalAction::Push, &op).is_ok());
        // 第 2 次应被拦截（预授权耗尽，需要审批）
        let result = baize.check_approval_gate("child", &ApprovalAction::Push, &op);
        assert!(matches!(result, Err(Error::ApprovalPending(_))));
    }

    #[test]
    fn test_chain_auto_pass_all() {
        // 全 auto → 自动批准
        let baize = setup_tree_with_rules(push_rule(true));
        let op = sample_push_op("child");
        // child → parent(L3 auto=true) → root → 全 auto → 通过
        let result = baize.check_approval_gate("child", &ApprovalAction::Push, &op);
        assert!(result.is_ok(), "all auto should pass, got {:?}", result);
    }

    #[test]
    fn test_chain_stops_at_manual_level() {
        let baize = setup_tree_with_rules(push_rule(false));
        let op = sample_push_op("child");
        let result = baize.check_approval_gate("child", &ApprovalAction::Push, &op);
        assert!(matches!(result, Err(Error::ApprovalPending(_))));

        // 请求应停在 parent
        let pending = baize.approval_pending("parent").unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].pending_at.as_deref(), Some("parent"));
    }

    // ─── approve / reject / escalate ───

    #[test]
    fn test_approve_at_manual_level() {
        let baize = setup_tree_with_rules(push_rule(false));
        let op = sample_push_op("child");
        let err = baize.check_approval_gate("child", &ApprovalAction::Push, &op).unwrap_err();
        let req_id = match err {
            Error::ApprovalPending(id) => id,
            other => panic!("expected ApprovalPending, got {:?}", other),
        };

        // parent 审批通过
        let status = baize.approval_approve(&req_id, "parent", 3, Some("ok")).unwrap();
        assert_eq!(status, ApprovalStatus::Approved);

        let req = baize.approval_show(&req_id, "parent").unwrap();
        assert_eq!(req.granted_count, 3);
        assert_eq!(req.remaining_count, 3);
        assert!(req.pending_at.is_none());
    }

    #[test]
    fn test_reject_stops_chain() {
        let baize = setup_tree_with_rules(push_rule(false));
        let op = sample_push_op("child");
        let err = baize.check_approval_gate("child", &ApprovalAction::Push, &op).unwrap_err();
        let req_id = match err {
            Error::ApprovalPending(id) => id,
            other => panic!("expected ApprovalPending, got {:?}", other),
        };

        let status = baize.approval_reject(&req_id, "parent", Some("not allowed")).unwrap();
        assert_eq!(status, ApprovalStatus::Rejected);

        let req = baize.approval_show(&req_id, "parent").unwrap();
        assert_eq!(req.status, ApprovalStatus::Rejected);
        assert!(req.pending_at.is_none());
    }

    #[test]
    fn test_escalate_to_root() {
        let baize = setup_tree_with_rules(push_rule(false));
        let op = sample_push_op("child");
        let err = baize.check_approval_gate("child", &ApprovalAction::Push, &op).unwrap_err();
        let req_id = match err {
            Error::ApprovalPending(id) => id,
            other => panic!("expected ApprovalPending, got {:?}", other),
        };

        // parent 越权到 root
        let status = baize.approval_escalate(&req_id, "parent", Some("above my pay grade")).unwrap();
        assert_eq!(status, ApprovalStatus::Pending);

        let req = baize.approval_show(&req_id, "baize-root").unwrap();
        assert_eq!(req.pending_at.as_deref(), Some("baize-root"));

        // root 审批
        let status = baize.approval_approve(&req_id, "baize-root", 1, None).unwrap();
        assert_eq!(status, ApprovalStatus::Approved);
    }

    #[test]
    fn test_escalate_at_root_fails() {
        let baize = setup_tree_with_rules(vec![ApprovalRule {
            action: ApprovalAction::Push,
            level_range: (0, 4),
            levels: vec![
                ApprovalLevelConfig { level: 3, auto: true, max_grant_count: 5 },
                ApprovalLevelConfig { level: 4, auto: false, max_grant_count: 5 },
            ],
            timeout_secs: None,
        }]);
        let op = sample_push_op("child");
        let err = baize.check_approval_gate("child", &ApprovalAction::Push, &op).unwrap_err();
        let req_id = match err {
            Error::ApprovalPending(id) => id,
            other => panic!("expected ApprovalPending, got {:?}", other),
        };

        // root 不能再越权
        let result = baize.approval_escalate(&req_id, "baize-root", Some("can't go higher"));
        assert!(result.is_err());
    }

    // ─── consume ───

    #[test]
    fn test_consume_decrement() {
        let baize = setup_tree_with_rules(push_rule(false));
        let op = sample_push_op("child");
        let err = baize.check_approval_gate("child", &ApprovalAction::Push, &op).unwrap_err();
        let req_id = match err {
            Error::ApprovalPending(id) => id,
            other => panic!("expected ApprovalPending, got {:?}", other),
        };

        baize.approval_approve(&req_id, "parent", 3, None).unwrap();

        // 消耗 3 次
        assert_eq!(baize.approval_consume(&req_id).unwrap(), 2);
        assert_eq!(baize.approval_consume(&req_id).unwrap(), 1);
        assert_eq!(baize.approval_consume(&req_id).unwrap(), 0);

        // 耗尽后标记 Executed
        let req = baize.approval_show(&req_id, "parent").unwrap();
        assert_eq!(req.status, ApprovalStatus::Executed);

        // 再消耗应报错
        let result = baize.approval_consume(&req_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_consume_not_approved_fails() {
        let baize = setup_tree_with_rules(push_rule(false));
        let op = sample_push_op("child");
        let err = baize.check_approval_gate("child", &ApprovalAction::Push, &op).unwrap_err();
        let req_id = match err {
            Error::ApprovalPending(id) => id,
            other => panic!("expected ApprovalPending, got {:?}", other),
        };

        // 未审批就消耗应报错
        let result = baize.approval_consume(&req_id);
        assert!(result.is_err());
    }

    // ─── pending 列表 ───

    #[test]
    fn test_pending_lists_correctly() {
        let baize = setup_tree_with_rules(push_rule(false));
        let op = sample_push_op("child");
        baize.check_approval_gate("child", &ApprovalAction::Push, &op).unwrap_err();

        // parent 应看到 1 个 pending
        let pending_parent = baize.approval_pending("parent").unwrap();
        assert_eq!(pending_parent.len(), 1);

        // child 不应看到（pending 在 parent，不在 child）
        let pending_child = baize.approval_pending("child").unwrap();
        assert_eq!(pending_child.len(), 0);
    }

    // ─── preauth ───

    #[test]
    fn test_preauth_create_and_use() {
        let baize = setup_tree();

        let pa = baize.approval_preauth("baize-root", "child", &ApprovalAction::Push, 3).unwrap();
        assert_eq!(pa.remaining_count, 3);
        assert_eq!(pa.granter_id, "baize-root");
        assert_eq!(pa.grantee_id, "child");

        // 列出预授权
        let list = baize.approval_list_preauth("child").unwrap();
        assert_eq!(list.len(), 1);

        // 使用预授权（即使有规则也通过）
        let baize = setup_tree_with_rules(push_rule(false));
        baize.approval_preauth("baize-root", "child", &ApprovalAction::Push, 3).unwrap();

        let op = sample_push_op("child");
        assert!(baize.check_approval_gate("child", &ApprovalAction::Push, &op).is_ok());
        assert!(baize.check_approval_gate("child", &ApprovalAction::Push, &op).is_ok());
        assert!(baize.check_approval_gate("child", &ApprovalAction::Push, &op).is_ok());
    }

    #[test]
    fn test_preauth_level_validation() {
        let baize = setup_tree();
        // child(L2) 不能给 parent(L3) 授权
        let result = baize.approval_preauth("child", "parent", &ApprovalAction::Push, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_preauth_delete() {
        let baize = setup_tree();
        let pa = baize.approval_preauth("baize-root", "child", &ApprovalAction::Push, 1).unwrap();
        baize.approval_delete_preauth(&pa.id, "baize-root").unwrap();
        let list = baize.approval_list_preauth("child").unwrap();
        assert!(list.is_empty());
    }

    // ─── policy ───

    #[test]
    fn test_policy_get_update() {
        let baize = setup_tree();

        // 初始应为空规则（RuleBasedPolicy::new(vec![])）
        let rules = baize.approval_policy_get();
        assert!(rules.is_empty());

        // 默认 RuleBasedPolicy（空规则）可以 update
        baize.approval_policy_update(push_rule(false)).unwrap();
        let rules = baize.approval_policy_get();
        assert_eq!(rules.len(), 1);

        // 用 RuleBasedPolicy 才能 update
        let baize = setup_tree_with_rules(push_rule(false));
        let rules = baize.approval_policy_get();
        assert_eq!(rules.len(), 1);

        baize.approval_policy_update(push_rule(true)).unwrap();
        let rules = baize.approval_policy_get();
        assert_eq!(rules.len(), 1);
        assert!(rules[0].levels[0].auto);
    }

    #[test]
    fn test_wrong_approver_fails() {
        let baize = setup_tree_with_rules(push_rule(false));
        let op = sample_push_op("child");
        let err = baize.check_approval_gate("child", &ApprovalAction::Push, &op).unwrap_err();
        let req_id = match err {
            Error::ApprovalPending(id) => id,
            other => panic!("expected ApprovalPending, got {:?}", other),
        };

        // child 不是 approver（pending 在 parent）
        let result = baize.approval_approve(&req_id, "child", 1, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_root_can_approve_any() {
        let baize = setup_tree_with_rules(push_rule(false));
        let op = sample_push_op("child");
        let err = baize.check_approval_gate("child", &ApprovalAction::Push, &op).unwrap_err();
        let req_id = match err {
            Error::ApprovalPending(id) => id,
            other => panic!("expected ApprovalPending, got {:?}", other),
        };

        // root 可直接审批（即使 pending 在 parent）
        let status = baize.approval_approve(&req_id, "baize-root", 1, None).unwrap();
        assert_eq!(status, ApprovalStatus::Approved);
    }

    // ─── Phase 4.3: gate + execute 集成测试 ───

    #[test]
    fn test_pipe_push_blocked_by_approval() {
        let baize = setup_tree_with_rules(push_rule(false));

        // child 先写一个文件到 workspace
        baize.pipe_file_write("child", "A/data.txt", b"hello", None).unwrap();

        // pipe_push 应被拦截
        let result = baize.pipe_push("child", "deploy v2", None);
        assert!(matches!(result, Err(Error::ApprovalPending(_))),
            "push should be blocked, got {:?}", result);
    }

    #[test]
    fn test_pipe_push_auto_passes() {
        let baize = setup_tree();

        baize.pipe_file_write("child", "A/data.txt", b"hello", None).unwrap();
        let result = baize.pipe_push("child", "deploy v2", None);
        assert!(result.is_ok(), "push should succeed with auto policy, got {:?}", result);
        assert_eq!(result.unwrap().files, 1);
    }

    #[test]
    fn test_replay_push_after_approval() {
        let baize = setup_tree_with_rules(push_rule(false));

        // child 写文件 → push 被拦截
        baize.pipe_file_write("child", "A/deploy.txt", b"deploy content", None).unwrap();
        let err = baize.pipe_push("child", "deploy", None).unwrap_err();
        let req_id = match err {
            Error::ApprovalPending(id) => id,
            other => panic!("expected ApprovalPending, got {:?}", other),
        };

        // 审批前，主仓库没有文件
        assert!(!baize.main_repo.join("A/deploy.txt").exists());

        // parent 审批通过 → 自动 replay
        baize.approval_approve(&req_id, "parent", 1, None).unwrap();

        // replay 后，主仓库应有文件
        let main_file = baize.main_repo.join("A/deploy.txt");
        assert!(main_file.exists(), "file should exist in main repo after replay");
        assert_eq!(std::fs::read(&main_file).unwrap(), b"deploy content");
    }

    #[test]
    fn test_replay_file_write_after_approval() {
        let rules = vec![ApprovalRule {
            action: ApprovalAction::FileWrite,
            level_range: (0, 2),
            levels: vec![
                ApprovalLevelConfig { level: 3, auto: false, max_grant_count: 5 },
            ],
            timeout_secs: None,
        }];
        let baize = setup_tree_with_rules(rules);

        // child 尝试写文件 → 被拦截
        let result = baize.pipe_file_write("child", "A/secret.txt", b"secret data", None);
        assert!(matches!(result, Err(Error::ApprovalPending(_))),
            "file_write should be blocked, got {:?}", result);

        // 获取请求 ID
        let pending = baize.approval_pending("parent").unwrap();
        assert_eq!(pending.len(), 1);
        let req_id = &pending[0].id;

        // parent 审批 → 自动 replay
        baize.approval_approve(req_id, "parent", 1, None).unwrap();

        // replay 后 workspace 应有文件
        let content = baize.pipe_file_read("child", "A/secret.txt").unwrap();
        assert_eq!(content.content, b"secret data");
    }

    #[test]
    fn test_replay_blob_write_after_approval() {
        let rules = vec![ApprovalRule {
            action: ApprovalAction::BlobWrite,
            level_range: (0, 2),
            levels: vec![
                ApprovalLevelConfig { level: 3, auto: false, max_grant_count: 5 },
            ],
            timeout_secs: None,
        }];
        let baize = setup_tree_with_rules(rules);

        // child 尝试写 blob → 被拦截
        let mut labels = HashMap::new();
        labels.insert("type".to_string(), "test".to_string());
        let result = baize.pipe_blob_write("child", "test data", &labels);
        assert!(matches!(result, Err(Error::ApprovalPending(_))),
            "blob_write should be blocked, got {:?}", result);

        // 获取请求 ID
        let pending = baize.approval_pending("parent").unwrap();
        assert_eq!(pending.len(), 1);
        let req_id = &pending[0].id;

        // parent 审批 → 自动 replay
        baize.approval_approve(req_id, "parent", 1, None).unwrap();

        // replay 后 blob 应存在
        let mut filter = HashMap::new();
        filter.insert("type".to_string(), "test".to_string());
        filter.insert("agent".to_string(), "child".to_string());
        let blobs = baize.storage.blob_query(&filter).unwrap();
        assert_eq!(blobs.len(), 1);
        assert_eq!(blobs[0].content, "test data");
    }

    #[test]
    fn test_pipe_file_delete_blocked_by_approval() {
        let rules = vec![ApprovalRule {
            action: ApprovalAction::FileDelete,
            level_range: (0, 2),
            levels: vec![
                ApprovalLevelConfig { level: 3, auto: false, max_grant_count: 5 },
            ],
            timeout_secs: None,
        }];
        let baize = setup_tree_with_rules(rules);

        // 先写一个文件
        baize.pipe_file_write("child", "A/temp.txt", b"temp", None).unwrap();

        // 删除被拦截
        let result = baize.pipe_file_delete("child", "A/temp.txt");
        assert!(matches!(result, Err(Error::ApprovalPending(_))),
            "file_delete should be blocked, got {:?}", result);
    }

    #[test]
    fn test_replay_push_fails_when_workspace_cleared() {
        let baize = setup_tree_with_rules(push_rule(false));

        // child 写文件 → push 被拦截
        baize.pipe_file_write("child", "A/gone.txt", b"will be cleared", None).unwrap();
        let err = baize.pipe_push("child", "deploy", None).unwrap_err();
        let req_id = match err {
            Error::ApprovalPending(id) => id,
            other => panic!("expected ApprovalPending, got {:?}", other),
        };

        // 审批前清空 workspace（模拟环境变化）
        baize.workspace_mgr.clear_all("child").unwrap();

        // parent 审批 → replay 应失败（workspace 为空，push 报 "workspace is empty"）
        let status = baize.approval_approve(&req_id, "parent", 1, None).unwrap();
        assert_eq!(status, ApprovalStatus::Approved, "审批应成功（replay 失败不阻塞）");

        // 主仓库不应有文件（replay 失败）
        assert!(!baize.main_repo.join("A/gone.txt").exists());

        // replay 失败应有审计记录
        let mut filter = HashMap::new();
        filter.insert("x-audit".to_string(), "true".to_string());
        filter.insert("x-audit-type".to_string(), "approval_replay_failed".to_string());
        let audits = baize.storage.blob_query(&filter).unwrap();
        assert_eq!(audits.len(), 1, "应有 replay 失败审计记录");
    }

    #[test]
    fn test_replay_file_delete_after_approval() {
        let rules = vec![ApprovalRule {
            action: ApprovalAction::FileDelete,
            level_range: (0, 2),
            levels: vec![
                ApprovalLevelConfig { level: 3, auto: false, max_grant_count: 5 },
            ],
            timeout_secs: None,
        }];
        let baize = setup_tree_with_rules(rules);

        // 先写文件
        baize.pipe_file_write("child", "A/to_delete.txt", b"delete me", None).unwrap();

        // 删除被拦截
        let result = baize.pipe_file_delete("child", "A/to_delete.txt");
        let req_id = match result {
            Err(Error::ApprovalPending(id)) => id,
            other => panic!("expected ApprovalPending, got {:?}", other),
        };

        // parent 审批 → 自动 replay 删除
        baize.approval_approve(&req_id, "parent", 1, None).unwrap();

        // 文件应已被删除
        let files = baize.pipe_file_list("child").unwrap();
        assert!(files.is_empty(), "file should be deleted after replay");
    }

    #[test]
    fn test_replay_success_audited() {
        let baize = setup_tree_with_rules(push_rule(false));

        // child 写文件 → push 被拦截 → 审批通过
        baize.pipe_file_write("child", "A/audit.txt", b"audit test", None).unwrap();
        let err = baize.pipe_push("child", "audit push", None).unwrap_err();
        let req_id = match err {
            Error::ApprovalPending(id) => id,
            other => panic!("expected ApprovalPending, got {:?}", other),
        };
        baize.approval_approve(&req_id, "parent", 1, None).unwrap();

        // 应有 replay 成功审计
        let mut filter = HashMap::new();
        filter.insert("x-audit".to_string(), "true".to_string());
        filter.insert("x-audit-type".to_string(), "approval_replay".to_string());
        let audits = baize.storage.blob_query(&filter).unwrap();
        assert_eq!(audits.len(), 1, "应有 replay 成功审计记录");
    }

    // ─── Phase 4.4: 访问控制 + 授权校验 ───

    #[test]
    fn test_show_access_control_requester() {
        let baize = setup_tree_with_rules(push_rule(false));
        let op = sample_push_op("child");
        let err = baize.check_approval_gate("child", &ApprovalAction::Push, &op).unwrap_err();
        let req_id = match err {
            Error::ApprovalPending(id) => id,
            other => panic!("expected ApprovalPending, got {:?}", other),
        };

        // 请求者 child 可以查看
        assert!(baize.approval_show(&req_id, "child").is_ok());
    }

    #[test]
    fn test_show_access_control_pending_approver() {
        let baize = setup_tree_with_rules(push_rule(false));
        let op = sample_push_op("child");
        baize.check_approval_gate("child", &ApprovalAction::Push, &op).unwrap_err();

        let pending = baize.approval_pending("parent").unwrap();
        let req_id = &pending[0].id;

        // pending_at 的 parent 可以查看
        assert!(baize.approval_show(req_id, "parent").is_ok());
    }

    #[test]
    fn test_show_access_control_root() {
        let baize = setup_tree_with_rules(push_rule(false));
        let op = sample_push_op("child");
        let err = baize.check_approval_gate("child", &ApprovalAction::Push, &op).unwrap_err();
        let req_id = match err {
            Error::ApprovalPending(id) => id,
            other => panic!("expected ApprovalPending, got {:?}", other),
        };

        // root 可以查看任何请求
        assert!(baize.approval_show(&req_id, "baize-root").is_ok());
    }

    #[test]
    fn test_show_access_control_unauthorized() {
        let mut baize = setup_tree_with_rules(push_rule(false));
        let op = sample_push_op("child");
        let err = baize.check_approval_gate("child", &ApprovalAction::Push, &op).unwrap_err();
        let req_id = match err {
            Error::ApprovalPending(id) => id,
            other => panic!("expected ApprovalPending, got {:?}", other),
        };

        // 注册一个无关 agent
        baize.agent_register("baize-root", "outsider", Level(1), vec!["X"], None).unwrap();

        // outsider 不能查看
        let result = baize.approval_show(&req_id, "outsider");
        assert!(matches!(result, Err(Error::PermissionDenied(_))));
    }

    #[test]
    fn test_preauth_delete_by_granter() {
        let baize = setup_tree();
        let pa = baize.approval_preauth("baize-root", "child", &ApprovalAction::Push, 1).unwrap();

        // root（授权者）可以删除
        assert!(baize.approval_delete_preauth(&pa.id, "baize-root").is_ok());
    }

    #[test]
    fn test_preauth_delete_by_unauthorized() {
        let mut baize = setup_tree();
        let _pa = baize.approval_preauth("baize-root", "child", &ApprovalAction::Push, 1).unwrap();

        // 注册一个无关 agent
        baize.agent_register("baize-root", "outsider", Level(1), vec!["X"], None).unwrap();

        // 获取 preauth ID
        let preauths = baize.approval_list_preauth("child").unwrap();
        let pa_id = &preauths[0].id;

        // outsider 不能删除
        let result = baize.approval_delete_preauth(pa_id, "outsider");
        assert!(matches!(result, Err(Error::PermissionDenied(_))),
            "unauthorized agent should not be able to delete preauth, got {:?}", result);

        // 数据仍然存在
        let preauths_after = baize.approval_list_preauth("child").unwrap();
        assert_eq!(preauths_after.len(), 1);
    }

    // ─── 链断裂测试 ───

    #[test]
    fn test_chain_broken_by_revoked_parent() {
        // 创建 parent → child 链，然后 revoke parent
        let mut baize = setup_tree_with_rules(push_rule(false));

        // revoke parent → child 的 parent_id 成为悬空引用
        baize.agent_revoke("baize-root", "parent").unwrap();

        let op = PendingOperation::Push {
            agent_id: "child".to_string(),
            message: "deploy".to_string(),
            ref_name: None,
        };
        let result = baize.check_approval_gate("child", &ApprovalAction::Push, &op);

        // 应返回 Validation 错误（链断裂），而不是 ApprovalPending
        assert!(matches!(result, Err(Error::Validation(_))),
            "broken chain should return Validation error, got {:?}", result);
    }

    #[test]
    fn test_chain_broken_audited() {
        let mut baize = setup_tree_with_rules(push_rule(false));
        baize.agent_revoke("baize-root", "parent").unwrap();

        let op = PendingOperation::Push {
            agent_id: "child".to_string(),
            message: "deploy".to_string(),
            ref_name: None,
        };
        let _ = baize.check_approval_gate("child", &ApprovalAction::Push, &op);

        // 应有链断裂审计记录
        let mut filter = HashMap::new();
        filter.insert("x-audit".to_string(), "true".to_string());
        filter.insert("x-audit-type".to_string(), "approval_chain_broken".to_string());
        let audits = baize.storage.blob_query(&filter).unwrap();
        assert_eq!(audits.len(), 1, "应有链断裂审计记录");
    }
}
