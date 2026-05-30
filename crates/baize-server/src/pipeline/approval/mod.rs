//! 传导式审批引擎 — 模块入口
//!
//! Phase 4: 将审批机制从 elevation 扩展为通用传导式审批引擎。

mod engine;
mod policy;
mod store;

pub use policy::{AutoApprovePolicy, RuleBasedPolicy};
pub use store::{ApprovalStore, BlobApprovalStore};

use baize_core::approval::{ApprovalAction, ApprovalRequest, ApprovalRule, ApprovalStatus, PreAuthorization};
use baize_core::error::Error;

/// 审批管理接口
pub trait ApprovalManager {
    /// 审批门控：返回 Ok(()) 表示操作可直接执行，Err(ApprovalPending) 表示已冻结等待审批
    fn check_approval_gate(
        &self,
        agent_id: &str,
        action: &ApprovalAction,
        operation: &baize_core::approval::PendingOperation,
    ) -> Result<(), Error>;

    /// 审批通过
    fn approval_approve(
        &self,
        request_id: &str,
        approver_id: &str,
        granted_count: u32,
        note: Option<&str>,
    ) -> Result<ApprovalStatus, Error>;

    /// 驳回请求
    fn approval_reject(
        &self,
        request_id: &str,
        approver_id: &str,
        reason: Option<&str>,
    ) -> Result<ApprovalStatus, Error>;

    /// 越权上传
    fn approval_escalate(
        &self,
        request_id: &str,
        approver_id: &str,
        reason: Option<&str>,
    ) -> Result<ApprovalStatus, Error>;

    /// 列出待我审批的请求
    fn approval_pending(&self, agent_id: &str) -> Result<Vec<ApprovalRequest>, Error>;

    /// 查看请求详情（含完整链），caller_id 用于访问控制
    fn approval_show(&self, request_id: &str, caller_id: &str) -> Result<ApprovalRequest, Error>;

    /// 消耗一次使用权，返回剩余次数
    fn approval_consume(&self, request_id: &str) -> Result<u32, Error>;

    /// 创建预授权
    fn approval_preauth(
        &self,
        granter_id: &str,
        grantee_id: &str,
        action: &ApprovalAction,
        count: u32,
    ) -> Result<PreAuthorization, Error>;

    /// 列出预授权
    fn approval_list_preauth(&self, agent_id: &str) -> Result<Vec<PreAuthorization>, Error>;

    /// 删除预授权（仅 root 或授权者可删除）
    fn approval_delete_preauth(&self, preauth_id: &str, caller_id: &str) -> Result<(), Error>;

    /// 获取当前策略规则
    fn approval_policy_get(&self) -> Vec<ApprovalRule>;

    /// 更新策略规则（仅 root）
    fn approval_policy_update(&self, rules: Vec<ApprovalRule>) -> Result<(), Error>;
}
