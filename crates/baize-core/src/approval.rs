//! 传导式审批引擎 — 类型与策略 trait
//!
//! V3 Phase 4：将审批机制从 elevation 扩展为通用传导式审批引擎。
//! 审批请求沿 agent 树向上传导（hop-by-hop），每一跳可 AutoPassed/Approved/Rejected/Escalated。
//! 默认策略为 AutoApproveAll（无规则 = 自动通过），保持 V2 行为不变。

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── 操作类型 ───

/// 受审批门控的操作类型
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalAction {
    Push,
    BlobWrite,
    FileWrite,
    FileDelete,
    AgentRegister,
    AuthzIssue,
    AuthzDelegate,
    IntentCreate,
    IntentDerive,
    ReceiptCreate,
    SessionCreate,
    SessionClose,
    KeyRotation,
    /// 自定义操作类型 — 名称不能与已有变体重名（如 "push"），否则反序列化会匹配到已有变体
    #[serde(untagged)]
    Custom(String),
}

impl fmt::Display for ApprovalAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ApprovalAction::Push => "push",
            ApprovalAction::BlobWrite => "blob_write",
            ApprovalAction::FileWrite => "file_write",
            ApprovalAction::FileDelete => "file_delete",
            ApprovalAction::AgentRegister => "agent_register",
            ApprovalAction::AuthzIssue => "authz_issue",
            ApprovalAction::AuthzDelegate => "authz_delegate",
            ApprovalAction::IntentCreate => "intent_create",
            ApprovalAction::IntentDerive => "intent_derive",
            ApprovalAction::ReceiptCreate => "receipt_create",
            ApprovalAction::SessionCreate => "session_create",
            ApprovalAction::SessionClose => "session_close",
            ApprovalAction::KeyRotation => "key_rotation",
            ApprovalAction::Custom(name) => name,
        };
        write!(f, "{}", s)
    }
}

impl std::str::FromStr for ApprovalAction {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "push" => Ok(ApprovalAction::Push),
            "blob_write" => Ok(ApprovalAction::BlobWrite),
            "file_write" => Ok(ApprovalAction::FileWrite),
            "file_delete" => Ok(ApprovalAction::FileDelete),
            "agent_register" => Ok(ApprovalAction::AgentRegister),
            "authz_issue" => Ok(ApprovalAction::AuthzIssue),
            "authz_delegate" => Ok(ApprovalAction::AuthzDelegate),
            "intent_create" => Ok(ApprovalAction::IntentCreate),
            "intent_derive" => Ok(ApprovalAction::IntentDerive),
            "receipt_create" => Ok(ApprovalAction::ReceiptCreate),
            "session_create" => Ok(ApprovalAction::SessionCreate),
            "session_close" => Ok(ApprovalAction::SessionClose),
            "key_rotation" => Ok(ApprovalAction::KeyRotation),
            other => Ok(ApprovalAction::Custom(other.to_string())),
        }
    }
}

// ─── 传导链类型 ───

/// 传导链单跳决策
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HopDecision {
    /// 配置为 auto，自动传导到下一级
    AutoPassed,
    /// 审批通过，授予 N 次使用权
    Approved { granted_count: u32 },
    /// 驳回
    Rejected,
    /// 越权，继续上传
    Escalated,
}

impl fmt::Display for HopDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HopDecision::AutoPassed => write!(f, "auto_passed"),
            HopDecision::Approved { granted_count } => write!(f, "approved({})", granted_count),
            HopDecision::Rejected => write!(f, "rejected"),
            HopDecision::Escalated => write!(f, "escalated"),
        }
    }
}

/// 传导链一跳
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalHop {
    pub agent_id: String,
    pub level: u8,
    pub decision: HopDecision,
    pub note: String,
    pub decided_at: String,
}

// ─── 审批请求 ───

/// 审批请求状态
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
    Executed,
}

impl fmt::Display for ApprovalStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApprovalStatus::Pending => write!(f, "pending"),
            ApprovalStatus::Approved => write!(f, "approved"),
            ApprovalStatus::Rejected => write!(f, "rejected"),
            ApprovalStatus::Expired => write!(f, "expired"),
            ApprovalStatus::Executed => write!(f, "executed"),
        }
    }
}

/// 审批请求（存储为 blob content）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// 唯一 ID（apr- 前缀）
    pub id: String,
    /// 请求者 agent ID
    pub requester_id: String,
    /// 请求者 level（冗余存储，避免反复查 identity）
    pub requester_level: u8,
    /// 触发审批的操作类型
    pub action: ApprovalAction,
    /// 序列化的 PendingOperation（serde_json）
    pub operation_payload: String,
    /// 传导链（所有 hop 的决策记录）
    pub chain: Vec<ApprovalHop>,
    /// 当前状态
    pub status: ApprovalStatus,
    /// 当前等待谁的决策
    pub pending_at: Option<String>,
    /// 授予的使用次数
    pub granted_count: u32,
    /// 剩余使用次数
    pub remaining_count: u32,
    /// 创建时间（RFC3339）
    pub created_at: String,
    /// 过期时间（RFC3339），None = 永不过期
    pub expires_at: Option<String>,
}

// ─── 冻结操作 ───

/// 冻结的操作（随审批请求存储，审批通过后 replay）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum PendingOperation {
    Push {
        agent_id: String,
        message: String,
        ref_name: Option<String>,
    },
    BlobWrite {
        agent_id: String,
        content: String,
        labels: HashMap<String, String>,
    },
    FileWrite {
        agent_id: String,
        path: String,
        content: Vec<u8>,
        labels: Option<HashMap<String, String>>,
    },
    FileDelete {
        agent_id: String,
        path: String,
    },
    AgentRegister {
        name: String,
        level: u8,
        zones: Vec<String>,
        parent_id: Option<String>,
    },
    AuthzIssue {
        agent_id: String,
        content: String,
        labels: HashMap<String, String>,
    },
    AuthzDelegate {
        agent_id: String,
        content: String,
        labels: HashMap<String, String>,
    },
    IntentCreate {
        agent_id: String,
        content: String,
        labels: HashMap<String, String>,
    },
    IntentDerive {
        agent_id: String,
        content: String,
        labels: HashMap<String, String>,
    },
    ReceiptCreate {
        agent_id: String,
        content: String,
        labels: HashMap<String, String>,
    },
    SessionCreate {
        agent_id: String,
        content: String,
        labels: HashMap<String, String>,
    },
    SessionClose {
        agent_id: String,
        session_id: String,
    },
    KeyRotation {
        agent_id: String,
        purpose: String,
    },
}

// ─── 预授权 ───

/// 预授权 — 高级 agent 预先授权低级 agent 的操作次数
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreAuthorization {
    /// 唯一 ID（pre- 前缀）
    pub id: String,
    /// 授权者 agent ID
    pub granter_id: String,
    /// 被授权者 agent ID
    pub grantee_id: String,
    /// 覆盖的操作类型
    pub action: ApprovalAction,
    /// 总授予次数
    pub granted_count: u32,
    /// 剩余次数
    pub remaining_count: u32,
    /// 创建时间（RFC3339）
    pub created_at: String,
}

// ─── 策略配置 ───

/// 单级审批配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalLevelConfig {
    pub level: u8,
    pub auto: bool,
    pub max_grant_count: u32,
}

/// 按 action + level 范围的审批规则
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRule {
    pub action: ApprovalAction,
    pub level_range: (u8, u8),
    pub levels: Vec<ApprovalLevelConfig>,
    pub timeout_secs: Option<u64>,
}

/// 审批策略 trait — 决定哪些操作需要审批
pub trait ApprovalPolicy: Send + Sync {
    /// 返回 action + requester_level 对应的规则；None 表示自动通过
    fn get_rule(&self, action: &ApprovalAction, requester_level: u8) -> Option<ApprovalRule>;

    /// 指定 approver_level 是否配置为 auto
    fn is_auto(&self, action: &ApprovalAction, requester_level: u8, approver_level: u8) -> bool;

    /// 返回 action 的超时时间（秒），None 表示永不过期
    fn timeout(&self, action: &ApprovalAction) -> Option<u64>;

    /// 支持 downcast（遵循 IdentityProvider 模式）
    fn as_any(&self) -> &dyn std::any::Any;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_action_display_roundtrip() {
        let actions = [
            ApprovalAction::Push,
            ApprovalAction::BlobWrite,
            ApprovalAction::FileWrite,
            ApprovalAction::FileDelete,
            ApprovalAction::AgentRegister,
            ApprovalAction::AuthzIssue,
            ApprovalAction::AuthzDelegate,
            ApprovalAction::IntentCreate,
            ApprovalAction::IntentDerive,
            ApprovalAction::ReceiptCreate,
            ApprovalAction::SessionCreate,
            ApprovalAction::SessionClose,
            ApprovalAction::KeyRotation,
        ];
        for action in &actions {
            let s = action.to_string();
            let parsed: ApprovalAction = s.parse().unwrap();
            assert_eq!(*action, parsed);
        }
    }

    #[test]
    fn approval_action_custom() {
        let custom = ApprovalAction::Custom("deploy".to_string());
        assert_eq!(custom.to_string(), "deploy");
        let parsed: ApprovalAction = "deploy".parse().unwrap();
        assert_eq!(custom, parsed);
    }

    #[test]
    fn approval_request_serialization() {
        let req = ApprovalRequest {
            id: "apr-test".to_string(),
            requester_id: "agent-001".to_string(),
            requester_level: 2,
            action: ApprovalAction::Push,
            operation_payload: "{}".to_string(),
            chain: vec![ApprovalHop {
                agent_id: "parent".to_string(),
                level: 3,
                decision: HopDecision::AutoPassed,
                note: String::new(),
                decided_at: "2025-01-01T00:00:00Z".to_string(),
            }],
            status: ApprovalStatus::Pending,
            pending_at: Some("root".to_string()),
            granted_count: 0,
            remaining_count: 0,
            created_at: "2025-01-01T00:00:00Z".to_string(),
            expires_at: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        let decoded: ApprovalRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.id, "apr-test");
        assert_eq!(decoded.action, ApprovalAction::Push);
        assert_eq!(decoded.chain.len(), 1);
    }

    #[test]
    fn pending_operation_serialization() {
        let op = PendingOperation::Push {
            agent_id: "agent-001".to_string(),
            message: "deploy v2".to_string(),
            ref_name: Some("main".to_string()),
        };
        let json = serde_json::to_string(&op).unwrap();
        let decoded: PendingOperation = serde_json::from_str(&json).unwrap();
        match decoded {
            PendingOperation::Push { agent_id, message, ref_name } => {
                assert_eq!(agent_id, "agent-001");
                assert_eq!(message, "deploy v2");
                assert_eq!(ref_name, Some("main".to_string()));
            }
            _ => panic!("expected Push"),
        }
    }

    #[test]
    fn pre_authorization_serialization() {
        let pa = PreAuthorization {
            id: "pre-001".to_string(),
            granter_id: "root".to_string(),
            grantee_id: "agent-001".to_string(),
            action: ApprovalAction::FileWrite,
            granted_count: 10,
            remaining_count: 7,
            created_at: "2025-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&pa).unwrap();
        let decoded: PreAuthorization = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.remaining_count, 7);
    }

    #[test]
    fn approval_status_display() {
        assert_eq!(ApprovalStatus::Pending.to_string(), "pending");
        assert_eq!(ApprovalStatus::Approved.to_string(), "approved");
        assert_eq!(ApprovalStatus::Rejected.to_string(), "rejected");
        assert_eq!(ApprovalStatus::Expired.to_string(), "expired");
        assert_eq!(ApprovalStatus::Executed.to_string(), "executed");
    }

    #[test]
    fn hop_decision_variants() {
        let auto = HopDecision::AutoPassed;
        let approved = HopDecision::Approved { granted_count: 5 };
        let rejected = HopDecision::Rejected;
        let escalated = HopDecision::Escalated;

        let json = serde_json::to_string(&auto).unwrap();
        assert!(json.contains("auto_passed"));

        let json = serde_json::to_string(&approved).unwrap();
        assert!(json.contains("approved"));
        assert!(json.contains("5"));

        let decoded: HopDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, approved);

        let json = serde_json::to_string(&rejected).unwrap();
        assert!(json.contains("rejected"));

        let json = serde_json::to_string(&escalated).unwrap();
        assert!(json.contains("escalated"));
    }

    #[test]
    fn approval_rule_serialization() {
        let rule = ApprovalRule {
            action: ApprovalAction::Push,
            level_range: (0, 2),
            levels: vec![
                ApprovalLevelConfig { level: 2, auto: true, max_grant_count: 10 },
                ApprovalLevelConfig { level: 3, auto: false, max_grant_count: 5 },
            ],
            timeout_secs: Some(3600),
        };
        let json = serde_json::to_string(&rule).unwrap();
        let decoded: ApprovalRule = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.level_range, (0, 2));
        assert_eq!(decoded.levels.len(), 2);
        assert_eq!(decoded.timeout_secs, Some(3600));
    }
}
