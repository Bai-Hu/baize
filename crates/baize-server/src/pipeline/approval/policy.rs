//! 审批策略实现
//!
//! AutoApprovePolicy — 默认，所有操作自动通过（V2 行为）
//! RuleBasedPolicy — 基于 ApprovalRule 配置的策略

use std::sync::Mutex;

use baize_core::approval::{
    ApprovalAction, ApprovalPolicy, ApprovalRule,
};

// ─── AutoApprovePolicy ───

/// 默认策略：所有操作自动通过
///
/// 不持有任何规则，`get_rule()` 永远返回 None。
/// 这保证了在不配置审批规则时，V2 行为完全不变。
pub struct AutoApprovePolicy;

impl ApprovalPolicy for AutoApprovePolicy {
    fn get_rule(&self, _action: &ApprovalAction, _requester_level: u8) -> Option<ApprovalRule> {
        None
    }

    fn is_auto(&self, _action: &ApprovalAction, _requester_level: u8, _approver_level: u8) -> bool {
        true
    }

    fn timeout(&self, _action: &ApprovalAction) -> Option<u64> {
        None
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

// ─── RuleBasedPolicy ───

/// 基于规则配置的审批策略
///
/// 持有 `Vec<ApprovalRule>`，匹配 action + requester_level。
/// 使用内部可变性（Mutex）允许运行时更新规则。
pub struct RuleBasedPolicy {
    rules: Mutex<Vec<ApprovalRule>>,
}

impl RuleBasedPolicy {
    pub fn new(rules: Vec<ApprovalRule>) -> Self {
        Self {
            rules: Mutex::new(rules),
        }
    }

    /// 替换所有规则
    pub fn set_rules(&self, new_rules: Vec<ApprovalRule>) {
        let mut rules = self.rules.lock().unwrap();
        *rules = new_rules;
    }

    /// 获取规则快照
    pub fn rules_snapshot(&self) -> Vec<ApprovalRule> {
        let rules = self.rules.lock().unwrap();
        rules.clone()
    }
}

impl ApprovalPolicy for RuleBasedPolicy {
    fn get_rule(&self, action: &ApprovalAction, requester_level: u8) -> Option<ApprovalRule> {
        self.find_rule(action, requester_level)
    }

    fn is_auto(&self, action: &ApprovalAction, requester_level: u8, approver_level: u8) -> bool {
        let rules = self.rules.lock().unwrap();
        if let Some(rule) = rules.iter().find(|r| {
            r.action == *action
                && requester_level >= r.level_range.0
                && requester_level <= r.level_range.1
        }) {
            rule.levels
                .iter()
                .find(|lc| lc.level == approver_level)
                .map(|lc| lc.auto)
                .unwrap_or(false)
        } else {
            // 无规则 → 自动通过
            true
        }
    }

    fn timeout(&self, action: &ApprovalAction) -> Option<u64> {
        let rules = self.rules.lock().unwrap();
        rules
            .iter()
            .find(|r| r.action == *action)
            .and_then(|r| r.timeout_secs)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

// 由于 trait 返回引用与 Mutex 不兼容，提供一个辅助方法直接查询
impl RuleBasedPolicy {
    /// 查找匹配的规则（返回克隆值）
    pub fn find_rule(&self, action: &ApprovalAction, requester_level: u8) -> Option<ApprovalRule> {
        let rules = self.rules.lock().unwrap();
        rules
            .iter()
            .find(|r| {
                r.action == *action
                    && requester_level >= r.level_range.0
                    && requester_level <= r.level_range.1
            })
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use baize_core::approval::ApprovalLevelConfig;

    #[test]
    fn auto_approve_returns_none() {
        let policy = AutoApprovePolicy;
        assert!(policy.get_rule(&ApprovalAction::Push, 2).is_none());
        assert!(policy.is_auto(&ApprovalAction::Push, 2, 3));
        assert!(policy.timeout(&ApprovalAction::Push).is_none());
    }

    #[test]
    fn rule_based_matches_action_and_level() {
        let rules = vec![ApprovalRule {
            action: ApprovalAction::Push,
            level_range: (0, 2),
            levels: vec![
                ApprovalLevelConfig { level: 2, auto: true, max_grant_count: 10 },
                ApprovalLevelConfig { level: 3, auto: false, max_grant_count: 5 },
            ],
            timeout_secs: Some(3600),
        }];
        let policy = RuleBasedPolicy::new(rules);

        // 匹配
        let rule = policy.find_rule(&ApprovalAction::Push, 1).unwrap();
        assert_eq!(rule.level_range, (0, 2));

        // 不匹配 level
        assert!(policy.find_rule(&ApprovalAction::Push, 3).is_none());

        // 不匹配 action
        assert!(policy.find_rule(&ApprovalAction::FileWrite, 1).is_none());
    }

    #[test]
    fn rule_based_is_auto() {
        let rules = vec![ApprovalRule {
            action: ApprovalAction::Push,
            level_range: (0, 2),
            levels: vec![
                ApprovalLevelConfig { level: 2, auto: true, max_grant_count: 10 },
                ApprovalLevelConfig { level: 3, auto: false, max_grant_count: 5 },
            ],
            timeout_secs: None,
        }];
        let policy = RuleBasedPolicy::new(rules);

        // L2 auto=true
        assert!(policy.is_auto(&ApprovalAction::Push, 1, 2));
        // L3 auto=false
        assert!(!policy.is_auto(&ApprovalAction::Push, 1, 3));
        // 无规则 → auto
        assert!(policy.is_auto(&ApprovalAction::FileWrite, 1, 3));
    }

    #[test]
    fn rule_based_timeout() {
        let rules = vec![ApprovalRule {
            action: ApprovalAction::Push,
            level_range: (0, 2),
            levels: vec![],
            timeout_secs: Some(1800),
        }];
        let policy = RuleBasedPolicy::new(rules);
        assert_eq!(policy.timeout(&ApprovalAction::Push), Some(1800));
        assert_eq!(policy.timeout(&ApprovalAction::FileWrite), None);
    }

    #[test]
    fn set_rules_replaces() {
        let policy = RuleBasedPolicy::new(vec![]);
        assert!(policy.find_rule(&ApprovalAction::Push, 1).is_none());

        policy.set_rules(vec![ApprovalRule {
            action: ApprovalAction::Push,
            level_range: (0, 4),
            levels: vec![],
            timeout_secs: None,
        }]);
        assert!(policy.find_rule(&ApprovalAction::Push, 1).is_some());
    }
}
