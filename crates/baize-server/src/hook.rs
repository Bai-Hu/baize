use std::collections::HashMap;

use baize_core::identity::AgentIdentity;
use baize_core::scope::Scope;

/// Hook 上下文：包含操作的所有信息
#[derive(Debug, Clone)]
pub struct HookContext {
    pub agent_id: String,
    pub identity: Option<AgentIdentity>,
    pub operation: String,
    pub scope: Option<Scope>,
    pub params: HashMap<String, String>,
    pub result: Option<String>,
}

/// Hook 结果
#[derive(Debug, Clone)]
pub struct HookResult {
    pub allowed: bool,
    pub reason: Option<String>,
    pub audit_labels: HashMap<String, String>,
}

impl HookResult {
    pub fn allow() -> Self {
        Self {
            allowed: true,
            reason: None,
            audit_labels: HashMap::new(),
        }
    }

    pub fn deny(reason: &str) -> Self {
        Self {
            allowed: false,
            reason: Some(reason.to_string()),
            audit_labels: HashMap::new(),
        }
    }
}

/// Pre-hook 函数类型：验证身份 + 检查权限
pub type PreHookFn = Box<dyn Fn(&HookContext) -> HookResult + Send + Sync>;

/// Post-hook 函数类型：审计记录
pub type PostHookFn = Box<dyn Fn(&HookContext, &HookResult) + Send + Sync>;

/// Hook 注册器
pub struct HookRegistry {
    pre_hooks: Vec<PreHookFn>,
    post_hooks: Vec<PostHookFn>,
}

impl Default for HookRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl HookRegistry {
    pub fn new() -> Self {
        Self {
            pre_hooks: Vec::new(),
            post_hooks: Vec::new(),
        }
    }

    /// 注册 pre-hook（验证身份 + 权限检查）
    pub fn register_pre(&mut self, hook: PreHookFn) {
        self.pre_hooks.push(hook);
    }

    /// 注册 post-hook（审计记录）
    pub fn register_post(&mut self, hook: PostHookFn) {
        self.post_hooks.push(hook);
    }

    /// 执行所有 pre-hooks，任一拒绝则拒绝
    pub fn run_pre(&self, ctx: &HookContext) -> HookResult {
        for hook in &self.pre_hooks {
            let result = hook(ctx);
            if !result.allowed {
                return result;
            }
        }
        HookResult::allow()
    }

    /// 执行所有 post-hooks
    pub fn run_post(&self, ctx: &HookContext, result: &HookResult) {
        for hook in &self.post_hooks {
            hook(ctx, result);
        }
    }
}

/// 创建默认 Hook 注册器（基础验证 + 审计）
pub fn default_hooks() -> HookRegistry {
    let mut registry = HookRegistry::new();

    // Pre-hook: 验证身份
    registry.register_pre(Box::new(|ctx: &HookContext| {
        if ctx.identity.is_none() {
            return HookResult::deny("no identity provided");
        }
        HookResult::allow()
    }));

    // Post-hook: 标记审计信息（审计由 Pipeline 层直接写入 Storage）
    // 当前为占位实现，后续审计逻辑可迁移到 hook 中
    registry.register_post(Box::new(|_ctx: &HookContext, _result: &HookResult| {
        // 审计记录由 Pipeline 的 pipe_* 方法直接调用 self.audit() 写入
    }));

    registry
}

#[cfg(test)]
mod tests {
    use super::*;
    use baize_core::scope::{Level, Scope};
    use baize_core::cert::CredentialStatus;

    fn basic_ctx() -> HookContext {
        let scope = Scope::new(Level(2), vec!["A"]).unwrap();
        HookContext {
            agent_id: "agent-001".to_string(),
            identity: Some(AgentIdentity {
                agent_id: "agent-001".to_string(),
                parent_id: None,
                level: 2,
                zones: vec!["A".to_string()],
                status: CredentialStatus::Active,
                attributes: HashMap::new(),
            }),
            operation: "test".to_string(),
            scope: Some(scope),
            params: HashMap::new(),
            result: None,
        }
    }

    #[test]
    fn new_registry_allows_all() {
        let registry = HookRegistry::new();
        let ctx = basic_ctx();
        let result = registry.run_pre(&ctx);
        assert!(result.allowed);
    }

    #[test]
    fn pre_hook_deny_stops() {
        let mut registry = HookRegistry::new();
        registry.register_pre(Box::new(|_ctx| {
            HookResult::deny("blocked for test")
        }));
        let result = registry.run_pre(&basic_ctx());
        assert!(!result.allowed);
        assert_eq!(result.reason.as_deref(), Some("blocked for test"));
    }

    #[test]
    fn pre_hook_chain_first_deny_wins() {
        let mut registry = HookRegistry::new();
        registry.register_pre(Box::new(|_ctx| HookResult::deny("first")));
        registry.register_pre(Box::new(|_ctx| HookResult::allow()));
        let result = registry.run_pre(&basic_ctx());
        assert!(!result.allowed);
        assert_eq!(result.reason.as_deref(), Some("first"));
    }

    #[test]
    fn post_hooks_all_called() {
        let mut registry = HookRegistry::new();
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c1 = counter.clone();
        let c2 = counter.clone();
        registry.register_post(Box::new(move |_ctx, _res| {
            c1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }));
        registry.register_post(Box::new(move |_ctx, _res| {
            c2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }));
        let ctx = basic_ctx();
        let result = HookResult::allow();
        registry.run_post(&ctx, &result);
        assert_eq!(counter.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[test]
    fn default_hooks_deny_no_identity() {
        let registry = default_hooks();
        let ctx = HookContext {
            identity: None,
            ..basic_ctx()
        };
        let result = registry.run_pre(&ctx);
        assert!(!result.allowed);
    }

    #[test]
    fn default_hooks_allow_with_identity() {
        let registry = default_hooks();
        let result = registry.run_pre(&basic_ctx());
        assert!(result.allowed);
    }
}
