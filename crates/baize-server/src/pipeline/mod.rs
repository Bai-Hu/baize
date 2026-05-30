use std::path::{Path, PathBuf};
use std::sync::Arc;

use baize_core::crypto::CryptoProvider;
use baize_core::error::Error;
use baize_core::identity::IdentityProvider;
use baize_core::approval::ApprovalPolicy;
use baize_core::storage::{BlobStore, Storage};
use baize_core::workspace::WorkspaceManager;
use baize_core::ROOT_AGENT_ID;

use crate::hook::HookRegistry;

// 共享宏（必须在子模块声明之前，子模块才能使用）
macro_rules! labels {
    ($($k:expr => $v:expr),* $(,)?) => {{
        <HashMap<String, String>>::from([
            $(($k.to_string(), $v.to_string())),*
        ])
    }};
}

// 子模块
pub mod agent_manager;
pub mod approval;
pub mod auth;
pub mod auditor;
pub mod data_ops;
pub mod elevation;
pub mod file_sync;
pub mod git_ops;
pub mod identity;
pub mod protocol;

// 重新导出 trait 和类型（方便外部使用）
pub use auditor::Auditor;
pub use agent_manager::{AgentRegistry, PermissionGuard};
pub use approval::{ApprovalManager, ApprovalStore, BlobApprovalStore, AutoApprovePolicy};
pub use data_ops::DataOps;
pub use elevation::ElevationManager;
pub use file_sync::{FileSync, FileRecord, FileContent, PushResult, PullResult};
pub use git_ops::{GitOps, GitCommitInfo, RepoStats};
pub use protocol::{BlobTypeHandler, ProtocolRegistry, ValidationContext};
pub use identity::CertIdentityProvider;

/// 判断 RFC3339 时间戳是否已过期（当前时间 > timestamp）
/// 解析失败时视为已过期（fail-closed）
pub(crate) fn is_timestamp_expired(timestamp: &str) -> bool {
    chrono::DateTime::parse_from_rfc3339(timestamp)
        .map(|dt| dt < chrono::Utc::now())
        .unwrap_or(true)
}

/// 比较两个 RFC3339 时间戳：a > b？
/// 解析失败时返回 None（调用方决定是否跳过比较）
pub(crate) fn is_timestamp_after(a: &str, b: &str) -> Option<bool> {
    let dt_a = chrono::DateTime::parse_from_rfc3339(a).ok()?;
    let dt_b = chrono::DateTime::parse_from_rfc3339(b).ok()?;
    Some(dt_a > dt_b)
}

/// 白泽主控 — 五关口管道核心
pub struct Baize {
    pub storage: Arc<dyn BlobStore>,
    pub crypto: CryptoProvider,
    pub(super) protocol_registry: ProtocolRegistry,
    pub workspace_mgr: WorkspaceManager,
    /// 主仓库路径：所有 agent 共享的单一数据源目录
    pub(super) main_repo: PathBuf,
    pub(super) hooks: HookRegistry,
    /// 可插拔身份提供者（默认 CertIdentityProvider）
    pub(super) identity: Arc<dyn IdentityProvider>,
    /// 审批存储（默认 BlobApprovalStore）
    pub(super) approval_store: Arc<dyn approval::ApprovalStore>,
    /// 审批策略（默认 RuleBasedPolicy，空规则 = 自动通过）
    pub(super) approval_policy: Arc<dyn ApprovalPolicy>,
    /// v1：ASL 合规上下文（适配 + 校验）
    pub asl: baize_asl::AslContext,
}

impl Baize {
    /// 获取存储后端的 trait object 引用
    ///
    /// 比 `&*self.storage` 更清晰，避免在调用点关心 Arc 解引用细节。
    pub fn store(&self) -> &dyn BlobStore {
        &*self.storage
    }

    /// 注册自定义协议 handler（扩展新的 blob type）
    ///
    /// 二次开发者实现 `BlobTypeHandler` trait 后调用此方法注册。
    /// 同名 handler 会覆盖默认 handler。
    pub fn register_handler(&mut self, handler: Box<dyn BlobTypeHandler>) {
        self.protocol_registry.register(handler);
    }

    /// 初始化白泽：创建存储 + 生成 Root CA
    pub fn init(db_path: &str, ws_base: &str, main_repo: &str) -> Result<Self, Error> {
        let crypto = CryptoProvider::default();
        let storage: Arc<dyn BlobStore> = Arc::new(Storage::open(db_path)?);
        let mut workspace_mgr = WorkspaceManager::new(ws_base)?;

        // 创建主仓库目录 + Git 初始化
        let main_repo_path = PathBuf::from(main_repo);
        std::fs::create_dir_all(&main_repo_path)
            .map_err(|e| Error::Internal(anyhow::anyhow!("failed to create main repo dir: {}", e)))?;
        Self::git_init(&main_repo_path)?;

        // 初始化身份提供者（root CA 生成 + agent 恢复）
        let cert_provider = identity::CertIdentityProvider::new();
        cert_provider.init_root(&*storage, &crypto)?;
        cert_provider.restore(&*storage, &crypto)?;

        // 为所有已恢复的 agent 确保 workspace
        workspace_mgr.ensure(ROOT_AGENT_ID)?;
        cert_provider.for_each_agent(|agent_id, _| {
            if agent_id != ROOT_AGENT_ID {
                let _ = workspace_mgr.ensure(agent_id);
            }
        });

        let identity: Arc<dyn IdentityProvider> = Arc::new(cert_provider);
        let approval_store: Arc<dyn approval::ApprovalStore> = Arc::new(
            approval::BlobApprovalStore::new(storage.clone())
        );
        let approval_policy: Arc<dyn ApprovalPolicy> = Arc::new(approval::RuleBasedPolicy::new(vec![]));

        Ok(Self {
            storage,
            crypto,
            protocol_registry: ProtocolRegistry::default(),
            workspace_mgr,
            main_repo: main_repo_path,
            hooks: crate::hook::default_hooks(),
            identity,
            approval_store,
            approval_policy,
            asl: baize_asl::AslContext::default(),
        })
    }

    /// 用内存数据库初始化（用于测试）
    pub fn init_in_memory() -> Result<Self, Error> {
        BaizeBuilder::new().build_in_memory()
    }

    /// 创建 Builder 用于自定义组件
    pub fn builder() -> BaizeBuilder {
        BaizeBuilder::new()
    }
}

/// Baize 构建器 — 允许外部 crate 替换可插拔组件
///
/// # 示例
///
/// ```ignore
/// let baize = Baize::builder()
///     .storage(my_custom_storage)
///     .crypto(my_crypto_provider)
///     .approval_policy(my_policy)
///     .build_in_memory()?;
/// ```
pub struct BaizeBuilder {
    storage: Option<Arc<dyn BlobStore>>,
    crypto: Option<CryptoProvider>,
    identity: Option<Arc<dyn IdentityProvider>>,
    approval_policy: Option<Arc<dyn ApprovalPolicy>>,
    approval_store: Option<Arc<dyn approval::ApprovalStore>>,
}

impl BaizeBuilder {
    pub fn new() -> Self {
        Self {
            storage: None,
            crypto: None,
            identity: None,
            approval_policy: None,
            approval_store: None,
        }
    }

    /// 自定义存储后端
    pub fn storage(mut self, s: Arc<dyn BlobStore>) -> Self {
        self.storage = Some(s);
        self
    }

    /// 自定义加密提供者
    pub fn crypto(mut self, c: CryptoProvider) -> Self {
        self.crypto = Some(c);
        self
    }

    /// 自定义身份提供者
    pub fn identity(mut self, id: Arc<dyn IdentityProvider>) -> Self {
        self.identity = Some(id);
        self
    }

    /// 自定义审批策略
    pub fn approval_policy(mut self, p: Arc<dyn ApprovalPolicy>) -> Self {
        self.approval_policy = Some(p);
        self
    }

    /// 自定义审批存储
    pub fn approval_store(mut self, s: Arc<dyn approval::ApprovalStore>) -> Self {
        self.approval_store = Some(s);
        self
    }

    /// 使用内存存储构建（用于测试）
    pub fn build_in_memory(self) -> Result<Baize, Error> {
        let crypto = self.crypto.unwrap_or_default();
        let storage = self.storage.unwrap_or_else(|| {
            Arc::new(Storage::open(":memory:").expect("in-memory storage should not fail"))
        });

        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let tmp_dir = std::env::temp_dir().join(format!("baize-test-{}-{}", std::process::id(), unique));
        let mut workspace_mgr = WorkspaceManager::new(tmp_dir.to_str().unwrap_or(""))?;

        let main_repo = tmp_dir.join("main");
        std::fs::create_dir_all(&main_repo)
            .map_err(|e| Error::Internal(anyhow::anyhow!("failed to create test main repo: {}", e)))?;
        Self::git_init(&main_repo)?;

        let identity = match self.identity {
            Some(id) => {
                workspace_mgr.ensure(ROOT_AGENT_ID)?;
                id
            }
            None => {
                let cert_provider = identity::CertIdentityProvider::new();
                cert_provider.init_root(&*storage, &crypto)?;
                workspace_mgr.ensure(ROOT_AGENT_ID)?;
                Arc::new(cert_provider)
            }
        };

        let approval_store = self.approval_store.unwrap_or_else(|| {
            Arc::new(approval::BlobApprovalStore::new(storage.clone()))
        });
        let approval_policy = self.approval_policy
            .unwrap_or_else(|| Arc::new(approval::RuleBasedPolicy::new(vec![])));

        Ok(Baize {
            storage,
            crypto,
            protocol_registry: ProtocolRegistry::default(),
            workspace_mgr,
            main_repo,
            hooks: crate::hook::default_hooks(),
            identity,
            approval_store,
            approval_policy,
            asl: baize_asl::AslContext::default(),
        })
    }

    fn git_init(path: &Path) -> Result<(), Error> {
        Baize::git_init(path)?;
        Ok(())
    }
}

impl Default for BaizeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use baize_core::scope::{ElevationMode, ElevationStatus, Level};

    // 需要引入 trait 才能调用 trait 方法
    use super::auditor::Auditor;
    use super::agent_manager::AgentRegistry;
    use super::elevation::ElevationManager;
    use super::data_ops::DataOps;
    use super::file_sync::FileSync;

    #[test]
    fn init_baize() {
        let baize = Baize::init_in_memory().unwrap();
        let agents = baize.agent_list();
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].0, "baize-root");
    }

    #[test]
    fn register_agent() {
        let mut baize = Baize::init_in_memory().unwrap();
        let (id, bundle) = baize.agent_register("baize-root", 
            "agent-001",
            Level(2),
            vec!["A", "B"],
            None,
        ).unwrap();

        assert_eq!(id, "agent-001");
        assert_eq!(bundle.identity.agent_id, "agent-001");
        assert_eq!(bundle.identity.level, 2);
    }

    #[test]
    fn register_child_agent() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("baize-root", "parent", Level(3), vec!["A", "B", "C"], None).unwrap();

        let (id, bundle) = baize.agent_register("baize-root", 
            "child",
            Level(2),
            vec!["A"],
            Some("parent"),
        ).unwrap();

        assert_eq!(id, "child");
        assert_eq!(bundle.identity.parent_id.as_deref(), Some("parent"));
    }

    #[test]
    fn revoke_agent() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("baize-root", "agent-001", Level(2), vec!["A"], None).unwrap();
        baize.agent_revoke("baize-root", "agent-001").unwrap();
        assert_eq!(baize.agent_list().len(), 1);
    }

    #[test]
    fn revoke_root_fails() {
        let mut baize = Baize::init_in_memory().unwrap();
        let result = baize.agent_revoke("baize-root", "baize-root");
        assert!(result.is_err());
    }

    #[test]
    fn elevation_flow() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("baize-root", "agent-001", Level(3), vec!["A", "B", "C"], None).unwrap();

        let req_id = baize.elevation_request(
            "agent-001",
            vec!["B", "C"],
            ElevationMode::ReadOnly,
            "need access to zone B",
            None,
        ).unwrap();

        let pending = baize.elevation_list().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].status, ElevationStatus::Pending);

        baize.elevation_approve(&req_id, "baize-root").unwrap();
        let approved = baize.elevation_list().unwrap();
        assert_eq!(approved[0].status, ElevationStatus::Approved);
    }

    #[test]
    fn elevation_can_request_beyond_scope() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("baize-root", "agent-001", Level(2), vec!["A"], None).unwrap();

        let result = baize.elevation_request(
            "agent-001",
            vec!["B"],
            ElevationMode::ReadOnly,
            "need access to zone B",
            None,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn trace_identity_chain() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("baize-root", "parent", Level(3), vec!["A", "B"], None).unwrap();
        baize.agent_register("baize-root", "child", Level(2), vec!["A"], Some("parent")).unwrap();

        let chain = baize.trace_identity("child").unwrap();
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].agent_id, "child");
        assert_eq!(chain[1].agent_id, "parent");
        assert_eq!(chain[2].agent_id, "baize-root");
    }

    #[test]
    fn scope_exceed_fails() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("baize-root", "parent", Level(2), vec!["A"], None).unwrap();

        let result = baize.agent_register("baize-root", "child", Level(3), vec!["A"], Some("parent"));
        assert!(result.is_err());
    }

    #[test]
    fn agent_register_duplicate_fails() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("baize-root", "dup", Level(2), vec!["A"], None).unwrap();
        let result = baize.agent_register("baize-root", "dup", Level(2), vec!["A"], None);
        assert!(result.is_err());
    }

    #[test]
    fn agent_revoke_nonexistent() {
        let mut baize = Baize::init_in_memory().unwrap();
        let result = baize.agent_revoke("baize-root", "no-such-agent");
        assert!(result.is_err());
    }

    #[test]
    fn audit_write_and_query() {
        let baize = Baize::init_in_memory().unwrap();
        baize.audit("test_event", "agent-001", "ok", None).unwrap();

        let mut filter = HashMap::new();
        filter.insert("x-audit".to_string(), "true".to_string());
        let blobs = baize.storage.blob_query(&filter).unwrap();
        assert_eq!(blobs.len(), 1);
        assert!(blobs[0].content.contains("test_event"));
    }

    #[test]
    fn audit_idempotent_not_swallowed() {
        let baize = Baize::init_in_memory().unwrap();
        baize.audit("blob_write", "cc-writer", "success", None).unwrap();
        baize.audit("blob_write", "cc-writer", "success", None).unwrap();

        let mut filter = HashMap::new();
        filter.insert("x-audit".to_string(), "true".to_string());
        filter.insert("x-audit-type".to_string(), "blob_write".to_string());
        let blobs = baize.storage.blob_query(&filter).unwrap();
        assert_eq!(blobs.len(), 2, "duplicate audit events must not be swallowed by blob idempotency");
    }

    #[test]
    fn audit_target_in_labels() {
        let baize = Baize::init_in_memory().unwrap();
        baize.audit("file_write", "agent-001", "success", Some("config/app.yaml")).unwrap();

        let mut filter = HashMap::new();
        filter.insert("x-audit".to_string(), "true".to_string());
        filter.insert("x-audit-target".to_string(), "config/app.yaml".to_string());
        let blobs = baize.storage.blob_query(&filter).unwrap();
        assert_eq!(blobs.len(), 1);
        assert_eq!(blobs[0].labels.get("x-audit-target").unwrap(), "config/app.yaml");
        assert!(blobs[0].content.contains("config/app.yaml"));
    }

    #[test]
    fn trace_identity_not_found() {
        let baize = Baize::init_in_memory().unwrap();
        let result = baize.trace_identity("no-such-agent");
        assert!(result.is_err());
    }

    #[test]
    fn elevation_approve_nonexistent() {
        let mut baize = Baize::init_in_memory().unwrap();
        let result = baize.elevation_approve("no-such-req", "baize-root");
        assert!(result.is_err());
    }

    #[test]
    fn elevation_approve_already_processed() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("baize-root", "agent-001", Level(3), vec!["A", "B", "C"], None).unwrap();

        let req_id = baize.elevation_request(
            "agent-001", vec!["A"], ElevationMode::ReadOnly, "test", None
        ).unwrap();

        baize.elevation_approve(&req_id, "baize-root").unwrap();
        let result = baize.elevation_approve(&req_id, "baize-root");
        assert!(result.is_err());
    }

    #[test]
    fn elevation_request_nonexistent_agent() {
        let mut baize = Baize::init_in_memory().unwrap();
        let result = baize.elevation_request(
            "ghost", vec!["A"], ElevationMode::ReadOnly, "test", None
        );
        assert!(result.is_err());
    }

    #[test]
    fn elevation_with_duration() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("baize-root", "agent-001", Level(3), vec!["A", "B"], None).unwrap();

        let req_id = baize.elevation_request(
            "agent-001", vec!["A"], ElevationMode::ReadOnly, "test", Some("30m"),
        ).unwrap();

        baize.elevation_approve(&req_id, "baize-root").unwrap();

        let _blob = baize.storage.blob_read(&req_id).unwrap();
        assert!(_blob.labels.contains_key("elevation-expires"));
        assert!(_blob.labels.contains_key("elevation-approver"));
    }

    #[test]
    fn elevation_expiry_lazy() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("baize-root", "agent-001", Level(3), vec!["A"], None).unwrap();

        let req_id = baize.elevation_request(
            "agent-001", vec!["A"], ElevationMode::ReadOnly, "test", Some("1h"),
        ).unwrap();

        baize.elevation_approve(&req_id, "baize-root").unwrap();

        let past = chrono::Utc::now() - chrono::Duration::hours(1);
        let past_str = past.to_rfc3339();

        let _blob = baize.storage.blob_read(&req_id).unwrap();

        let mut baize2 = Baize::init_in_memory().unwrap();
        baize2.agent_register("baize-root", "w", Level(3), vec!["A"], None).unwrap();

        let content = serde_json::json!({"agent": "w", "zones": ["A"], "mode": "ReadOnly", "reason": "test", "time": "2020-01-01"}).to_string();
        let mut lbls = HashMap::new();
        lbls.insert("type".to_string(), "elevation-request".to_string());
        lbls.insert("elevation-agent".to_string(), "w".to_string());
        lbls.insert("elevation-zones".to_string(), "[\"A\"]".to_string());
        lbls.insert("elevation-mode".to_string(), "readonly".to_string());
        lbls.insert("elevation-reason".to_string(), "test".to_string());
        lbls.insert("elevation-time".to_string(), "2020-01-01".to_string());
        lbls.insert("elevation-approved".to_string(), "true".to_string());
        lbls.insert("elevation-expires".to_string(), past_str);

        let expired_blob = baize2.storage.blob_write(&content, &lbls).unwrap();

        let list = baize2.elevation_list().unwrap();
        let expired_req = list.iter().find(|r| r.id == expired_blob.hash).unwrap();
        assert_eq!(expired_req.status, ElevationStatus::Expired);
    }

    #[test]
    fn approval_routing_parent_can_approve() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("baize-root", "parent", Level(3), vec!["A", "B", "C"], None).unwrap();
        baize.agent_register("baize-root", "child", Level(2), vec!["A"], Some("parent")).unwrap();

        let req_id = baize.elevation_request(
            "child", vec!["A"], ElevationMode::ReadOnly, "need A", None,
        ).unwrap();

        baize.elevation_approve(&req_id, "parent").unwrap();
    }

    #[test]
    fn approval_routing_parent_cannot_approve_beyond_scope() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("baize-root", "parent", Level(3), vec!["A", "B"], None).unwrap();
        baize.agent_register("baize-root", "child", Level(2), vec!["A"], Some("parent")).unwrap();

        let req_id = baize.elevation_request(
            "child", vec!["Z"], ElevationMode::ReadOnly, "need Z", None,
        ).unwrap();

        let result = baize.elevation_approve(&req_id, "parent");
        assert!(result.is_err());
    }

    #[test]
    fn approval_routing_root_can_approve_anything() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("baize-root", "parent", Level(3), vec!["A", "B"], None).unwrap();
        baize.agent_register("baize-root", "child", Level(2), vec!["A"], Some("parent")).unwrap();

        let req_id = baize.elevation_request(
            "child", vec!["Z"], ElevationMode::ReadOnly, "need Z", None,
        ).unwrap();

        baize.elevation_approve(&req_id, "baize-root").unwrap();
    }

    #[test]
    fn approval_routing_non_parent_cannot_approve() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("baize-root", "agent-a", Level(3), vec!["A"], None).unwrap();
        baize.agent_register("baize-root", "agent-b", Level(3), vec!["B"], None).unwrap();

        let req_id = baize.elevation_request(
            "agent-a", vec!["A"], ElevationMode::ReadOnly, "test", None,
        ).unwrap();

        let result = baize.elevation_approve(&req_id, "agent-b");
        assert!(result.is_err());
    }

    #[test]
    fn elevation_return_success() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("baize-root", "worker", Level(2), vec!["A"], None).unwrap();

        let req_id = baize.elevation_request(
            "worker", vec!["A"], ElevationMode::ReadOnly, "need A", None,
        ).unwrap();
        baize.elevation_approve(&req_id, "baize-root").unwrap();

        baize.elevation_return(&req_id, "worker", "worker").unwrap();

        let list = baize.elevation_list().unwrap();
        let req = list.iter().find(|r| r.id == req_id).unwrap();
        assert_eq!(req.status, ElevationStatus::Returned);
    }

    #[test]
    fn elevation_return_not_approved_fails() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("baize-root", "worker", Level(2), vec!["A"], None).unwrap();

        let req_id = baize.elevation_request(
            "worker", vec!["A"], ElevationMode::ReadOnly, "need A", None,
        ).unwrap();

        let result = baize.elevation_return(&req_id, "worker", "worker");
        assert!(result.is_err());
    }

    #[test]
    fn elevation_return_already_returned_fails() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("baize-root", "worker", Level(2), vec!["A"], None).unwrap();

        let req_id = baize.elevation_request(
            "worker", vec!["A"], ElevationMode::ReadOnly, "need A", None,
        ).unwrap();
        baize.elevation_approve(&req_id, "baize-root").unwrap();
        baize.elevation_return(&req_id, "worker", "worker").unwrap();

        let result = baize.elevation_return(&req_id, "worker", "worker");
        assert!(result.is_err());
    }

    #[test]
    fn elevation_return_wrong_caller_fails() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("baize-root", "worker", Level(2), vec!["A"], None).unwrap();
        baize.agent_register("baize-root", "other", Level(2), vec!["B"], None).unwrap();

        let req_id = baize.elevation_request(
            "worker", vec!["A"], ElevationMode::ReadOnly, "need A", None,
        ).unwrap();
        baize.elevation_approve(&req_id, "baize-root").unwrap();

        let result = baize.elevation_return(&req_id, "worker", "other");
        assert!(result.is_err());
    }

    #[test]
    fn export_plain_blob_allowed() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("baize-root", "reader", Level(0), vec![], None).unwrap();

        let blob = baize.pipe_blob_write("baize-root", "plain data", &HashMap::new()).unwrap();

        let exported = baize.pipe_export("reader", &blob.hash).unwrap();
        assert_eq!(exported.content, "plain data");
    }

    #[test]
    fn export_sensitive_blob_requires_level() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("baize-root", "low-agent", Level(1), vec!["A"], None).unwrap();

        let mut labels = HashMap::new();
        labels.insert("sensitivity".to_string(), "high".to_string());
        let blob = baize.pipe_blob_write("baize-root", "sensitive data", &labels).unwrap();

        let result = baize.pipe_export("low-agent", &blob.hash);
        assert!(result.is_err());
    }

    #[test]
    fn export_zone_blob_requires_scope() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("baize-root", "agent-a", Level(2), vec!["A"], None).unwrap();

        let mut labels = HashMap::new();
        labels.insert("zone".to_string(), "B".to_string());
        let blob = baize.pipe_blob_write("baize-root", "zone B data", &labels).unwrap();

        let result = baize.pipe_export("agent-a", &blob.hash);
        assert!(result.is_err());
    }

    #[test]
    fn export_sensitive_blob_root_bypass() {
        let baize = Baize::init_in_memory().unwrap();

        let mut labels = HashMap::new();
        labels.insert("sensitivity".to_string(), "high".to_string());
        labels.insert("zone".to_string(), "X".to_string());
        let blob = baize.pipe_blob_write("baize-root", "high sensitivity zone X", &labels).unwrap();

        let exported = baize.pipe_export("baize-root", &blob.hash).unwrap();
        assert_eq!(exported.content, "high sensitivity zone X");
    }

    #[test]
    fn write_nonexistent_agent_returns_user_decision() {
        let baize = Baize::init_in_memory().unwrap();
        let result = baize.pipe_blob_write("ghost-agent", "data", &HashMap::new());
        match result {
            Err(Error::NeedUserDecision(msg)) => {
                assert!(msg.contains("ghost-agent"));
            }
            other => panic!("expected NeedUserDecision, got {:?}", other),
        }
    }

    #[test]
    fn elevation_expired_auto_cleanup() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("baize-root", "worker", Level(2), vec!["A"], None).unwrap();

        let past = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        let mut labels = HashMap::new();
        labels.insert("type".to_string(), "elevation-request".to_string());
        labels.insert("elevation-agent".to_string(), "worker".to_string());
        labels.insert("elevation-zones".to_string(), "[\"A\"]".to_string());
        labels.insert("elevation-mode".to_string(), "readonly".to_string());
        labels.insert("elevation-reason".to_string(), "test".to_string());
        labels.insert("elevation-approved".to_string(), "true".to_string());
        labels.insert("elevation-approver".to_string(), "baize-root".to_string());
        labels.insert("elevation-duration".to_string(), "1h".to_string());
        labels.insert("elevation-expires".to_string(), past);
        let blob = baize.storage.blob_write("expired elevation test", &labels).unwrap();

        baize.elevation_request(
            "worker", vec!["A"], ElevationMode::WriteOnly, "need A again", None,
        ).unwrap();

        let reqs = baize.elevation_list().unwrap();
        let expired_req = reqs.iter().find(|r| r.id == blob.hash).unwrap();
        assert_eq!(expired_req.status, ElevationStatus::Expired);
    }

    #[test]
    fn file_write_and_read() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("baize-root", "writer", Level(2), vec!["A"], None).unwrap();

        let record = baize.pipe_file_write("writer", "A/config.yaml", b"key: value", None).unwrap();
        assert_eq!(record.path, "A/config.yaml");
        assert_eq!(record.size, 10);

        let content = baize.pipe_file_read("writer", "A/config.yaml").unwrap();
        assert_eq!(content.content, b"key: value");
        assert_eq!(content.hash, record.hash);
    }

    #[test]
    fn file_write_creates_blob() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("baize-root", "writer", Level(2), vec!["A"], None).unwrap();

        baize.pipe_file_write("writer", "A/data.txt", b"hello", None).unwrap();

        let mut filter = HashMap::new();
        filter.insert("type".to_string(), "file".to_string());
        filter.insert("path".to_string(), "A/data.txt".to_string());
        let blobs = baize.storage.blob_query(&filter).unwrap();
        assert_eq!(blobs.len(), 1);
        assert_eq!(blobs[0].labels.get("action").unwrap(), "write");
        assert_eq!(blobs[0].labels.get("agent").unwrap(), "writer");
    }

    #[test]
    fn file_delete() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("baize-root", "writer", Level(2), vec!["A"], None).unwrap();

        baize.pipe_file_write("writer", "A/temp.txt", b"temp", None).unwrap();
        baize.pipe_file_delete("writer", "A/temp.txt").unwrap();

        let files = baize.pipe_file_list("writer").unwrap();
        assert!(files.is_empty());
    }

    #[test]
    fn file_delete_records_audit() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("baize-root", "writer", Level(2), vec!["A"], None).unwrap();

        baize.pipe_file_write("writer", "A/del.txt", b"delme", None).unwrap();
        baize.pipe_file_delete("writer", "A/del.txt").unwrap();

        let mut filter = HashMap::new();
        filter.insert("x-audit".to_string(), "true".to_string());
        filter.insert("x-audit-type".to_string(), "file_delete".to_string());
        let audits = baize.storage.blob_query_metadata(&filter).unwrap();
        assert!(!audits.is_empty());
    }

    #[test]
    fn file_zone_check_blocks() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("baize-root", "writer", Level(2), vec!["A"], None).unwrap();

        let result = baize.pipe_file_write("writer", "B/data.txt", b"hack", None);
        assert!(result.is_err());
    }

    #[test]
    fn file_zone_root_accessible() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("baize-root", "writer", Level(2), vec!["A"], None).unwrap();

        let record = baize.pipe_file_write("writer", "readme.txt", b"hello", None).unwrap();
        assert_eq!(record.path, "readme.txt");
    }

    #[test]
    fn file_list() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("baize-root", "writer", Level(2), vec!["A"], None).unwrap();

        baize.pipe_file_write("writer", "A/a.txt", b"a", None).unwrap();
        baize.pipe_file_write("writer", "A/b.txt", b"b", None).unwrap();

        let files = baize.pipe_file_list("writer").unwrap();
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn file_level0_cannot_write() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("baize-root", "sandbox", Level(0), vec!["A"], None).unwrap();

        let result = baize.pipe_file_write("sandbox", "A/data.txt", b"try", None);
        assert!(result.is_err());
    }

    #[test]
    fn push_writes_to_main_repo() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("baize-root", "worker", Level(2), vec!["A"], None).unwrap();

        baize.pipe_file_write("worker", "A/config.yaml", b"key: value", None).unwrap();
        baize.pipe_file_write("worker", "A/data.txt", b"hello", None).unwrap();

        let result = baize.pipe_push("worker", "snapshot 1", None).unwrap();
        assert_eq!(result.files, 2);
        assert!(result.pending);

        let main_config = baize.main_repo.join("A/config.yaml");
        assert!(main_config.exists());
        assert_eq!(std::fs::read(&main_config).unwrap(), b"key: value");
    }

    #[test]
    fn push_empty_workspace_fails() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("baize-root", "worker", Level(2), vec!["A"], None).unwrap();

        let result = baize.pipe_push("worker", "empty", None);
        assert!(result.is_err());
    }

    #[test]
    fn pull_restores_files_from_main_repo() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("baize-root", "worker", Level(2), vec!["A"], None).unwrap();

        baize.pipe_file_write("worker", "A/config.yaml", b"key: value", None).unwrap();
        baize.pipe_push("worker", "v1", None).unwrap();

        baize.workspace_mgr.delete_file("worker", "A/config.yaml").unwrap();
        assert!(baize.pipe_file_list("worker").unwrap().is_empty());

        let result = baize.pipe_pull("worker", None).unwrap();
        assert_eq!(result.files, 1);

        let content = baize.pipe_file_read("worker", "A/config.yaml").unwrap();
        assert_eq!(content.content, b"key: value");
    }

    #[test]
    fn push_creates_auth_blob() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("baize-root", "worker", Level(2), vec!["A"], None).unwrap();

        baize.pipe_file_write("worker", "A/v1.txt", b"version 1", None).unwrap();
        baize.pipe_push("worker", "v1", None).unwrap();

        let mut filter = HashMap::new();
        filter.insert("type".to_string(), "push-auth".to_string());
        let blobs = baize.storage.blob_query(&filter).unwrap();
        assert_eq!(blobs.len(), 1);
        assert!(blobs[0].content.contains("push"));
    }

    #[test]
    fn push_pull_cross_agent() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("baize-root", "alice", Level(2), vec!["A"], None).unwrap();
        baize.agent_register("baize-root", "bob", Level(2), vec!["A"], None).unwrap();

        baize.pipe_file_write("alice", "A/shared.txt", b"from alice", None).unwrap();
        baize.pipe_push("alice", "alice's work", None).unwrap();

        let result = baize.pipe_pull("bob", None).unwrap();
        assert_eq!(result.files, 1);

        let content = baize.pipe_file_read("bob", "A/shared.txt").unwrap();
        assert_eq!(content.content, b"from alice");
    }

    #[test]
    fn pull_empty_main_repo() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("baize-root", "worker", Level(2), vec!["A"], None).unwrap();

        let result = baize.pipe_pull("worker", None).unwrap();
        assert_eq!(result.files, 0);
    }

    #[test]
    fn pull_syncs_from_main_repo() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("baize-root", "worker", Level(2), vec!["A"], None).unwrap();

        baize.pipe_file_write("worker", "A/real.txt", b"real content", None).unwrap();
        baize.pipe_push("worker", "commit 1", None).unwrap();

        baize.workspace_mgr.clear_all("worker").unwrap();

        let result = baize.pipe_pull("worker", None).unwrap();
        assert_eq!(result.files, 1);

        let content = baize.pipe_file_read("worker", "A/real.txt").unwrap();
        assert_eq!(content.content, b"real content");
    }
}
