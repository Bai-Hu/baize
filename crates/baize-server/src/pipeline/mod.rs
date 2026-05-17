use std::collections::HashMap;
use std::path::PathBuf;

use baize_core::cert::{CertIdentity, CertTool};
use baize_core::error::Error;
use baize_core::storage::Storage;
use baize_core::workspace::WorkspaceManager;
use baize_core::ROOT_AGENT_ID;

use crate::hook::HookRegistry;

// 共享宏（必须在子模块声明之前，子模块才能使用）
macro_rules! labels {
    ($($k:expr => $v:expr),* $(,)?) => {{
        let mut m = HashMap::<String, String>::new();
        $(m.insert($k.to_string(), $v.to_string());)*
        m
    }};
}

// 子模块
pub mod agent_manager;
pub mod auditor;
pub mod data_ops;
pub mod elevation;
pub mod file_sync;
pub mod git_ops;

// 重新导出 trait 和类型（方便外部使用）
pub use auditor::Auditor;
pub use agent_manager::{AgentRegistry, PermissionGuard};
pub use data_ops::DataOps;
pub use elevation::ElevationManager;
pub use file_sync::{FileSync, FileRecord, FileContent, PushResult, PullResult};
pub use git_ops::{GitOps, GitCommitInfo, RepoStats};

/// 白泽主控 — 五关口管道核心
pub struct Baize {
    pub storage: Storage,
    pub workspace_mgr: WorkspaceManager,
    /// 主仓库路径：所有 agent 共享的单一数据源目录
    pub(super) main_repo: PathBuf,
    pub(super) hooks: HookRegistry,
    /// agent_id → (CertIdentity, IssuerCtx)
    pub(super) agents: HashMap<String, (CertIdentity, baize_core::cert::IssuerCtx)>,
}

impl Baize {
    /// 初始化白泽：创建存储 + 生成 Root CA
    pub fn init(db_path: &str, ws_base: &str, main_repo: &str) -> Result<Self, Error> {
        let storage = Storage::open(db_path)?;
        let workspace_mgr = WorkspaceManager::new(ws_base)?;

        // 创建主仓库目录 + Git 初始化
        let main_repo_path = PathBuf::from(main_repo);
        std::fs::create_dir_all(&main_repo_path)
            .map_err(|e| Error::Internal(anyhow::anyhow!("failed to create main repo dir: {}", e)))?;
        Self::git_init(&main_repo_path)?;

        // 检查是否已有 root CA
        let mut root_filter = HashMap::new();
        root_filter.insert("type".to_string(), "root-ca".to_string());
        let existing_root = storage.blob_query(&root_filter)?;

        let mut agents = HashMap::new();

        if !existing_root.is_empty() {
            // 已有 root CA：从存储恢复
            let root_cert_pem = &existing_root[0].content;
            let root_identity = CertTool::parse_identity(root_cert_pem)?;

            // 尝试恢复 root key
            let mut key_filter = HashMap::new();
            key_filter.insert("type".to_string(), "agent-key".to_string());
            key_filter.insert("agent-id".to_string(), ROOT_AGENT_ID.to_string());
            let root_keys = storage.blob_query(&key_filter)?;

            if let Some(key_blob) = root_keys.first() {
                let root_ctx = CertTool::recover_issuer(root_cert_pem, &key_blob.content)?;
                agents.insert(ROOT_AGENT_ID.to_string(), (root_identity, root_ctx));
            } else {
                let (root_bundle, root_ctx) = CertTool::generate_root_ca()?;
                let labels = labels! { "type" => "root-ca", "agent-id" => ROOT_AGENT_ID };
                storage.blob_write(&root_bundle.cert_pem, &labels)?;
                let key_labels = labels! { "type" => "agent-key", "agent-id" => ROOT_AGENT_ID };
                storage.blob_write(&root_bundle.key_pem, &key_labels)?;
                agents.insert(ROOT_AGENT_ID.to_string(), (root_bundle.identity, root_ctx));
            }
        } else {
            // 首次初始化
            let (root_bundle, root_ctx) = CertTool::generate_root_ca()?;
            let labels = labels! { "type" => "root-ca", "agent-id" => ROOT_AGENT_ID };
            storage.blob_write(&root_bundle.cert_pem, &labels)?;
            let key_labels = labels! { "type" => "agent-key", "agent-id" => ROOT_AGENT_ID };
            storage.blob_write(&root_bundle.key_pem, &key_labels)?;
            agents.insert(ROOT_AGENT_ID.to_string(), (root_bundle.identity, root_ctx));
        }

        // 恢复所有已注册的 agent
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

            let revoked = storage.label_query("revoked", Some("true"))
                .unwrap_or_default()
                .iter()
                .any(|l| l.entity_hash == cert_blob.hash);
            if revoked {
                continue;
            }

            let identity = CertTool::parse_identity(&cert_blob.content)?;

            let mut akey_filter = HashMap::new();
            akey_filter.insert("type".to_string(), "agent-key".to_string());
            akey_filter.insert("agent-id".to_string(), agent_id.clone());
            let agent_keys = storage.blob_query(&akey_filter)?;

            if let Some(key_blob) = agent_keys.first() {
                if let Ok(agent_ctx) = CertTool::recover_issuer(&cert_blob.content, &key_blob.content) {
                    agents.insert(agent_id, (identity, agent_ctx));
                }
            }
        }

        Ok(Self {
            storage,
            workspace_mgr,
            main_repo: main_repo_path,
            hooks: crate::hook::default_hooks(),
            agents,
        })
    }

    /// 用内存数据库初始化（用于测试）
    pub fn init_in_memory() -> Result<Self, Error> {
        let storage = Storage::open(":memory:")?;
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let tmp_dir = std::env::temp_dir().join(format!("baize-test-{}-{}", std::process::id(), unique));
        let workspace_mgr = WorkspaceManager::new(tmp_dir.to_str().unwrap_or(""))?;

        let main_repo = tmp_dir.join("main");
        std::fs::create_dir_all(&main_repo)
            .map_err(|e| Error::Internal(anyhow::anyhow!("failed to create test main repo: {}", e)))?;
        Self::git_init(&main_repo)?;

        let (root_bundle, root_ctx) = CertTool::generate_root_ca()?;

        let labels = labels! { "type" => "root-ca", "agent-id" => ROOT_AGENT_ID };
        storage.blob_write(&root_bundle.cert_pem, &labels)?;
        let key_labels = labels! { "type" => "agent-key", "agent-id" => ROOT_AGENT_ID };
        storage.blob_write(&root_bundle.key_pem, &key_labels)?;

        let root_identity = root_bundle.identity;
        let mut agents = HashMap::new();
        agents.insert(ROOT_AGENT_ID.to_string(), (root_identity, root_ctx));

        Ok(Self {
            storage,
            workspace_mgr,
            main_repo,
            hooks: crate::hook::default_hooks(),
            agents,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let (id, bundle) = baize.agent_register(
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
        baize.agent_register("parent", Level(3), vec!["A", "B", "C"], None).unwrap();

        let (id, bundle) = baize.agent_register(
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
        baize.agent_register("agent-001", Level(2), vec!["A"], None).unwrap();
        baize.agent_revoke("agent-001").unwrap();
        assert_eq!(baize.agent_list().len(), 1);
    }

    #[test]
    fn revoke_root_fails() {
        let mut baize = Baize::init_in_memory().unwrap();
        let result = baize.agent_revoke("baize-root");
        assert!(result.is_err());
    }

    #[test]
    fn elevation_flow() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("agent-001", Level(3), vec!["A", "B", "C"], None).unwrap();

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
        baize.agent_register("agent-001", Level(2), vec!["A"], None).unwrap();

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
        baize.agent_register("parent", Level(3), vec!["A", "B"], None).unwrap();
        baize.agent_register("child", Level(2), vec!["A"], Some("parent")).unwrap();

        let chain = baize.trace_identity("child").unwrap();
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].agent_id, "child");
        assert_eq!(chain[1].agent_id, "parent");
        assert_eq!(chain[2].agent_id, "baize-root");
    }

    #[test]
    fn scope_exceed_fails() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("parent", Level(2), vec!["A"], None).unwrap();

        let result = baize.agent_register("child", Level(3), vec!["A"], Some("parent"));
        assert!(result.is_err());
    }

    #[test]
    fn agent_register_duplicate_fails() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("dup", Level(2), vec!["A"], None).unwrap();
        let result = baize.agent_register("dup", Level(2), vec!["A"], None);
        assert!(result.is_err());
    }

    #[test]
    fn agent_revoke_nonexistent() {
        let mut baize = Baize::init_in_memory().unwrap();
        let result = baize.agent_revoke("no-such-agent");
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
        baize.agent_register("agent-001", Level(3), vec!["A", "B", "C"], None).unwrap();

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
        baize.agent_register("agent-001", Level(3), vec!["A", "B"], None).unwrap();

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
        baize.agent_register("agent-001", Level(3), vec!["A"], None).unwrap();

        let req_id = baize.elevation_request(
            "agent-001", vec!["A"], ElevationMode::ReadOnly, "test", Some("1h"),
        ).unwrap();

        baize.elevation_approve(&req_id, "baize-root").unwrap();

        let past = chrono::Utc::now() - chrono::Duration::hours(1);
        let past_str = past.to_rfc3339();

        let _blob = baize.storage.blob_read(&req_id).unwrap();

        let mut baize2 = Baize::init_in_memory().unwrap();
        baize2.agent_register("w", Level(3), vec!["A"], None).unwrap();

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
        baize.agent_register("parent", Level(3), vec!["A", "B", "C"], None).unwrap();
        baize.agent_register("child", Level(2), vec!["A"], Some("parent")).unwrap();

        let req_id = baize.elevation_request(
            "child", vec!["A"], ElevationMode::ReadOnly, "need A", None,
        ).unwrap();

        baize.elevation_approve(&req_id, "parent").unwrap();
    }

    #[test]
    fn approval_routing_parent_cannot_approve_beyond_scope() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("parent", Level(3), vec!["A", "B"], None).unwrap();
        baize.agent_register("child", Level(2), vec!["A"], Some("parent")).unwrap();

        let req_id = baize.elevation_request(
            "child", vec!["Z"], ElevationMode::ReadOnly, "need Z", None,
        ).unwrap();

        let result = baize.elevation_approve(&req_id, "parent");
        assert!(result.is_err());
    }

    #[test]
    fn approval_routing_root_can_approve_anything() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("parent", Level(3), vec!["A", "B"], None).unwrap();
        baize.agent_register("child", Level(2), vec!["A"], Some("parent")).unwrap();

        let req_id = baize.elevation_request(
            "child", vec!["Z"], ElevationMode::ReadOnly, "need Z", None,
        ).unwrap();

        baize.elevation_approve(&req_id, "baize-root").unwrap();
    }

    #[test]
    fn approval_routing_non_parent_cannot_approve() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("agent-a", Level(3), vec!["A"], None).unwrap();
        baize.agent_register("agent-b", Level(3), vec!["B"], None).unwrap();

        let req_id = baize.elevation_request(
            "agent-a", vec!["A"], ElevationMode::ReadOnly, "test", None,
        ).unwrap();

        let result = baize.elevation_approve(&req_id, "agent-b");
        assert!(result.is_err());
    }

    #[test]
    fn elevation_return_success() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("worker", Level(2), vec!["A"], None).unwrap();

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
        baize.agent_register("worker", Level(2), vec!["A"], None).unwrap();

        let req_id = baize.elevation_request(
            "worker", vec!["A"], ElevationMode::ReadOnly, "need A", None,
        ).unwrap();

        let result = baize.elevation_return(&req_id, "worker", "worker");
        assert!(result.is_err());
    }

    #[test]
    fn elevation_return_already_returned_fails() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("worker", Level(2), vec!["A"], None).unwrap();

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
        baize.agent_register("worker", Level(2), vec!["A"], None).unwrap();
        baize.agent_register("other", Level(2), vec!["B"], None).unwrap();

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
        baize.agent_register("reader", Level(0), vec![], None).unwrap();

        let blob = baize.pipe_blob_write("baize-root", "plain data", &HashMap::new()).unwrap();

        let exported = baize.pipe_export("reader", &blob.hash).unwrap();
        assert_eq!(exported.content, "plain data");
    }

    #[test]
    fn export_sensitive_blob_requires_level() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("low-agent", Level(1), vec!["A"], None).unwrap();

        let mut labels = HashMap::new();
        labels.insert("sensitivity".to_string(), "high".to_string());
        let blob = baize.pipe_blob_write("baize-root", "sensitive data", &labels).unwrap();

        let result = baize.pipe_export("low-agent", &blob.hash);
        assert!(result.is_err());
    }

    #[test]
    fn export_zone_blob_requires_scope() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("agent-a", Level(2), vec!["A"], None).unwrap();

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
        baize.agent_register("worker", Level(2), vec!["A"], None).unwrap();

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
        baize.agent_register("writer", Level(2), vec!["A"], None).unwrap();

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
        baize.agent_register("writer", Level(2), vec!["A"], None).unwrap();

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
        baize.agent_register("writer", Level(2), vec!["A"], None).unwrap();

        baize.pipe_file_write("writer", "A/temp.txt", b"temp", None).unwrap();
        baize.pipe_file_delete("writer", "A/temp.txt").unwrap();

        let files = baize.pipe_file_list("writer").unwrap();
        assert!(files.is_empty());
    }

    #[test]
    fn file_delete_records_audit() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("writer", Level(2), vec!["A"], None).unwrap();

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
        baize.agent_register("writer", Level(2), vec!["A"], None).unwrap();

        let result = baize.pipe_file_write("writer", "B/data.txt", b"hack", None);
        assert!(result.is_err());
    }

    #[test]
    fn file_zone_root_accessible() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("writer", Level(2), vec!["A"], None).unwrap();

        let record = baize.pipe_file_write("writer", "readme.txt", b"hello", None).unwrap();
        assert_eq!(record.path, "readme.txt");
    }

    #[test]
    fn file_list() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("writer", Level(2), vec!["A"], None).unwrap();

        baize.pipe_file_write("writer", "A/a.txt", b"a", None).unwrap();
        baize.pipe_file_write("writer", "A/b.txt", b"b", None).unwrap();

        let files = baize.pipe_file_list("writer").unwrap();
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn file_level0_cannot_write() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("sandbox", Level(0), vec!["A"], None).unwrap();

        let result = baize.pipe_file_write("sandbox", "A/data.txt", b"try", None);
        assert!(result.is_err());
    }

    #[test]
    fn push_writes_to_main_repo() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("worker", Level(2), vec!["A"], None).unwrap();

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
        baize.agent_register("worker", Level(2), vec!["A"], None).unwrap();

        let result = baize.pipe_push("worker", "empty", None);
        assert!(result.is_err());
    }

    #[test]
    fn pull_restores_files_from_main_repo() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("worker", Level(2), vec!["A"], None).unwrap();

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
        baize.agent_register("worker", Level(2), vec!["A"], None).unwrap();

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
        baize.agent_register("alice", Level(2), vec!["A"], None).unwrap();
        baize.agent_register("bob", Level(2), vec!["A"], None).unwrap();

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
        baize.agent_register("worker", Level(2), vec!["A"], None).unwrap();

        let result = baize.pipe_pull("worker", None).unwrap();
        assert_eq!(result.files, 0);
    }

    #[test]
    fn pull_syncs_from_main_repo() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("worker", Level(2), vec!["A"], None).unwrap();

        baize.pipe_file_write("worker", "A/real.txt", b"real content", None).unwrap();
        baize.pipe_push("worker", "commit 1", None).unwrap();

        baize.workspace_mgr.clear_all("worker").unwrap();

        let result = baize.pipe_pull("worker", None).unwrap();
        assert_eq!(result.files, 1);

        let content = baize.pipe_file_read("worker", "A/real.txt").unwrap();
        assert_eq!(content.content, b"real content");
    }
}
