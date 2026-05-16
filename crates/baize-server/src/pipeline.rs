use std::collections::HashMap;
use std::path::PathBuf;

use baize_core::cert::{CertBundle, CertIdentity, CertTool, IssuerCtx};
use baize_core::error::Error;
use baize_core::scope::{ElevationMode, ElevationRequest, ElevationStatus, Level, Scope};
use baize_core::ROOT_AGENT_ID;
use baize_core::storage::Storage;
use baize_core::workspace::WorkspaceManager;
use sha2::{Digest, Sha256};

use crate::hook::{HookRegistry, HookContext};

/// 白泽主控 — 五关口管道核心
pub struct Baize {
    pub storage: Storage,
    pub workspace_mgr: WorkspaceManager,
    /// 主仓库路径：所有 agent 共享的单一数据源目录
    main_repo: PathBuf,
    hooks: HookRegistry,
    /// agent_id → (CertIdentity, IssuerCtx)
    agents: HashMap<String, (CertIdentity, IssuerCtx)>,
}

macro_rules! labels {
    ($($k:expr => $v:expr),* $(,)?) => {{
        let mut m = HashMap::<String, String>::new();
        $(m.insert($k.to_string(), $v.to_string());)*
        m
    }};
}

impl Baize {
    /// 初始化白泽：创建存储 + 生成 Root CA
    pub fn init(db_path: &str, ws_base: &str, main_repo: &str) -> Result<Self, Error> {
        let storage = Storage::open(db_path)?;
        let workspace_mgr = WorkspaceManager::new(ws_base)?;

        // 创建主仓库目录
        let main_repo_path = PathBuf::from(main_repo);
        std::fs::create_dir_all(&main_repo_path)
            .map_err(|e| Error::Internal(anyhow::anyhow!("failed to create main repo dir: {}", e)))?;

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
                // 无 key，只有 identity，无签发能力
                // 重新生成以保留签发能力（会使旧证书链失效）
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

            // 跳过已撤销的 agent（检查通用 labels 表）
            let revoked = storage.label_query("revoked", Some("true"))
                .unwrap_or_default()
                .iter()
                .any(|l| l.entity_hash == cert_blob.hash);
            if revoked {
                continue;
            }

            let identity = CertTool::parse_identity(&cert_blob.content)?;

            // 尝试恢复 agent key + IssuerCtx
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
    /// 每次调用创建独立的临时目录，确保测试之间互不干扰
    pub fn init_in_memory() -> Result<Self, Error> {
        let storage = Storage::open(":memory:")?;
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let tmp_dir = std::env::temp_dir().join(format!("baize-test-{}-{}", std::process::id(), unique));
        let workspace_mgr = WorkspaceManager::new(tmp_dir.to_str().unwrap_or(""))?;

        // 测试用主仓库（临时目录下的 main 子目录）
        let main_repo = tmp_dir.join("main");
        std::fs::create_dir_all(&main_repo)
            .map_err(|e| Error::Internal(anyhow::anyhow!("failed to create test main repo: {}", e)))?;

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

    // ─── Agent 管理 ───

    /// 注册 Agent
    pub fn agent_register(
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

        // 存储 agent 私钥（用于跨重启恢复 IssuerCtx）
        // 安全风险：私钥以明文存储在 SQLite 中，任何有数据库读权限的人可获取。
        // 生产环境应使用 KMS 或加密存储。MVP 阶段暂时接受此风险。
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

    /// 撤销 Agent
    pub fn agent_revoke(&mut self, agent_id: &str) -> Result<(), Error> {
        if !self.agents.contains_key(agent_id) {
            return Err(Error::NotFound(format!("agent {}", agent_id)));
        }
        if agent_id == ROOT_AGENT_ID {
            return Err(Error::PermissionDenied("cannot revoke root".into()));
        }

        // 销毁 workspace
        self.workspace_mgr.destroy(agent_id)?;

        // 标记证书为已撤销（持久化到存储）
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

    /// 列出所有 Agent
    pub fn agent_list(&self) -> Vec<(String, CertIdentity)> {
        self.agents.iter()
            .map(|(id, (identity, _))| (id.clone(), identity.clone()))
            .collect()
    }

    // ─── Scope Elevation ───

    /// 申请借权
    /// 借权请求用 blob + label 存储：
    ///   blob 内容 = 借权申请 JSON（含时间戳，确保每次请求唯一）
    ///   labels 包含 type=elevation-request, elevation-agent 等（权威数据源，查询走 labels）
    ///   审批前：无 elevation-approved 标签 → Pending
    ///   审批后：追加 elevation-approved=true → Approved
    ///   注意：blob 内容与 labels 存在冗余（agent/zones/mode/reason），
    ///         labels 是查询和展示的权威数据源，内容仅用于生成唯一 hash。
    pub fn elevation_request(
        &mut self,
        agent_id: &str,
        zones: Vec<&str>,
        mode: ElevationMode,
        reason: &str,
        duration: Option<&str>,
    ) -> Result<String, Error> {
        // 主动清理已过期的借权
        let _ = self.elevation_cleanup_expired();

        // 验证 agent 存在（zone 限制在 P1-1 修复，当前暂不限制）
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

        // 借权申请 blob（含时间戳，确保相同参数的重复请求产生不同 hash）
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
            // 验证 duration 格式（过期时间在审批时计算）
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

    /// 审批借权
    /// 审批路由：baize-root 可批任何请求；parent agent 可批 scope 内请求
    /// 通过 label_add 追加 elevation-approved=true（append-only，历史保留）
    /// 重复审批会因 label PRIMARY KEY 冲突而失败
    pub fn elevation_approve(&mut self, request_hash: &str, approver: &str) -> Result<(), Error> {
        // 读取借权请求 blob
        let blob = self.storage.blob_read(request_hash)?;

        // 检查是否已审批
        if blob.labels.contains_key("elevation-approved") {
            return Err(Error::Validation("request already approved".into()));
        }

        // 检查是否已归还/撤销
        if let Some(status) = blob.labels.get("elevation-status") {
            if status == "Returned" || status == "Revoked" {
                return Err(Error::Validation(
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

    /// 审批权限校验：baize-root 可批任何请求；parent agent 只能批 scope 内请求
    fn validate_approver(
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

    /// 归还借权：清理 workspace 中超出 scope 的文件，标记为 Returned
    pub fn elevation_return(
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

    /// 主动清理已过期的借权：标记为 Expired + 清理 workspace
    fn elevation_cleanup_expired(&self) -> Result<usize, Error> {
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

    /// 列出借权请求
    /// 通过 blob_query 查询 type=elevation-request 的 blob
    pub fn elevation_list(&self) -> Result<Vec<ElevationRequest>, Error> {
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

            // 检查是否已被审批（有 elevation-approved label）
            let mut status = if blob.labels.contains_key("elevation-approved") {
                ElevationStatus::Approved
            } else {
                ElevationStatus::Pending
            };

            // Lazy expiry: 已审批且有过期时间，检查是否过期
            if status == ElevationStatus::Approved {
                if let Some(expires_str) = blob.labels.get("elevation-expires") {
                    if let Ok(expires) = expires_str.parse::<chrono::DateTime<chrono::Utc>>() {
                        if chrono::Utc::now() > expires {
                            status = ElevationStatus::Expired;
                        }
                    }
                }
            }

            // 检查显式状态覆盖（Returned / Revoked）
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

    // ─── 审计 ───

    /// 写入审计记录
    /// target: 操作对象标识（如 blob hash、agent id、file path），可为空
    pub fn audit(&self, audit_type: &str, agent_id: &str, result: &str, target: Option<&str>) -> Result<(), Error> {
        let seq = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        let mut labels = labels! {
            "x-audit" => "true",
            "x-audit-type" => audit_type,
            "x-audit-agent" => agent_id,
            "x-audit-result" => result,
            "x-audit-time" => &chrono::Utc::now().to_rfc3339(),
            "x-audit-seq" => &seq.to_string(),
        };
        if let Some(t) = target {
            labels.insert("x-audit-target".to_string(), t.to_string());
        }

        let mut content = serde_json::json!({
            "type": audit_type,
            "agent": agent_id,
            "result": result,
            "seq": seq,
        });
        if let Some(t) = target {
            content["target"] = serde_json::Value::String(t.to_string());
        }

        self.storage.blob_write(&content.to_string(), &labels)?;
        Ok(())
    }

    // ─── 泽图操作（经管道） ───
    // 设计说明：agent_register 走完整 HookRegistry（pre/post-hook），
    // pipe_* 方法直接在内部完成 验身份→查权限→执行→留痕 四步，
    // 不经过 HookRegistry。后续统一时可将 pipe_* 的权限检查迁移到 hook 中。

    /// 验证 agent 身份 + 检查写权限
    /// 三层决策：
    ///   Level >= 1 → 自主决策（直接执行）
    ///   Level == 0 → 返回 PermissionDenied（需要 elevation 到 Level >= 1）
    ///   agent 不存在 → 返回 NotFound（需要用户干预）
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

    /// 验证 agent 身份（读操作：只检查 agent 存在，不限制 level）
    fn verify_read_agent(&self, agent_id: &str) -> Result<CertIdentity, Error> {
        let (identity, _) = self.agents.get(agent_id)
            .ok_or_else(|| Error::NeedUserDecision(
                format!("agent '{}' not found. Register the agent first.", agent_id)
            ))?;
        Ok(identity.clone())
    }

    /// 管道：blob 写入
    pub fn pipe_blob_write(
        &self,
        agent_id: &str,
        content: &str,
        labels: &HashMap<String, String>,
    ) -> Result<baize_core::storage::Blob, Error> {
        // 1. 验身份 + 查权限
        self.verify_write_agent(agent_id)?;

        // 2. 执行
        let blob = self.storage.blob_write(content, labels)?;

        // 3. 留痕
        self.audit("blob_write", agent_id, "success", Some(&blob.hash))?;

        Ok(blob)
    }

    /// 管道：commit 创建
    pub fn pipe_commit_create(
        &self,
        agent_id: &str,
        blob_hashes: &[String],
        message: &str,
        parent_hash: Option<&str>,
    ) -> Result<baize_core::storage::Commit, Error> {
        self.verify_write_agent(agent_id)?;

        let commit = self.storage.commit_create(blob_hashes, message, parent_hash, Some(agent_id), &HashMap::new())?;

        self.audit("commit_create", agent_id, "success", Some(&commit.hash))?;

        Ok(commit)
    }

    /// 管道：label 追加
    pub fn pipe_label_add(
        &self,
        agent_id: &str,
        entity_hash: &str,
        key: &str,
        value: &str,
    ) -> Result<(), Error> {
        self.verify_write_agent(agent_id)?;

        self.storage.label_add(entity_hash, key, value)?;

        self.audit("label_add", agent_id, "success", Some(entity_hash))?;

        Ok(())
    }

    /// 管道：ref 设置
    pub fn pipe_ref_set(
        &self,
        agent_id: &str,
        name: &str,
        commit_hash: &str,
    ) -> Result<(), Error> {
        self.verify_write_agent(agent_id)?;

        self.storage.ref_set(name, commit_hash)?;

        self.audit("ref_set", agent_id, "success", Some(name))?;

        Ok(())
    }

    /// 管道：ref 删除
    pub fn pipe_ref_delete(&self, agent_id: &str, name: &str) -> Result<(), Error> {
        self.verify_write_agent(agent_id)?;

        self.storage.ref_delete(name)?;

        self.audit("ref_delete", agent_id, "success", Some(name))?;

        Ok(())
    }

    /// 管道：数据导入
    pub fn pipe_import(
        &self,
        agent_id: &str,
        content: &str,
        source: &str,
        trust_level: u8,
        extra_labels: Option<HashMap<String, String>>,
    ) -> Result<baize_core::storage::Blob, Error> {
        self.verify_write_agent(agent_id)?;

        let mut labels = extra_labels.unwrap_or_default();
        labels.insert("source".to_string(), source.to_string());
        labels.insert("trust-level".to_string(), trust_level.to_string());
        labels.insert("imported".to_string(), "true".to_string());

        if trust_level == 0 {
            labels.insert("sandbox".to_string(), "true".to_string());
        }

        let blob = self.storage.blob_write(content, &labels)?;

        self.audit("import", agent_id, "success", Some(&blob.hash))?;

        Ok(blob)
    }

    /// 管道：数据导出（读操作，验证 agent 身份 + sensitivity/zone 检查）
    pub fn pipe_export(
        &self,
        agent_id: &str,
        hash: &str,
    ) -> Result<baize_core::storage::Blob, Error> {
        let identity = self.verify_read_agent(agent_id)?;

        let blob = self.storage.blob_read(hash)?;

        // 敏感标签检查
        if let Some(sensitivity) = blob.labels.get("sensitivity") {
            let required_level = match sensitivity.as_str() {
                "high" => 3,
                "medium" => 2,
                "low" => 1,
                _ => 0,
            };
            if identity.level < required_level {
                return Err(Error::PermissionDenied(
                    format!("export requires level {} for sensitivity '{}', agent {} is level {}",
                        required_level, sensitivity, agent_id, identity.level)
                ));
            }
        }

        // Zone 检查：blob 有 zone label 且 agent scope 非通配
        if let Some(blob_zone) = blob.labels.get("zone") {
            if !identity.zones.iter().any(|z| z == "*")
                && !identity.zones.contains(blob_zone)
            {
                return Err(Error::PermissionDenied(
                    format!("agent {} scope {:?} does not cover zone '{}'",
                        agent_id, identity.zones, blob_zone)
                ));
            }
        }

        self.audit("export", agent_id, "success", Some(hash))?;

        Ok(blob)
    }

    // ─── 追溯查询 ───

    /// 数据链追溯：
    /// - 给定 commit hash → 沿 parent 链追溯
    /// - 给定 blob hash → 找到包含它的 commit，再沿 parent 链追溯
    pub fn trace_data(&self, hash: &str) -> Result<Vec<baize_core::storage::Commit>, Error> {
        // 先尝试作为 commit hash
        if let Ok(commit) = self.storage.commit_read(hash) {
            let mut chain = vec![commit];
            let mut current = chain[0].parent_hash.clone();
            while let Some(parent_hash) = current {
                let parent = self.storage.commit_read(&parent_hash)?;
                current = parent.parent_hash.clone();
                chain.push(parent);
            }
            return Ok(chain);
        }

        // 再尝试作为 blob hash → 找包含它的 commit → 追溯 commit 链
        let commit_hashes = self.storage.commits_containing_blob(hash)?;
        if commit_hashes.is_empty() {
            return Err(Error::NotFound(format!("commit or blob {}", hash)));
        }

        // 取最近的 commit（第一个）向上追溯
        let commit = self.storage.commit_read(&commit_hashes[0])?;
        let mut chain = vec![commit];
        let mut current = chain[0].parent_hash.clone();
        while let Some(parent_hash) = current {
            let parent = self.storage.commit_read(&parent_hash)?;
            current = parent.parent_hash.clone();
            chain.push(parent);
        }
        Ok(chain)
    }

    /// 身份链追溯：沿证书 parent_id 追溯
    pub fn trace_identity(&self, agent_id: &str) -> Result<Vec<CertIdentity>, Error> {
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

    // ─── 文件操作（网关代理） ───

    /// 管道：文件写入
    pub fn pipe_file_write(
        &self,
        agent_id: &str,
        path: &str,
        content: &[u8],
        labels: Option<HashMap<String, String>>,
    ) -> Result<FileRecord, Error> {
        let identity = self.verify_write_agent(agent_id)?;
        self.verify_file_zone(&identity, path)?;

        self.workspace_mgr.write_file(agent_id, path, content)?;

        let hash = sha256_hex(content);

        let mut file_labels = labels.unwrap_or_default();
        file_labels.insert("type".into(), "file".into());
        file_labels.insert("path".into(), path.into());
        file_labels.insert("action".into(), "write".into());
        file_labels.insert("agent".into(), agent_id.into());
        file_labels.insert("content-hash".into(), hash.clone());
        self.storage.blob_write(&hash, &file_labels)?;

        self.audit("file_write", agent_id, &format!("success path={}", path), Some(path))?;

        Ok(FileRecord {
            path: path.to_string(),
            hash,
            size: content.len(),
        })
    }

    /// 管道：文件读取
    pub fn pipe_file_read(
        &self,
        agent_id: &str,
        path: &str,
    ) -> Result<FileContent, Error> {
        let identity = self.verify_read_agent(agent_id)?;
        self.verify_file_zone(&identity, path)?;

        // Overlay read：workspace 优先 → 主仓库 fallback
        let content = match self.workspace_mgr.read_file(agent_id, path) {
            Ok(c) => {
                self.audit("file_read", agent_id, &format!("success path={} source=workspace", path), Some(path))?;
                c
            }
            Err(_) => {
                // workspace 中没有，尝试从主仓库读取
                let main_path = self.main_repo.join(path);
                let c = std::fs::read(&main_path)
                    .map_err(|e| Error::NotFound(
                        format!("file not found in workspace or main repo: {} ({})", path, e)
                    ))?;
                self.audit("file_read", agent_id, &format!("success path={} source=main-repo", path), Some(path))?;
                c
            }
        };

        let hash = sha256_hex(&content);
        let size = content.len();

        Ok(FileContent {
            path: path.to_string(),
            content,
            hash,
            size,
        })
    }

    /// 管道：文件删除
    pub fn pipe_file_delete(
        &self,
        agent_id: &str,
        path: &str,
    ) -> Result<(), Error> {
        let identity = self.verify_write_agent(agent_id)?;
        self.verify_file_zone(&identity, path)?;

        let hash = self.workspace_mgr.file_hash(agent_id, path).ok();
        self.workspace_mgr.delete_file(agent_id, path)?;

        let mut del_labels = labels! {
            "type" => "file",
            "path" => path,
            "action" => "delete",
            "agent" => agent_id,
        };
        if let Some(h) = hash {
            del_labels.insert("content-hash".into(), h);
        }
        let del_content = format!("delete:{}:{}", path, chrono::Utc::now().to_rfc3339());
        self.storage.blob_write(&del_content, &del_labels)?;

        self.audit("file_delete", agent_id, &format!("success path={}", path), Some(path))?;

        Ok(())
    }

    /// 管道：列出文件
    pub fn pipe_file_list(
        &self,
        agent_id: &str,
    ) -> Result<Vec<String>, Error> {
        self.verify_read_agent(agent_id)?;
        let files = self.workspace_mgr.list_files(agent_id)?;
        self.audit("file_list", agent_id, "success", None)?;
        Ok(files)
    }

    // ─── Push / Pull ───

    /// Push：workspace 快照 → commit 链 + 同步到主仓库
    /// 遍历 agent workspace 所有文件，每个文件写 blob，汇总为一个 commit，更新 ref，
    /// 然后将文件同步到主仓库目录。
    pub fn pipe_push(
        &self,
        agent_id: &str,
        message: &str,
        ref_name: Option<&str>,
    ) -> Result<PushResult, Error> {
        let identity = self.verify_write_agent(agent_id)?;

        // Zone 检查所有文件
        let files = self.workspace_mgr.list_files(agent_id)?;
        if files.is_empty() {
            return Err(Error::Validation("workspace is empty, nothing to push".into()));
        }
        for path in &files {
            self.verify_file_zone(&identity, path)?;
        }

        // 每个文件写 blob（带 path/type/agent/content-hash labels）
        let mut blob_hashes = Vec::new();
        for path in &files {
            let content = self.workspace_mgr.read_file(agent_id, path)?;
            let content_hash = sha256_hex(&content);
            let content_str = String::from_utf8_lossy(&content).to_string();

            let mut labels = HashMap::new();
            labels.insert("type".into(), "file".into());
            labels.insert("path".into(), path.clone());
            labels.insert("agent".into(), agent_id.into());
            labels.insert("content-hash".into(), content_hash);

            let blob = self.storage.blob_write(&content_str, &labels)?;
            blob_hashes.push(blob.hash);
        }

        // 确定 parent：如果 ref 已存在，用它指向的 commit 作为 parent
        let ref_name = ref_name.unwrap_or("HEAD");
        let parent_hash = self.storage.ref_get(ref_name)
            .ok()
            .map(|r| r.commit_hash);

        // 创建 commit
        let commit = self.storage.commit_create(
            &blob_hashes,
            message,
            parent_hash.as_deref(),
            Some(agent_id),
            &HashMap::new(),
        )?;

        // 更新 ref
        self.storage.ref_set(ref_name, &commit.hash)?;

        // 同步文件到主仓库
        for path in &files {
            let content = self.workspace_mgr.read_file(agent_id, path)?;
            let dest = self.main_repo.join(path);
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| Error::Internal(
                        anyhow::anyhow!("failed to create main repo dir for {}: {}", path, e)
                    ))?;
            }
            std::fs::write(&dest, &content)
                .map_err(|e| Error::Internal(
                    anyhow::anyhow!("failed to write to main repo {}: {}", path, e)
                ))?;
        }

        self.audit("push", agent_id, &format!("success files={} ref={}", files.len(), ref_name), Some(&ref_name))?;

        Ok(PushResult {
            commit_hash: commit.hash,
            files: files.len(),
            ref_name: ref_name.to_string(),
        })
    }

    /// Pull：主仓库 → workspace
    /// 清空 workspace 后从主仓库目录复制所有文件到 workspace。
    /// 仍需记录 commit 信息（通过 ref），但数据来源是主仓库而非 commit blob。
    pub fn pipe_pull(
        &self,
        agent_id: &str,
        ref_name: Option<&str>,
    ) -> Result<PullResult, Error> {
        let identity = self.verify_write_agent(agent_id)?;

        let ref_name = ref_name.unwrap_or("HEAD");
        let r = self.storage.ref_get(ref_name)
            .map_err(|_| Error::NotFound(format!("ref {}", ref_name)))?;

        let commit = self.storage.commit_read(&r.commit_hash)?;

        // 清空 workspace
        self.workspace_mgr.clear_all(agent_id)?;

        // 从主仓库目录遍历并复制文件到 workspace
        let mut files_written = 0;
        self.sync_main_repo_to_workspace(agent_id, &identity, &mut files_written)?;

        self.audit("pull", agent_id, &format!("success files={} from ref={}", files_written, ref_name), Some(&ref_name))?;

        Ok(PullResult {
            ref_name: ref_name.to_string(),
            commit_hash: commit.hash,
            files: files_written,
        })
    }

    /// 递归遍历主仓库目录，将所有文件同步到 agent workspace
    fn sync_main_repo_to_workspace(
        &self,
        agent_id: &str,
        identity: &CertIdentity,
        count: &mut usize,
    ) -> Result<(), Error> {
        let mut stack = vec![self.main_repo.clone()];
        while let Some(dir) = stack.pop() {
            let entries = std::fs::read_dir(&dir)
                .map_err(|e| Error::Internal(anyhow::anyhow!("failed to read main repo dir {:?}: {}", dir, e)))?;
            for entry in entries {
                let entry = entry.map_err(|e| Error::Internal(anyhow::anyhow!("failed to read dir entry: {}", e)))?;
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    // 计算相对路径
                    let rel = path.strip_prefix(&self.main_repo)
                        .map_err(|e| Error::Internal(anyhow::anyhow!("path prefix error: {}", e)))?;
                    let rel_str = rel.to_str()
                        .ok_or_else(|| Error::Internal(anyhow::anyhow!("invalid path encoding: {:?}", rel)))?;

                    // Zone 权限检查
                    self.verify_file_zone(identity, rel_str)?;

                    let content = std::fs::read(&path)
                        .map_err(|e| Error::Internal(anyhow::anyhow!("failed to read main repo file {}: {}", rel_str, e)))?;
                    self.workspace_mgr.write_file(agent_id, rel_str, &content)?;
                    *count += 1;
                }
            }
        }
        Ok(())
    }

    /// Zone 检查：路径首段必须在 agent scope 内
    fn verify_file_zone(&self, identity: &CertIdentity, path: &str) -> Result<(), Error> {
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

/// 文件操作记录
pub struct FileRecord {
    pub path: String,
    pub hash: String,
    pub size: usize,
}

/// 文件读取内容
pub struct FileContent {
    pub path: String,
    pub content: Vec<u8>,
    pub hash: String,
    pub size: usize,
}

/// Push 结果
pub struct PushResult {
    pub commit_hash: String,
    pub files: usize,
    pub ref_name: String,
}

/// Pull 结果
pub struct PullResult {
    pub ref_name: String,
    pub commit_hash: String,
    pub files: usize,
}

/// SHA-256 hex 辅助
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(baize.agent_list().len(), 1); // only root left
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
        // P1-1: 借权允许申请超出自己 scope 的 zone（需审批）
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("agent-001", Level(2), vec!["A"], None).unwrap();

        // agent-001 只有 zone A，但可以申请 zone B（超出 scope）
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
        assert_eq!(chain.len(), 3); // child → parent → root
        assert_eq!(chain[0].agent_id, "child");
        assert_eq!(chain[1].agent_id, "parent");
        assert_eq!(chain[2].agent_id, "baize-root");
    }

    #[test]
    fn scope_exceed_fails() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("parent", Level(2), vec!["A"], None).unwrap();

        // child level 3 > parent level 2
        let result = baize.agent_register("child", Level(3), vec!["A"], Some("parent"));
        assert!(result.is_err());
    }

    #[test]
    fn agent_register_duplicate_fails() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("dup", Level(2), vec!["A"], None).unwrap();
        // 同名注册应该失败（证书已存在）
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
        // 同一 agent、同一操作类型、同一结果：两次审计必须产生两条独立记录
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
    fn trace_data_chain() {
        let baize = Baize::init_in_memory().unwrap();
        let b1 = baize.storage.blob_write("data1", &HashMap::new()).unwrap();
        let c1 = baize.storage.commit_create(&[b1.hash.clone()], "first", None, None, &HashMap::new()).unwrap();
        let b2 = baize.storage.blob_write("data2", &HashMap::new()).unwrap();
        let _c2 = baize.storage.commit_create(&[b2.hash.clone()], "second", Some(&c1.hash), None, &HashMap::new()).unwrap();

        let chain = baize.trace_data(&c1.hash).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].message, "first");
    }

    #[test]
    fn trace_data_nonexistent() {
        let baize = Baize::init_in_memory().unwrap();
        let result = baize.trace_data("deadbeef");
        assert!(result.is_err());
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
        // 再次审批应失败
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

    // ─── 审批路由 + Duration + Expiry 测试 ───

    #[test]
    fn elevation_with_duration() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("agent-001", Level(3), vec!["A", "B"], None).unwrap();

        let req_id = baize.elevation_request(
            "agent-001", vec!["A"], ElevationMode::ReadOnly, "test", Some("30m"),
        ).unwrap();

        baize.elevation_approve(&req_id, "baize-root").unwrap();

        // 验证 elevation-expires label 存在
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

        // 手动设置过期时间为过去
        let past = chrono::Utc::now() - chrono::Duration::hours(1);
        // 删除旧 expires label 再加新的（label_add 会拒绝重复 key）
        // 直接用 storage 重写 blob（通过 label_add 跳过，这里用更简单的方式）
        // 由于 label_add 会冲突，我们用一个测试辅助：创建一个新的过期的 elevation blob
        let _blob = baize.storage.blob_read(&req_id).unwrap();
        let past_str = past.to_rfc3339();

        // 通过 storage 直接操作：先删除再插入
        // 但我们没有 delete label API，所以测试一个新创建的过期请求
        let mut baize2 = Baize::init_in_memory().unwrap();
        baize2.agent_register("w", Level(3), vec!["A"], None).unwrap();

        // 手动创建一个已过期的 elevation blob
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

        // parent 可以审批（zone A 在 parent scope 内）
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

        // parent 不能审批（zone Z 超出 parent scope）
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

        // baize-root 可以审批任何请求
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

        // agent-b 不是 agent-a 的 parent，不能审批
        let result = baize.elevation_approve(&req_id, "agent-b");
        assert!(result.is_err());
    }

    // ─── Elevation Return 测试 ───

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

    // ─── P2-1: 导出审批 ───

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

        // root (level 4, zones=*) 可导出任何 blob
        let exported = baize.pipe_export("baize-root", &blob.hash).unwrap();
        assert_eq!(exported.content, "high sensitivity zone X");
    }

    // ─── 用户决策层 ───

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

    // ─── 借权到期主动回收 ───

    #[test]
    fn elevation_expired_auto_cleanup() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("worker", Level(2), vec!["A"], None).unwrap();

        // 手动构造一个已过期且已审批的借权请求 blob
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

        // 新的 elevation_request 会触发清理
        baize.elevation_request(
            "worker", vec!["A"], ElevationMode::WriteOnly, "need A again", None,
        ).unwrap();

        // list 中之前的请求应显示 Expired
        let reqs = baize.elevation_list().unwrap();
        let expired_req = reqs.iter().find(|r| r.id == blob.hash).unwrap();
        assert_eq!(expired_req.status, ElevationStatus::Expired);
    }

    // ─── 文件操作测试 ───

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

        // agent 只有 zone A，写 zone B 应失败
        let result = baize.pipe_file_write("writer", "B/data.txt", b"hack", None);
        assert!(result.is_err());
    }

    #[test]
    fn file_zone_root_accessible() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("writer", Level(2), vec!["A"], None).unwrap();

        // 根级文件（无 / 前缀）所有 agent 可访问
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

    // ─── Push / Pull 测试 ───

    #[test]
    fn push_creates_commit_with_files() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("worker", Level(2), vec!["A"], None).unwrap();

        baize.pipe_file_write("worker", "A/config.yaml", b"key: value", None).unwrap();
        baize.pipe_file_write("worker", "A/data.txt", b"hello", None).unwrap();

        let result = baize.pipe_push("worker", "snapshot 1", None).unwrap();
        assert_eq!(result.files, 2);
        assert!(!result.commit_hash.is_empty());
        assert_eq!(result.ref_name, "HEAD");

        // 验证 commit 存在且包含 blob
        let commit = baize.storage.commit_read(&result.commit_hash).unwrap();
        assert_eq!(commit.blob_hashes.len(), 2);
    }

    #[test]
    fn push_empty_workspace_fails() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("worker", Level(2), vec!["A"], None).unwrap();

        let result = baize.pipe_push("worker", "empty", None);
        assert!(result.is_err());
    }

    #[test]
    fn pull_restores_files_from_commit() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("worker", Level(2), vec!["A"], None).unwrap();

        // 写文件 → push
        baize.pipe_file_write("worker", "A/config.yaml", b"key: value", None).unwrap();
        baize.pipe_push("worker", "v1", None).unwrap();

        // 清空 workspace（通过删文件）
        baize.workspace_mgr.delete_file("worker", "A/config.yaml").unwrap();
        assert!(baize.pipe_file_list("worker").unwrap().is_empty());

        // pull → 文件恢复
        let result = baize.pipe_pull("worker", None).unwrap();
        assert_eq!(result.files, 1);

        let content = baize.pipe_file_read("worker", "A/config.yaml").unwrap();
        assert_eq!(content.content, b"key: value");
    }

    #[test]
    fn push_creates_commit_chain() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("worker", Level(2), vec!["A"], None).unwrap();

        baize.pipe_file_write("worker", "A/v1.txt", b"version 1", None).unwrap();
        let r1 = baize.pipe_push("worker", "v1", None).unwrap();

        baize.pipe_file_write("worker", "A/v2.txt", b"version 2", None).unwrap();
        let r2 = baize.pipe_push("worker", "v2", None).unwrap();

        // r2 的 parent 应该是 r1
        let c2 = baize.storage.commit_read(&r2.commit_hash).unwrap();
        assert_eq!(c2.parent_hash.as_deref(), Some(r1.commit_hash.as_str()));
    }

    #[test]
    fn push_pull_cross_agent() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("alice", Level(2), vec!["A"], None).unwrap();
        baize.agent_register("bob", Level(2), vec!["A"], None).unwrap();

        // alice 写文件 → push
        baize.pipe_file_write("alice", "A/shared.txt", b"from alice", None).unwrap();
        baize.pipe_push("alice", "alice's work", Some("shared")).unwrap();

        // bob pull → 拿到 alice 的文件
        let result = baize.pipe_pull("bob", Some("shared")).unwrap();
        assert_eq!(result.files, 1);

        let content = baize.pipe_file_read("bob", "A/shared.txt").unwrap();
        assert_eq!(content.content, b"from alice");
    }

    #[test]
    fn pull_nonexistent_ref_fails() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("worker", Level(2), vec!["A"], None).unwrap();

        let result = baize.pipe_pull("worker", Some("no-such-ref"));
        assert!(result.is_err());
    }

    /// push/pull 使用命名 ref
    /// 注意：pull 现在从主仓库同步，主仓库始终反映最后一次 push 的状态。
    /// 因此 pull v1 ref 不会恢复 v1 内容，而是从主仓库同步当前状态。
    #[test]
    fn push_pull_named_ref() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("worker", Level(2), vec!["A"], None).unwrap();

        baize.pipe_file_write("worker", "A/data.txt", b"v1", None).unwrap();
        baize.pipe_push("worker", "tag v1", Some("v1")).unwrap();

        // 写新版本 push 到 HEAD
        baize.pipe_file_write("worker", "A/data.txt", b"v2", None).unwrap();
        baize.pipe_push("worker", "latest", None).unwrap();

        // 主仓库现在是 v2（最后一次 push 的状态）
        // pull 从主仓库同步，不管指定哪个 ref，拿到的都是主仓库当前状态
        baize.pipe_pull("worker", Some("v1")).unwrap();
        let content = baize.pipe_file_read("worker", "A/data.txt").unwrap();
        assert_eq!(content.content, b"v2"); // 主仓库是 v2
    }

    /// pull 从主仓库同步文件
    /// 只有经过 push 的文件才会出现在主仓库中
    #[test]
    fn pull_syncs_from_main_repo() {
        let mut baize = Baize::init_in_memory().unwrap();
        baize.agent_register("worker", Level(2), vec!["A"], None).unwrap();

        // 写文件并 push → 同步到主仓库
        baize.pipe_file_write("worker", "A/real.txt", b"real content", None).unwrap();
        baize.pipe_push("worker", "commit 1", None).unwrap();

        // 清空 workspace
        baize.workspace_mgr.clear_all("worker").unwrap();

        // pull → 从主仓库恢复
        let result = baize.pipe_pull("worker", None).unwrap();
        assert_eq!(result.files, 1);

        let content = baize.pipe_file_read("worker", "A/real.txt").unwrap();
        assert_eq!(content.content, b"real content");
    }
}
