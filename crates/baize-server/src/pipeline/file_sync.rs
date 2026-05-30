use std::collections::HashMap;

use sha2::{Digest, Sha256};

use baize_core::cert::CertIdentity;
use baize_core::error::Error;
use baize_core::approval::{ApprovalAction, PendingOperation};

use super::Baize;
use super::auditor::Auditor;
use super::agent_manager::PermissionGuard;
use super::approval::ApprovalManager;

/// 文件操作记录
#[derive(Debug)]
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
#[derive(Debug)]
pub struct PushResult {
    pub files: usize,
    pub pending: bool,
}

/// Pull 结果
pub struct PullResult {
    pub files: usize,
}

/// 文件同步接口：文件 I/O + push/pull
pub trait FileSync {
    /// 管道：文件写入
    fn pipe_file_write(
        &self,
        agent_id: &str,
        path: &str,
        content: &[u8],
        labels: Option<HashMap<String, String>>,
    ) -> Result<FileRecord, Error>;

    /// 管道：文件读取（workspace 优先，主仓库 fallback）
    fn pipe_file_read(
        &self,
        agent_id: &str,
        path: &str,
    ) -> Result<FileContent, Error>;

    /// 管道：文件删除
    fn pipe_file_delete(
        &self,
        agent_id: &str,
        path: &str,
    ) -> Result<(), Error>;

    /// 管道：列出文件
    fn pipe_file_list(
        &self,
        agent_id: &str,
    ) -> Result<Vec<String>, Error>;

    /// Push：workspace → 主仓库工作区
    fn pipe_push(
        &self,
        agent_id: &str,
        message: &str,
        ref_name: Option<&str>,
    ) -> Result<PushResult, Error>;

    /// Pull：主仓库工作区 → workspace
    fn pipe_pull(
        &self,
        agent_id: &str,
        ref_name: Option<&str>,
    ) -> Result<PullResult, Error>;
}

/// SHA-256 hex 辅助
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

impl Baize {
    /// 递归遍历主仓库 Git 工作树，将所有文件同步到 agent workspace
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
                    if path.file_name() == Some(std::ffi::OsStr::new(".git")) {
                        continue;
                    }
                    stack.push(path);
                } else {
                    let rel = path.strip_prefix(&self.main_repo)
                        .map_err(|e| Error::Internal(anyhow::anyhow!("path prefix error: {}", e)))?;
                    let rel_str = rel.to_str()
                        .ok_or_else(|| Error::Internal(anyhow::anyhow!("invalid path encoding: {:?}", rel)))?;

                    if self.is_zone_accessible(agent_id, identity, rel_str).is_err() {
                        continue;
                    }

                    let content = std::fs::read(&path)
                        .map_err(|e| Error::Internal(anyhow::anyhow!("failed to read main repo file {}: {}", rel_str, e)))?;
                    self.workspace_mgr.write_file(agent_id, rel_str, &content)?;
                    *count += 1;
                }
            }
        }
        Ok(())
    }

    /// 文件写入实际执行（审批通过后由 pipe_file_write 或 replay_operation 调用）
    pub(crate) fn execute_file_write(
        &self,
        agent_id: &str,
        path: &str,
        content: &[u8],
        labels: Option<&HashMap<String, String>>,
    ) -> Result<FileRecord, Error> {
        let identity = self.verify_write_agent(agent_id)?;

        // Phase 4: Level 3+ 文件写入需有效 proof（root 豁免）
        if identity.level >= 3 && agent_id != baize_core::ROOT_AGENT_ID {
            self.require_valid_proof(agent_id)?;
        }

        self.is_zone_accessible(agent_id, &identity, path)?;

        self.workspace_mgr.write_file(agent_id, path, content)?;

        let hash = sha256_hex(content);

        let mut blob_labels = labels.cloned().unwrap_or_default();
        blob_labels.insert("type".into(), "file".into());
        blob_labels.insert("path".into(), path.into());
        blob_labels.insert("action".into(), "write".into());
        blob_labels.insert("agent".into(), agent_id.into());
        blob_labels.insert("content-hash".into(), hash.clone());
        self.storage.blob_write(&hash, &blob_labels)?;

        self.audit("file_write", agent_id, &format!("success path={}", path), Some(path))?;

        Ok(FileRecord {
            path: path.to_string(),
            hash,
            size: content.len(),
        })
    }

    /// 文件删除实际执行（审批通过后由 pipe_file_delete 或 replay_operation 调用）
    pub(crate) fn execute_file_delete(
        &self,
        agent_id: &str,
        path: &str,
    ) -> Result<(), Error> {
        let identity = self.verify_write_agent(agent_id)?;

        // Phase 4: Level 3+ 文件删除需有效 proof（root 豁免）
        if identity.level >= 3 && agent_id != baize_core::ROOT_AGENT_ID {
            self.require_valid_proof(agent_id)?;
        }

        self.is_zone_accessible(agent_id, &identity, path)?;

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

    /// Push 实际执行（审批通过后由 pipe_push 或 replay_operation 调用）
    pub(crate) fn execute_push(
        &self,
        agent_id: &str,
        message: &str,
        _ref_name: Option<&str>, // 预留 Git 分支名，当前未使用
    ) -> Result<PushResult, Error> {
        let identity = self.verify_write_agent(agent_id)?;

        // Phase 4: Level 3+ push 需有效 proof（root 豁免）
        if identity.level >= 3 && agent_id != baize_core::ROOT_AGENT_ID {
            self.require_valid_proof(agent_id)?;
        }

        let files = self.workspace_mgr.list_files(agent_id)?;
        if files.is_empty() {
            return Err(Error::Validation("workspace is empty, nothing to push".into()));
        }
        for path in &files {
            self.is_zone_accessible(agent_id, &identity, path)?;
        }

        // 鉴权 blob
        let push_content = serde_json::json!({
            "type": "push",
            "agent": agent_id,
            "message": message,
            "files": files.len(),
            "time": chrono::Utc::now().to_rfc3339(),
        }).to_string();
        let push_labels = labels! {
            "type" => "push-auth",
            "agent" => agent_id,
        };
        self.storage.blob_write(&push_content, &push_labels)?;

        // Mirror deletion: 删除主仓库中 agent 可访问但 workspace 中已不存在的文件
        let file_set: std::collections::HashSet<String> = files.iter().cloned().collect();
        let mut deleted = 0;
        {
            let mut stack = vec![self.main_repo.clone()];
            while let Some(dir) = stack.pop() {
                let entries = std::fs::read_dir(&dir)
                    .map_err(|e| Error::Internal(anyhow::anyhow!("read main repo dir {:?}: {}", dir, e)))?;
                for entry in entries {
                    let entry = entry.map_err(|e| Error::Internal(anyhow::anyhow!("dir entry: {}", e)))?;
                    let path = entry.path();
                    if path.is_dir() {
                        if path.file_name() == Some(std::ffi::OsStr::new(".git")) {
                            continue;
                        }
                        stack.push(path);
                        continue;
                    }
                    let rel = path.strip_prefix(&self.main_repo)
                        .map_err(|e| Error::Internal(anyhow::anyhow!("path prefix: {}", e)))?;
                    let rel_str = rel.to_str()
                        .ok_or_else(|| Error::Internal(anyhow::anyhow!("invalid path encoding: {:?}", rel)))?;

                    // 只处理 agent 有 zone 权限的文件
                    if self.is_zone_accessible(agent_id, &identity, rel_str).is_err() {
                        continue;
                    }

                    // workspace 中不存在 → 从主仓库删除
                    if !file_set.contains(rel_str) {
                        if std::fs::remove_file(&path).is_ok() {
                            deleted += 1;
                        }
                    }
                }
            }
        }

        // 同步文件到主仓库工作区
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

        self.audit("push", agent_id, &format!("success files={} deleted={}", files.len(), deleted), None)?;

        Ok(PushResult {
            files: files.len(),
            pending: true,
        })
    }
}

impl FileSync for Baize {
    fn pipe_file_write(
        &self,
        agent_id: &str,
        path: &str,
        content: &[u8],
        file_labels: Option<HashMap<String, String>>,
    ) -> Result<FileRecord, Error> {
        let op = PendingOperation::FileWrite {
            agent_id: agent_id.to_string(),
            path: path.to_string(),
            content: content.to_vec(),
            labels: file_labels.clone(),
        };
        self.check_approval_gate(agent_id, &ApprovalAction::FileWrite, &op)?;
        self.execute_file_write(agent_id, path, content, file_labels.as_ref())
    }

    fn pipe_file_read(
        &self,
        agent_id: &str,
        path: &str,
    ) -> Result<FileContent, Error> {
        let identity = self.verify_read_agent(agent_id)?;

        // 设计决策：读操作不需要 IDN-ATH proof。
        // proof 的目的是证明"这个 agent 正在运行且凭证未被篡改"——写操作
        // 会产生不可逆的副作用（blob、文件、推送），所以需要 proof；
        // 读操作只返回数据快照，不改变系统状态，因此无需 proof。
        // 凭证状态检查（revoked/expired/suspended）由 verify_read_agent 负责。

        self.is_zone_accessible(agent_id, &identity, path)?;

        // Overlay read：workspace 优先 → 主仓库 fallback
        let content = match self.workspace_mgr.read_file(agent_id, path) {
            Ok(c) => {
                self.audit("file_read", agent_id, &format!("success path={} source=workspace", path), Some(path))?;
                c
            }
            Err(_) => {
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

    fn pipe_file_delete(
        &self,
        agent_id: &str,
        path: &str,
    ) -> Result<(), Error> {
        let op = PendingOperation::FileDelete {
            agent_id: agent_id.to_string(),
            path: path.to_string(),
        };
        self.check_approval_gate(agent_id, &ApprovalAction::FileDelete, &op)?;
        self.execute_file_delete(agent_id, path)
    }

    fn pipe_file_list(
        &self,
        agent_id: &str,
    ) -> Result<Vec<String>, Error> {
        self.verify_read_agent(agent_id)?;
        let files = self.workspace_mgr.list_files(agent_id)?;
        self.audit("file_list", agent_id, "success", None)?;
        Ok(files)
    }

    fn pipe_push(
        &self,
        agent_id: &str,
        message: &str,
        ref_name: Option<&str>,
    ) -> Result<PushResult, Error> {
        let op = PendingOperation::Push {
            agent_id: agent_id.to_string(),
            message: message.to_string(),
            ref_name: ref_name.map(|s| s.to_string()),
        };
        self.check_approval_gate(agent_id, &ApprovalAction::Push, &op)?;
        self.execute_push(agent_id, message, ref_name)
    }

    fn pipe_pull(
        &self,
        agent_id: &str,
        _ref_name: Option<&str>,
    ) -> Result<PullResult, Error> {
        let identity = self.verify_write_agent(agent_id)?;

        self.workspace_mgr.clear_all(agent_id)?;

        let mut files_written = 0;
        self.sync_main_repo_to_workspace(agent_id, &identity, &mut files_written)?;

        self.audit("pull", agent_id, &format!("success files={}", files_written), None)?;

        Ok(PullResult {
            files: files_written,
        })
    }
}
