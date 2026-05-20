use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::scope::Scope;

/// Agent 工作目录管理
pub struct WorkspaceManager {
    base_dir: PathBuf,
    /// agent_id → workspace path
    workspaces: HashMap<String, PathBuf>,
}

impl WorkspaceManager {
    /// 创建 WorkspaceManager，base_dir 为所有 workspace 的根目录
    /// 自动恢复已存在于磁盘上的 workspace
    pub fn new(base_dir: impl AsRef<Path>) -> Result<Self> {
        let base_dir = base_dir.as_ref().to_path_buf();
        fs::create_dir_all(&base_dir)
            .map_err(|e| Error::Storage(format!("create workspace base dir: {}", e), None))?;

        // 扫描磁盘恢复已有 workspace
        let mut workspaces = HashMap::new();
        if base_dir.exists() {
            for entry in fs::read_dir(&base_dir)
                .map_err(|e| Error::Storage(format!("read workspace base dir: {}", e), None))?
            {
                let entry = entry.map_err(|e| Error::Storage(format!("read dir entry: {}", e), None))?;
                if entry.path().is_dir() {
                    if let Some(name) = entry.file_name().to_str() {
                        workspaces.insert(name.to_string(), entry.path());
                    }
                }
            }
        }

        Ok(Self {
            base_dir,
            workspaces,
        })
    }

    /// 为 Agent 创建工作目录
    pub fn create(&mut self, agent_id: &str) -> Result<PathBuf> {
        if self.workspaces.contains_key(agent_id) {
            return Err(Error::Conflict(format!(
                "workspace already exists for agent {}", agent_id
            )));
        }

        let ws_path = self.base_dir.join(agent_id);
        fs::create_dir_all(&ws_path)
            .map_err(|e| Error::Storage(format!("create workspace for {}: {}", agent_id, e), None))?;

        self.workspaces.insert(agent_id.to_string(), ws_path.clone());
        Ok(ws_path)
    }

    /// 确保 workspace 存在：已存在则返回路径，否则创建
    pub fn ensure(&mut self, agent_id: &str) -> Result<PathBuf> {
        if let Some(path) = self.workspaces.get(agent_id) {
            return Ok(path.clone());
        }
        self.create(agent_id)
    }

    /// 销毁 Agent 工作目录
    pub fn destroy(&mut self, agent_id: &str) -> Result<()> {
        let ws_path = self.workspaces.remove(agent_id)
            .ok_or_else(|| Error::NotFound(format!("workspace for agent {}", agent_id)))?;

        if ws_path.exists() {
            fs::remove_dir_all(&ws_path)
                .map_err(|e| Error::Storage(format!("destroy workspace for {}: {}", agent_id, e), None))?;
        }

        Ok(())
    }

    /// 获取 Agent 工作目录路径
    pub fn get(&self, agent_id: &str) -> Option<&Path> {
        self.workspaces.get(agent_id).map(|p| p.as_path())
    }

    /// 列出所有 Agent 的工作目录
    pub fn list(&self) -> Vec<(&str, &Path)> {
        self.workspaces.iter()
            .map(|(id, path)| (id.as_str(), path.as_path()))
            .collect()
    }

    /// 列出工作目录中的文件（相对路径）
    pub fn list_files(&self, agent_id: &str) -> Result<Vec<String>> {
        let ws_path = self.workspaces.get(agent_id)
            .ok_or_else(|| Error::NotFound(format!("workspace for agent {}", agent_id)))?;

        let mut files = Vec::new();
        if ws_path.exists() {
            self.collect_files(ws_path, ws_path, &mut files)?;
        }
        Ok(files)
    }

    /// 写入文件到 Agent 工作目录
    pub fn write_file(&self, agent_id: &str, relative_path: &str, content: &[u8]) -> Result<()> {
        let ws_path = self.workspaces.get(agent_id)
            .ok_or_else(|| Error::NotFound(format!("workspace for agent {}", agent_id)))?;

        Self::validate_relative_path(relative_path)?;

        let file_path = ws_path.join(relative_path);

        // 确保父目录存在
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| Error::Storage(format!("create dir: {}", e), None))?;
        }

        // Canonicalize workspace 和 parent，验证 parent 不超出 workspace
        let canonical_ws = ws_path.canonicalize()
            .map_err(|e| Error::Storage(format!("canonicalize workspace: {}", e), None))?;
        let canonical_parent = file_path.parent()
            .and_then(|p| p.canonicalize().ok())
            .unwrap_or_else(|| canonical_ws.clone());
        if !canonical_parent.starts_with(&canonical_ws) {
            return Err(Error::PermissionDenied("path traversal detected".into()));
        }

        // 从已验证的 canonical parent + 文件名构造安全路径，消除 TOCTOU
        let file_name = file_path.file_name()
            .ok_or_else(|| Error::Storage("invalid file name".to_string(), None))?;
        let safe_path = canonical_parent.join(file_name);

        fs::write(&safe_path, content)
            .map_err(|e| Error::Storage(format!("write file: {}", e), None))?;

        Ok(())
    }

    /// 读取工作目录中的文件
    pub fn read_file(&self, agent_id: &str, relative_path: &str) -> Result<Vec<u8>> {
        let ws_path = self.workspaces.get(agent_id)
            .ok_or_else(|| Error::NotFound(format!("workspace for agent {}", agent_id)))?;

        Self::validate_relative_path(relative_path)?;

        let file_path = ws_path.join(relative_path);

        let canonical_ws = ws_path.canonicalize()
            .map_err(|e| Error::Storage(format!("canonicalize workspace: {}", e), None))?;
        let canonical_file = file_path.canonicalize()
            .map_err(|_e| Error::NotFound(format!("file {}", relative_path)))?;
        if !canonical_file.starts_with(&canonical_ws) {
            return Err(Error::PermissionDenied("path traversal detected".into()));
        }

        // 使用 canonical 路径做实际 I/O，消除 TOCTOU
        fs::read(&canonical_file)
            .map_err(|e| Error::Storage(format!("read file: {}", e), None))
    }

    /// 删除工作目录中的文件
    pub fn delete_file(&self, agent_id: &str, relative_path: &str) -> Result<()> {
        let ws_path = self.workspaces.get(agent_id)
            .ok_or_else(|| Error::NotFound(format!("workspace for agent {}", agent_id)))?;

        Self::validate_relative_path(relative_path)?;

        let file_path = ws_path.join(relative_path);

        let canonical_ws = ws_path.canonicalize()
            .map_err(|e| Error::Storage(format!("canonicalize workspace: {}", e), None))?;
        let canonical_file = file_path.canonicalize()
            .map_err(|_e| Error::NotFound(format!("file {}", relative_path)))?;
        if !canonical_file.starts_with(&canonical_ws) {
            return Err(Error::PermissionDenied("path traversal detected".into()));
        }

        // 符号链接：删除链接本身；普通文件：使用 canonical 路径消除 TOCTOU
        let meta = fs::symlink_metadata(&file_path)
            .map_err(|_e| Error::NotFound(format!("file {}", relative_path)))?;
        if meta.file_type().is_symlink() {
            fs::remove_file(&file_path)
                .map_err(|e| Error::Storage(format!("delete file: {}", e), None))
        } else {
            fs::remove_file(&canonical_file)
                .map_err(|e| Error::Storage(format!("delete file: {}", e), None))
        }
    }

    /// 计算工作目录中文件的 SHA-256
    pub fn file_hash(&self, agent_id: &str, relative_path: &str) -> Result<String> {
        let content = self.read_file(agent_id, relative_path)?;
        let mut hasher = Sha256::new();
        hasher.update(&content);
        Ok(format!("{:x}", hasher.finalize()))
    }

    /// 清理工作目录中超出 scope 的文件
    /// scope 含 "*" → 不清理（全权）
    /// 文件路径含 '/' 且第一段为 zone 名 → 超出 scope 则删除
    /// 无 '/' 的文件（如 "readme.txt"）→ 保留
    pub fn clean(&self, agent_id: &str, scope: &Scope) -> Result<usize> {
        let ws_path = self.workspaces.get(agent_id)
            .ok_or_else(|| Error::NotFound(format!("workspace for agent {}", agent_id)))?;

        // wildcard scope → 不清理
        if scope.zones.contains("*") {
            return Ok(0);
        }

        let files = self.list_files(agent_id)?;
        let mut cleaned = 0;

        for rel_path in &files {
            // 只处理含 '/' 的路径（zone 前缀目录下的文件）
            let Some((file_zone, _)) = rel_path.split_once('/') else {
                continue; // 无 zone 前缀 → 保留
            };

            // zone 在 scope 内 → 保留
            if scope.zones.contains(file_zone) {
                continue;
            }

            let full_path = ws_path.join(rel_path);

                // 跳过符号链接，防止删除指向 workspace 外的文件
                if fs::symlink_metadata(&full_path)
                    .map(|m| m.file_type().is_symlink())
                    .unwrap_or(false)
                {
                    continue;
                }

                if fs::remove_file(&full_path).is_ok() {
                cleaned += 1;
            }
        }

        Ok(cleaned)
    }

    /// 清空工作目录中的所有文件，但保留目录结构
    /// 用于 pull 操作前清空 workspace
    pub fn clear_all(&self, agent_id: &str) -> Result<usize> {
        let ws_path = self.workspaces.get(agent_id)
            .ok_or_else(|| Error::NotFound(format!("workspace for agent {}", agent_id)))?;

        let mut count = 0;
        let mut stack = vec![ws_path.clone()];
        while let Some(dir) = stack.pop() {
            let entries = fs::read_dir(&dir)
                .map_err(|e| Error::Storage(format!("read dir {:?}: {}", dir, e), None))?;
            for entry in entries {
                let entry = entry.map_err(|e| Error::Storage(format!("read entry: {}", e), None))?;
                let path = entry.path();
                let file_type = entry.file_type()
                    .map_err(|e| Error::Storage(format!("file type: {}", e), None))?;
                if file_type.is_symlink() {
                    // 符号链接：移除链接本身，不跟随
                    if fs::remove_file(&path).is_ok() {
                        count += 1;
                    }
                } else if file_type.is_dir() {
                    stack.push(path);
                } else {
                    if fs::remove_file(&path).is_ok() {
                        count += 1;
                    }
                }
            }
        }
        Ok(count)
    }

    /// 验证相对路径安全：拒绝 .. 组件、绝对路径、空路径、null 字节
    fn validate_relative_path(relative_path: &str) -> Result<()> {
        if relative_path.is_empty() {
            return Err(Error::PermissionDenied("empty path not allowed".into()));
        }
        if relative_path.contains('\0') {
            return Err(Error::PermissionDenied("null byte in path".into()));
        }
        let path = Path::new(relative_path);
        if path.is_absolute() {
            return Err(Error::PermissionDenied(
                format!("absolute path not allowed: {}", relative_path)
            ));
        }
        for component in path.components() {
            if matches!(component, std::path::Component::ParentDir) {
                return Err(Error::PermissionDenied(
                    format!("path traversal not allowed: {}", relative_path)
                ));
            }
        }
        Ok(())
    }

    fn collect_files(&self, dir: &Path, base: &Path, files: &mut Vec<String>) -> Result<()> {
        let entries = fs::read_dir(dir)
            .map_err(|e| Error::Storage(format!("read dir: {}", e), None))?;

        for entry in entries {
            let entry = entry.map_err(|e| Error::Storage(format!("read entry: {}", e), None))?;
            let file_type = entry.file_type()
                .map_err(|e| Error::Storage(format!("file type: {}", e), None))?;

            // 跳过符号链接 — 不跟随、不列入
            if file_type.is_symlink() {
                continue;
            }

            let path = entry.path();
            if file_type.is_dir() {
                self.collect_files(&path, base, files)?;
            } else if let Ok(rel) = path.strip_prefix(base) {
                files.push(rel.to_string_lossy().to_string());
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::Level;
    use tempfile::TempDir;

    fn setup() -> (TempDir, WorkspaceManager) {
        let tmp = TempDir::new().unwrap();
        let mgr = WorkspaceManager::new(tmp.path()).unwrap();
        (tmp, mgr)
    }

    #[test]
    fn create_workspace() {
        let (tmp, mut mgr) = setup();
        let path = mgr.create("agent-001").unwrap();
        assert!(path.exists());
        assert!(path.starts_with(tmp.path()));
    }

    #[test]
    fn create_duplicate_fails() {
        let (_, mut mgr) = setup();
        mgr.create("agent-001").unwrap();
        let result = mgr.create("agent-001");
        assert!(result.is_err());
    }

    #[test]
    fn destroy_workspace() {
        let (_, mut mgr) = setup();
        mgr.create("agent-001").unwrap();
        mgr.destroy("agent-001").unwrap();
        assert!(mgr.get("agent-001").is_none());
    }

    #[test]
    fn destroy_nonexistent_fails() {
        let (_, mut mgr) = setup();
        let result = mgr.destroy("agent-001");
        assert!(result.is_err());
    }

    #[test]
    fn write_and_read_file() {
        let (_, mut mgr) = setup();
        mgr.create("agent-001").unwrap();

        mgr.write_file("agent-001", "data.txt", b"hello").unwrap();
        let content = mgr.read_file("agent-001", "data.txt").unwrap();
        assert_eq!(content, b"hello");
    }

    #[test]
    fn write_file_creates_subdirs() {
        let (_, mut mgr) = setup();
        mgr.create("agent-001").unwrap();

        mgr.write_file("agent-001", "sub/dir/file.txt", b"nested").unwrap();
        let content = mgr.read_file("agent-001", "sub/dir/file.txt").unwrap();
        assert_eq!(content, b"nested");
    }

    #[test]
    fn list_files() {
        let (_, mut mgr) = setup();
        mgr.create("agent-001").unwrap();

        mgr.write_file("agent-001", "a.txt", b"a").unwrap();
        mgr.write_file("agent-001", "b.txt", b"b").unwrap();

        let files = mgr.list_files("agent-001").unwrap();
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn clean_workspace() {
        let (_, mut mgr) = setup();
        mgr.create("agent-001").unwrap();
        mgr.write_file("agent-001", "a.txt", b"a").unwrap();
        mgr.write_file("agent-001", "b.txt", b"b").unwrap();

        // 无 zone 前缀的文件在 scope clean 后保留
        let scope = Scope::new(Level(2), vec!["A"]).unwrap();
        let cleaned = mgr.clean("agent-001", &scope).unwrap();
        assert_eq!(cleaned, 0); // 无 zone 前缀文件不清理

        let files = mgr.list_files("agent-001").unwrap();
        assert_eq!(files.len(), 2);
    }

    #[test]
    fn clean_wildcard_scope_removes_nothing() {
        let (_, mut mgr) = setup();
        mgr.create("agent-001").unwrap();
        mgr.write_file("agent-001", "Z/data.txt", b"z").unwrap();

        let scope = Scope::new(Level(4), vec!["*"]).unwrap();
        let cleaned = mgr.clean("agent-001", &scope).unwrap();
        assert_eq!(cleaned, 0);

        let files = mgr.list_files("agent-001").unwrap();
        assert_eq!(files.len(), 1);
    }

    #[test]
    fn clean_removes_only_out_of_scope() {
        let (_, mut mgr) = setup();
        mgr.create("agent-001").unwrap();
        mgr.write_file("agent-001", "A/data.txt", b"a").unwrap();
        mgr.write_file("agent-001", "B/data.txt", b"b").unwrap();
        mgr.write_file("agent-001", "readme.txt", b"info").unwrap();

        let scope = Scope::new(Level(2), vec!["A"]).unwrap();
        let cleaned = mgr.clean("agent-001", &scope).unwrap();
        assert_eq!(cleaned, 1); // only B/data.txt removed

        let files = mgr.list_files("agent-001").unwrap();
        assert_eq!(files.len(), 2); // A/data.txt + readme.txt kept
        assert!(files.iter().any(|f| f.contains("A/data")));
        assert!(files.iter().any(|f| f.contains("readme")));
    }

    #[test]
    fn clean_keeps_root_files() {
        let (_, mut mgr) = setup();
        mgr.create("agent-001").unwrap();
        mgr.write_file("agent-001", "config.json", b"{}").unwrap();
        mgr.write_file("agent-001", "Z/secret.txt", b"s").unwrap();

        let scope = Scope::new(Level(2), vec!["A"]).unwrap();
        let cleaned = mgr.clean("agent-001", &scope).unwrap();
        assert_eq!(cleaned, 1); // Z/secret.txt removed

        let files = mgr.list_files("agent-001").unwrap();
        assert_eq!(files.len(), 1);
        assert!(files[0].contains("config"));
    }

    #[test]
    fn path_traversal_blocked() {
        let (_, mut mgr) = setup();
        mgr.create("agent-001").unwrap();

        let result = mgr.write_file("agent-001", "../etc/passwd", b"hack");
        assert!(result.is_err());
    }

    #[test]
    fn delete_file() {
        let (_, mut mgr) = setup();
        mgr.create("agent-001").unwrap();
        mgr.write_file("agent-001", "data.txt", b"hello").unwrap();

        mgr.delete_file("agent-001", "data.txt").unwrap();

        let files = mgr.list_files("agent-001").unwrap();
        assert!(files.is_empty());
    }

    #[test]
    fn delete_nonexistent_fails() {
        let (_, mut mgr) = setup();
        mgr.create("agent-001").unwrap();

        let result = mgr.delete_file("agent-001", "nope.txt");
        assert!(result.is_err());
    }

    #[test]
    fn file_hash_matches_content() {
        let (_, mut mgr) = setup();
        mgr.create("agent-001").unwrap();
        mgr.write_file("agent-001", "data.txt", b"hello").unwrap();

        let hash = mgr.file_hash("agent-001", "data.txt").unwrap();
        assert_eq!(hash.len(), 64); // SHA-256 hex

        // 相同内容应该得到相同 hash
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"hello");
        let expected = format!("{:x}", hasher.finalize());
        assert_eq!(hash, expected);
    }

    #[test]
    fn list_workspaces() {
        let (_, mut mgr) = setup();
        mgr.create("agent-001").unwrap();
        mgr.create("agent-002").unwrap();

        let list = mgr.list();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn absolute_path_rejected() {
        let (_, mut mgr) = setup();
        mgr.create("agent-001").unwrap();

        let result = mgr.write_file("agent-001", "/etc/passwd", b"hack");
        assert!(result.is_err());
    }

    #[test]
    fn empty_path_rejected() {
        let (_, mut mgr) = setup();
        mgr.create("agent-001").unwrap();

        let result = mgr.write_file("agent-001", "", b"data");
        assert!(result.is_err());
    }

    #[test]
    fn null_byte_in_path_rejected() {
        let (_, mut mgr) = setup();
        mgr.create("agent-001").unwrap();

        let result = mgr.write_file("agent-001", "foo\0bar", b"data");
        assert!(result.is_err());
    }

    #[test]
    #[cfg(unix)]
    fn symlink_read_blocked() {
        use std::os::unix::fs::symlink;

        let (_, mut mgr) = setup();
        mgr.create("agent-001").unwrap();
        mgr.create("agent-002").unwrap();

        // agent-002 写入文件
        mgr.write_file("agent-002", "secret.txt", b"secret").unwrap();

        // agent-001 创建符号链接指向 agent-002 的 workspace
        let ws = mgr.get("agent-001").unwrap().to_path_buf();
        let other_ws = mgr.get("agent-002").unwrap().to_path_buf();
        symlink(&other_ws, ws.join("escape")).unwrap();

        // 通过符号链接读取应被拒绝
        let result = mgr.read_file("agent-001", "escape/secret.txt");
        assert!(result.is_err());
    }

    #[test]
    #[cfg(unix)]
    fn symlink_write_blocked() {
        use std::os::unix::fs::symlink;

        let (_, mut mgr) = setup();
        mgr.create("agent-001").unwrap();
        mgr.create("agent-002").unwrap();

        let ws = mgr.get("agent-001").unwrap().to_path_buf();
        let other_ws = mgr.get("agent-002").unwrap().to_path_buf();
        symlink(&other_ws, ws.join("escape")).unwrap();

        // 通过符号链接写入应被拒绝
        let result = mgr.write_file("agent-001", "escape/hack.txt", b"hacked");
        assert!(result.is_err());
    }

    #[test]
    #[cfg(unix)]
    fn symlink_not_followed_in_list() {
        use std::os::unix::fs::symlink;

        let (tmp, mut mgr) = setup();
        mgr.create("agent-001").unwrap();
        mgr.write_file("agent-001", "real.txt", b"real").unwrap();

        // 创建符号链接指向 workspace 外
        let ws = mgr.get("agent-001").unwrap().to_path_buf();
        symlink(tmp.path(), ws.join("link")).unwrap();

        // list_files 不应跟随符号链接
        let files = mgr.list_files("agent-001").unwrap();
        assert_eq!(files.len(), 1);
        assert!(files[0].contains("real.txt"));
    }

    #[test]
    #[cfg(unix)]
    fn symlink_deleted_not_target() {
        use std::os::unix::fs::symlink;

        let (_, mut mgr) = setup();
        mgr.create("agent-001").unwrap();
        mgr.write_file("agent-001", "real.txt", b"real").unwrap();

        // 创建符号链接指向 workspace 内的文件
        let ws = mgr.get("agent-001").unwrap().to_path_buf();
        symlink(ws.join("real.txt"), ws.join("link")).unwrap();

        // 删除符号链接本身，不应删除目标文件
        mgr.delete_file("agent-001", "link").unwrap();

        // 目标文件仍然存在
        let content = mgr.read_file("agent-001", "real.txt").unwrap();
        assert_eq!(content, b"real");
    }

    #[test]
    #[cfg(unix)]
    fn symlink_skipped_in_clean() {
        use std::os::unix::fs::symlink;

        let (_, mut mgr) = setup();
        mgr.create("agent-001").unwrap();
        mgr.write_file("agent-001", "Z/data.txt", b"z").unwrap();

        // 创建符号链接
        let ws = mgr.get("agent-001").unwrap().to_path_buf();
        symlink(ws.join("Z"), ws.join("link")).unwrap();

        let scope = Scope::new(Level(2), vec!["A"]).unwrap();
        let cleaned = mgr.clean("agent-001", &scope).unwrap();
        // 只有 Z/data.txt 被删除，符号链接被跳过
        assert_eq!(cleaned, 1);
    }
}
