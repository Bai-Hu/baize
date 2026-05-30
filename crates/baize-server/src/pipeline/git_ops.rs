use baize_core::error::Error;

use super::Baize;

/// Git commit 信息
pub struct GitCommitInfo {
    pub hash: String,
    pub message: String,
    pub author: String,
    pub time: String,
}

/// 仓库统计信息
pub struct RepoStats {
    pub total_blobs: i64,
    pub total_commits: i64,
    pub total_refs: i64,
}

/// Git 操作接口：主仓库版本管理
pub trait GitOps {
    /// Git log：返回最近的 commit 列表
    fn git_log(&self, limit: usize) -> Result<Vec<GitCommitInfo>, Error>;
    /// 列出所有 Git refs
    fn git_ref_list(&self) -> Result<Vec<String>, Error>;
    /// 获取指定 Git ref 的 OID
    fn git_ref_get(&self, name: &str) -> Result<String, Error>;
    /// 设置 Git ref 指向指定 commit
    fn git_ref_set(&self, name: &str, oid: &str) -> Result<(), Error>;
    /// 删除 Git ref（不可删除 HEAD）
    fn git_ref_delete(&self, name: &str) -> Result<(), Error>;
    /// 仓库统计信息
    fn repo_stats(&self) -> Result<RepoStats, Error>;
    /// Git add all + commit，返回 commit OID
    fn git_commit_all(&self, message: &str, author: &str) -> Result<String, Error>;
}

impl Baize {
    /// 打开主仓库的 Git 仓库
    pub(super) fn git_repo(&self) -> Result<git2::Repository, Error> {
        git2::Repository::open(&self.main_repo)
            .map_err(|e| Error::Internal(anyhow::anyhow!("failed to open git repo: {}", e)))
    }

    /// 初始化主仓库为 Git 仓库
    pub(super) fn git_init(main_repo: &std::path::Path) -> Result<git2::Repository, Error> {
        git2::Repository::init(main_repo)
            .map_err(|e| Error::Internal(anyhow::anyhow!("failed to init git repo: {}", e)))
    }
}

impl GitOps for Baize {
    fn git_log(&self, limit: usize) -> Result<Vec<GitCommitInfo>, Error> {
        let repo = self.git_repo()?;

        let head = repo.head()
            .map_err(|e| Error::Internal(anyhow::anyhow!("failed to get HEAD: {}", e)))?;
        let oid = head.target()
            .ok_or_else(|| Error::Internal(anyhow::anyhow!("HEAD is not a direct reference")))?;

        let mut revwalk = repo.revwalk()
            .map_err(|e| Error::Internal(anyhow::anyhow!("failed to create revwalk: {}", e)))?;
        revwalk.push(oid)
            .map_err(|e| Error::Internal(anyhow::anyhow!("failed to push OID: {}", e)))?;

        let mut commits = Vec::new();
        for oid_result in revwalk.take(limit) {
            let oid = oid_result
                .map_err(|e| Error::Internal(anyhow::anyhow!("revwalk error: {}", e)))?;
            let commit = repo.find_commit(oid)
                .map_err(|e| Error::Internal(anyhow::anyhow!("failed to find commit: {}", e)))?;

            commits.push(GitCommitInfo {
                hash: format!("{}", oid),
                message: commit.message().unwrap_or("").to_string(),
                author: commit.author().name().unwrap_or("").to_string(),
                time: chrono::DateTime::from_timestamp(commit.author().when().seconds(), 0)
                    .map(|t| t.to_rfc3339())
                    .unwrap_or_default(),
            });
        }

        Ok(commits)
    }

    fn git_ref_list(&self) -> Result<Vec<String>, Error> {
        let repo = self.git_repo()?;
        let refs = repo.references()
            .map_err(|e| Error::Internal(anyhow::anyhow!("failed to list refs: {}", e)))?;

        let mut result = Vec::new();
        for r in refs {
            let r = r.map_err(|e| Error::Internal(anyhow::anyhow!("ref error: {}", e)))?;
            if let Some(name) = r.shorthand() {
                result.push(name.to_string());
            }
        }
        Ok(result)
    }

    fn git_ref_get(&self, name: &str) -> Result<String, Error> {
        let repo = self.git_repo()?;
        let reference = repo.find_reference(name)
            .map_err(|_| Error::NotFound(format!("git ref {}", name)))?;
        let oid = reference.target()
            .ok_or_else(|| Error::NotFound(format!("git ref {} is not a direct reference", name)))?;
        Ok(format!("{}", oid))
    }

    fn git_ref_set(&self, name: &str, oid: &str) -> Result<(), Error> {
        let repo = self.git_repo()?;
        let oid = git2::Oid::from_str(oid)
            .map_err(|e| Error::Validation(format!("invalid oid '{}': {}", oid, e)))?;
        repo.find_commit(oid)
            .map_err(|_| Error::NotFound(format!("git commit {}", oid)))?;
        match repo.find_reference(name) {
            Ok(mut reference) => {
                reference.set_target(oid, "")
                    .map_err(|e| Error::Internal(anyhow::anyhow!("failed to update ref {}: {}", name, e)))?;
            }
            Err(_) => {
                repo.reference(name, oid, false, "")
                    .map_err(|e| Error::Internal(anyhow::anyhow!("failed to create ref {}: {}", name, e)))?;
            }
        }
        Ok(())
    }

    fn git_ref_delete(&self, name: &str) -> Result<(), Error> {
        if name == "HEAD" {
            return Err(Error::Validation("cannot delete HEAD".into()));
        }
        let repo = self.git_repo()?;
        let mut reference = repo.find_reference(name)
            .map_err(|_| Error::NotFound(format!("git ref {}", name)))?;
        reference.delete()
            .map_err(|e| Error::Internal(anyhow::anyhow!("failed to delete ref {}: {}", name, e)))?;
        Ok(())
    }

    fn repo_stats(&self) -> Result<RepoStats, Error> {
        let total_blobs = self.storage.blob_count().unwrap_or(0);

        let (total_commits, total_refs) = match self.git_repo() {
            Ok(repo) => {
                let commits = match repo.head().ok().and_then(|h| h.target()) {
                    Some(oid) => repo.revwalk()
                        .ok()
                        .map(|mut rw| { rw.push(oid).ok(); rw.count() as i64 })
                        .unwrap_or(0),
                    None => 0,
                };
                let refs = repo.references()
                    .map(|r| r.count() as i64)
                    .unwrap_or(0);
                (commits, refs)
            }
            Err(_) => (0, 0),
        };

        Ok(RepoStats {
            total_blobs,
            total_commits,
            total_refs,
        })
    }

    /// Git add all + commit：将主仓库工作区的所有变更提交到 Git 历史
    ///
    /// 等价于 `git add -A && git commit -m <message>`
    /// 用于 `bz push --auto-commit` 自动完成 git commit
    fn git_commit_all(&self, message: &str, author: &str) -> Result<String, Error> {
        let repo = self.git_repo()?;

        // 将工作区文件全部加入 index
        let mut index = repo.index()
            .map_err(|e| Error::Internal(anyhow::anyhow!("git index: {}", e)))?;

        // 递归添加所有文件（跳过 .git）
        let workdir = repo.workdir()
            .ok_or_else(|| Error::Internal(anyhow::anyhow!("git repo has no working directory")))?;
        let mut stack = vec![workdir.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let entries = std::fs::read_dir(&dir)
                .map_err(|e| Error::Internal(anyhow::anyhow!("read dir {:?}: {}", dir, e)))?;
            for entry in entries {
                let entry = entry.map_err(|e| Error::Internal(anyhow::anyhow!("dir entry: {}", e)))?;
                let path = entry.path();
                if path.is_dir() {
                    if path.file_name() == Some(std::ffi::OsStr::new(".git")) {
                        continue;
                    }
                    stack.push(path);
                } else {
                    let rel = path.strip_prefix(workdir)
                        .map_err(|e| Error::Internal(anyhow::anyhow!("path prefix: {}", e)))?;
                    index.add_path(rel)
                        .map_err(|e| Error::Internal(anyhow::anyhow!("git add {:?}: {}", rel, e)))?;
                }
            }
        }
        index.write()
            .map_err(|e| Error::Internal(anyhow::anyhow!("git index write: {}", e)))?;

        let tree_oid = index.write_tree()
            .map_err(|e| Error::Internal(anyhow::anyhow!("git write tree: {}", e)))?;
        let tree = repo.find_tree(tree_oid)
            .map_err(|e| Error::Internal(anyhow::anyhow!("git find tree: {}", e)))?;

        let sig = git2::Signature::now(author, "baize@local")
            .map_err(|e| Error::Internal(anyhow::anyhow!("git signature: {}", e)))?;

        // 获取父 commit（HEAD），首次 commit 无父节点
        let parents: Vec<git2::Commit> = match repo.head() {
            Ok(head) => {
                if let Some(oid) = head.target() {
                    vec![repo.find_commit(oid)
                        .map_err(|e| Error::Internal(anyhow::anyhow!("git find commit: {}", e)))?]
                } else {
                    vec![]
                }
            }
            Err(_) => vec![],
        };
        let parent_refs: Vec<&git2::Commit> = parents.iter().collect();

        let oid = repo.commit(
            Some("HEAD"),
            &sig,
            &sig,
            message,
            &tree,
            &parent_refs,
        ).map_err(|e| Error::Internal(anyhow::anyhow!("git commit: {}", e)))?;

        Ok(format!("{}", oid))
    }
}
