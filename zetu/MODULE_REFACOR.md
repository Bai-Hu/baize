# 白泽模块重构讨论

## 问题

`pipeline.rs` 是一个 1400 行的大杂烩，所有业务逻辑混在一起。
需要将功能域拆开，各模块通过 trait 接口通讯。

---

## 当前功能域（pipeline.rs 内）

| # | 功能域 | 方法 | 依赖 |
|---|--------|------|------|
| 1 | **Agent 管理** | register, revoke, list, trace_identity | cert, storage, workspace |
| 2 | **权限验证** | verify_write_agent, verify_read_agent, verify_file_zone | cert, scope |
| 3 | **借权** | elevation_request/approve/return/cleanup/list | storage, scope |
| 4 | **审计** | audit() | storage |
| 5 | **Git 操作** | git_repo/init/log/ref_*/repo_stats | git2, main_repo |
| 6 | **数据操作** | pipe_blob_write, pipe_label_add, pipe_import, pipe_export | storage, scope, audit |
| 7 | **文件 + 同步** | pipe_file_*, pipe_push, pipe_pull, sync_main_repo_to_workspace | workspace, git, storage, scope, audit |

---

## 当前 crate 结构

```
baize-core      → storage(blob/label), cert, scope, workspace, error
baize-server    → pipeline(全部业务逻辑), api, hook
baize-middleware → client trait, http client, types
baize-cli       → main.rs
```

---

## 讨论点

### 1. 拆分粒度：module 级还是 crate 级？

- **Module 级**（在 baize-server 内拆成多个 .rs 文件）
  - 优点：改动小，不需要调整 Cargo.toml 和依赖
  - 缺点：模块间仍然可以直接访问内部状态

- **Crate 级**（拆成独立 crate）
  - 优点：强制接口边界，依赖清晰
  - 缺点：改动大，需要定义公共 trait 和类型

### 2. 各模块的接口是什么？

每个功能域需要定义 trait，例如：

```rust
trait Auditor {
    fn audit(&self, op: &str, agent: &str, result: &str, target: Option<&str>) -> Result<()>;
}

trait GitOps {
    fn git_log(&self, limit: usize) -> Result<Vec<GitCommitInfo>>;
    fn git_ref_get(&self, name: &str) -> Result<String>;
    fn git_ref_set(&self, name: &str, oid: &str) -> Result<()>;
    // ...
}

trait AgentRegistry {
    fn register(&mut self, name: &str, level: Level, zones: Vec<String>, parent: Option<&str>) -> Result<AgentInfo>;
    fn revoke(&mut self, id: &str) -> Result<()>;
    fn list(&self) -> Result<Vec<AgentInfo>>;
}
```

### 3. 仲裁器（Arbiter）的位置

当前 cluster.py 中的 coordinator 就是仲裁器，但仲裁逻辑在 Python 脚本里。
白泽是否应该内置仲裁器模块？如果是，它调用哪些接口？

### 4. 依赖方向

```
AgentManager → Auditor（注册 agent 时审计）
FileGateway  → AgentManager（验证权限）, Auditor（审计）, WorkspaceManager
SyncEngine   → FileGateway（push/pull）, GitOps（主仓库）, Auditor
```

需要确认是否有循环依赖风险。

---

## 待决定

1. 拆分粒度？
2. 仲裁器是否内置？
3. 接口设计先从哪个域开始？
