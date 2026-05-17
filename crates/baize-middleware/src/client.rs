//! 白泽客户端 trait
//!
//! 定义 agent 与白泽交互的标准接口。
//! 内部 agent 架构和外部 agent 使用同一接口。

use crate::error::ClientResult;
use crate::types::*;

/// 白泽客户端
///
/// 所有 agent 框架通过此 trait 与白泽交互。
/// 两种典型实现：
/// - `BaizeHttpClient`：通过 HTTP API 调用（外部 agent 或远程 agent）
/// - 自定义实现：直接调用 pipeline（进程内 agent）
pub trait BaizeClient {
    // ─── Agent 管理 ───

    /// 注册新 agent
    fn agent_register(&self, req: AgentRegisterRequest) -> ClientResult<AgentRegisterResponse>;

    /// 列出所有 agent
    fn agent_list(&self) -> ClientResult<Vec<AgentInfo>>;

    /// 撤销 agent
    fn agent_revoke(&self, id: &str) -> ClientResult<()>;

    // ─── Blob 操作 ───

    /// 写入 blob
    fn blob_write(&self, req: BlobWriteRequest) -> ClientResult<BlobInfo>;

    /// 读取 blob
    fn blob_read(&self, hash: &str) -> ClientResult<BlobInfo>;

    /// 按 labels 查询 blob（支持分页）
    fn blob_query(&self, req: BlobQueryRequest) -> ClientResult<Vec<BlobInfo>>;

    // ─── 文件操作 ───

    /// 写入文件
    fn file_write(&self, path: &str, req: FileWriteRequest) -> ClientResult<FileRecord>;

    /// 读取文件
    fn file_read(&self, path: &str) -> ClientResult<FileContent>;

    /// 删除文件
    fn file_delete(&self, path: &str) -> ClientResult<()>;

    /// 列出文件
    fn file_list(&self) -> ClientResult<Vec<String>>;

    // ─── 数据同步 ───

    /// Push：workspace → 主仓库工作区
    fn push(&self, req: PushRequest) -> ClientResult<PushResponse>;

    /// Pull：主仓库工作区 → workspace
    fn pull(&self, req: PullRequest) -> ClientResult<PullResponse>;

    /// Git log
    fn git_log(&self, limit: Option<usize>) -> ClientResult<Vec<GitCommitInfo>>;

    // ─── Label ───

    /// 添加 label
    fn label_add(&self, req: LabelAddRequest) -> ClientResult<()>;

    /// 查询 label（GET，query params）
    fn label_query(&self, key: &str, value: Option<&str>) -> ClientResult<Vec<LabelInfo>>;

    // ─── Git Ref ───

    /// 设置 Git ref（PUT）
    fn ref_set(&self, name: &str, oid: &str) -> ClientResult<()>;

    /// 获取 Git ref
    fn ref_get(&self, name: &str) -> ClientResult<RefGetResponse>;

    /// 删除 Git ref
    fn ref_delete(&self, name: &str) -> ClientResult<()>;

    /// 列出所有 Git ref
    fn ref_list(&self) -> ClientResult<Vec<String>>;

    // ─── Elevation ───

    /// 申请借权
    fn elevation_request(&self, req: ElevationCreateRequest) -> ClientResult<String>;

    /// 审批借权
    fn elevation_approve(&self, id: &str) -> ClientResult<ElevationStatus>;

    /// 归还借权
    fn elevation_return(&self, id: &str, req: ElevationReturnRequest) -> ClientResult<ElevationStatus>;

    /// 列出借权记录
    fn elevation_list(&self) -> ClientResult<Vec<ElevationRecord>>;

    // ─── Trace ───

    /// 身份追溯
    fn trace_identity(&self, agent_id: &str) -> ClientResult<Vec<TraceIdentityInfo>>;

    // ─── Audit ───

    /// 查询审计日志
    fn audit_query(
        &self,
        agent: Option<&str>,
        audit_type: Option<&str>,
    ) -> ClientResult<Vec<AuditRecord>>;

    // ─── Import / Export ───

    /// 导入外部数据
    fn import_data(&self, req: ImportRequest) -> ClientResult<ImportResponse>;

    /// 导出数据
    fn export_data(&self, hash: &str) -> ClientResult<BlobInfo>;

    // ─── Repo Stats ───

    /// 仓库统计信息
    fn repo_stats(&self) -> ClientResult<RepoStats>;
}
