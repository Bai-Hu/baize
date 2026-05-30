use std::collections::HashMap;

use baize_core::scope::{ElevationMode, Level};
use baize_core::ROOT_AGENT_ID;
use baize_server::pipeline::{
    AgentRegistry, ElevationManager, DataOps, FileSync, GitOps,
    ApprovalManager,
};
use baize_server::pipeline::auditor::Auditor;
use baize_server::Baize;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "bz", about = "白泽 — Agent 治理框架")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 初始化仓库
    Init {
        /// 数据库路径
        #[arg(long, default_value = "baize.db")]
        db: String,
        /// workspace 根目录
        #[arg(long, default_value = ".baize/workspaces")]
        workspace: String,
        /// 主仓库目录
        #[arg(long, default_value = ".baize/main")]
        main_repo: String,
    },

    /// Agent 管理
    Agent {
        #[command(subcommand)]
        action: AgentAction,
    },

    /// Blob 操作
    Blob {
        #[command(subcommand)]
        action: BlobAction,
    },

    /// Label 操作
    Label {
        #[command(subcommand)]
        action: LabelAction,
    },

    /// Ref 操作
    Ref {
        #[command(subcommand)]
        action: RefAction,
    },

    /// Log
    Log,

    /// 借权管理
    Elevate {
        #[command(subcommand)]
        action: ElevateAction,
    },

    /// 追溯查询（身份链）
    Trace {
        /// agent id
        target: String,
    },

    /// 审计日志
    Audit {
        #[command(subcommand)]
        action: Option<AuditAction>,
    },

    /// 仓库统计
    Stats,

    /// 导入外部数据
    Import {
        /// 文件路径
        file: String,
        /// 来源
        #[arg(long)]
        source: String,
        /// 信任级别 (0-4)
        #[arg(long, default_value = "2")]
        trust_level: u8,
        #[arg(long, default_value = ROOT_AGENT_ID)]
        agent: String,
    },

    /// 导出数据
    Export {
        /// blob hash
        hash: String,
        /// 输出路径
        #[arg(long)]
        output: String,
        #[arg(long, default_value = ROOT_AGENT_ID)]
        agent: String,
    },

    /// 文件操作（网关代理）
    File {
        #[command(subcommand)]
        action: FileAction,
    },

    /// Push: workspace 快照提交到主仓库
    Push {
        #[arg(short, long)]
        message: String,
        #[arg(long)]
        r#ref: Option<String>,
        #[arg(long, default_value = ROOT_AGENT_ID)]
        agent: String,
        /// 自动 git commit（跳过人工审批）
        #[arg(long)]
        auto_commit: bool,
    },

    /// Pull: 主仓库同步到 workspace
    Pull {
        #[arg(long)]
        r#ref: Option<String>,
        #[arg(long, default_value = ROOT_AGENT_ID)]
        agent: String,
    },

    /// 意图操作 (v1)
    Intent {
        #[command(subcommand)]
        action: IntentAction,
    },

    /// 回执操作 (v1)
    Receipt {
        #[command(subcommand)]
        action: ReceiptAction,
    },

    /// 授权操作 (v1)
    Authz {
        #[command(subcommand)]
        action: AuthzAction,
    },

    /// 会话操作 (v1)
    Session {
        #[command(subcommand)]
        action: SessionAction,
    },

    /// CNV 全链路校验 (v1)
    Cnv {
        #[command(subcommand)]
        action: CnvAction,
    },

    /// 审批管理
    Approval {
        #[command(subcommand)]
        action: ApprovalCliAction,
    },

    /// 启动 HTTP API 服务器
    Serve {
        /// 监听地址
        #[arg(long, default_value = "127.0.0.1:3000")]
        addr: String,
        /// 数据库路径
        #[arg(long, default_value = "baize.db")]
        db: String,
        /// workspace 根目录
        #[arg(long, default_value = ".baize/workspaces")]
        workspace: String,
        /// 主仓库目录
        #[arg(long, default_value = ".baize/main")]
        main_repo: String,
    },
}

#[derive(Subcommand)]
enum AgentAction {
    /// 注册 Agent
    Register {
        name: String,
        #[arg(long)]
        level: u8,
        #[arg(long, value_delimiter = ',')]
        zones: Vec<String>,
        #[arg(long)]
        parent: Option<String>,
    },
    /// 子 Agent（委托）
    Delegate {
        parent: String,
        name: String,
        #[arg(long)]
        level: u8,
        #[arg(long, value_delimiter = ',')]
        zones: Vec<String>,
    },
    /// 撤销 Agent
    Revoke {
        agent_id: String,
    },
    /// 列出所有 Agent
    List,
    /// 查询凭证状态 (v1)
    Status {
        agent_id: String,
    },
    /// 暂停凭证 (v1)
    Suspend {
        agent_id: String,
        #[arg(long, default_value = "")]
        reason: String,
    },
    /// 恢复凭证 (v1)
    Reactivate {
        agent_id: String,
        #[arg(long, default_value = "")]
        reason: String,
    },
    /// 生成运行态证明 (v1)
    Proof {
        agent_id: String,
    },
}

#[derive(Subcommand)]
enum BlobAction {
    /// 写入 blob
    Write {
        #[arg(long)]
        content: Option<String>,
        /// 从文件读取内容（解决多行内容中 `---` 被 clap 误解析的问题）
        #[arg(long)]
        content_file: Option<String>,
        #[arg(long, value_delimiter = ',')]
        labels: Option<String>,
        #[arg(long, default_value = ROOT_AGENT_ID)]
        agent: String,
    },
    /// 读取 blob
    Read {
        hash: String,
    },
    /// 查询 blob
    Query {
        #[arg(long, value_delimiter = ',')]
        labels: Option<String>,
    },
}

#[derive(Subcommand)]
enum LabelAction {
    /// 追加 label
    Add {
        entity_hash: String,
        key: String,
        value: String,
        #[arg(long, default_value = ROOT_AGENT_ID)]
        agent: String,
    },
    /// 查询 label
    Query {
        key: String,
        #[arg(long)]
        value: Option<String>,
    },
}

#[derive(Subcommand)]
enum RefAction {
    /// 获取 Git ref
    Get {
        name: String,
    },
    /// 设置 Git ref
    Set {
        name: String,
        /// Git commit OID
        oid: String,
    },
    /// 删除 Git ref（不可删除 HEAD）
    Delete {
        name: String,
    },
    /// 列出 Git refs
    List,
}

#[derive(Subcommand)]
enum ElevateAction {
    /// 申请借权
    Request {
        #[arg(long, value_delimiter = ',')]
        zones: Vec<String>,
        #[arg(long, default_value = "readonly")]
        mode: String,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        agent: String,
        #[arg(long)]
        duration: Option<String>,
    },
    /// 审批借权
    Approve {
        request_id: String,
        #[arg(long, default_value = ROOT_AGENT_ID)]
        agent: String,
    },
    /// 归还借权
    Return {
        request_id: String,
        #[arg(long)]
        agent: String,
    },
    /// 列出借权记录
    List,
}

#[derive(Subcommand)]
enum AuditAction {
    /// 查看审计日志（默认）
    Log,
    /// 验证审计哈希链 (v1)
    ChainVerify,
}

#[derive(Subcommand)]
enum FileAction {
    /// 写入文件
    Write {
        /// 相对路径（如 config/app.yaml）
        path: String,
        #[arg(long)]
        content: Option<String>,
        /// 从文件读取内容
        #[arg(long)]
        content_file: Option<String>,
        #[arg(long, value_delimiter = ',')]
        labels: Option<String>,
        #[arg(long, default_value = ROOT_AGENT_ID)]
        agent: String,
    },
    /// 读取文件
    Read {
        path: String,
        #[arg(long, default_value = ROOT_AGENT_ID)]
        agent: String,
    },
    /// 删除文件
    Rm {
        path: String,
        #[arg(long, default_value = ROOT_AGENT_ID)]
        agent: String,
    },
    /// 列出文件
    Ls {
        #[arg(long, default_value = ROOT_AGENT_ID)]
        agent: String,
    },
}

// ─── v1 新增 CLI 子命令 ───

#[derive(Subcommand)]
enum IntentAction {
    /// 创建通用意图
    Create {
        #[arg(long)]
        content: Option<String>,
        /// 从文件读取内容
        #[arg(long)]
        content_file: Option<String>,
        #[arg(long, default_value = ROOT_AGENT_ID)]
        agent: String,
    },
    /// 派生子意图
    Derive {
        #[arg(long)]
        content: Option<String>,
        /// 从文件读取内容
        #[arg(long)]
        content_file: Option<String>,
        #[arg(long, default_value = ROOT_AGENT_ID)]
        agent: String,
    },
    /// 读取意图
    Read {
        hash: String,
    },
    /// 查询意图
    Query {
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        owner: Option<String>,
    },
}

#[derive(Subcommand)]
enum ReceiptAction {
    /// 创建执行回执
    Create {
        #[arg(long)]
        content: Option<String>,
        /// 从文件读取内容
        #[arg(long)]
        content_file: Option<String>,
        #[arg(long, default_value = ROOT_AGENT_ID)]
        agent: String,
    },
    /// 读取回执
    Read {
        hash: String,
    },
    /// 查询回执
    Query {
        #[arg(long)]
        executor: Option<String>,
        #[arg(long)]
        status: Option<String>,
    },
}

#[derive(Subcommand)]
enum AuthzAction {
    /// 签发授权
    Issue {
        #[arg(long)]
        content: Option<String>,
        /// 从文件读取内容
        #[arg(long)]
        content_file: Option<String>,
        #[arg(long, default_value = ROOT_AGENT_ID)]
        agent: String,
    },
    /// 委托子授权
    Delegate {
        #[arg(long)]
        content: Option<String>,
        /// 从文件读取内容
        #[arg(long)]
        content_file: Option<String>,
        #[arg(long, default_value = ROOT_AGENT_ID)]
        agent: String,
    },
    /// 校验授权
    Verify {
        hash: String,
        #[arg(long)]
        action_type: String,
    },
    /// 读取授权
    Read {
        hash: String,
    },
}

#[derive(Subcommand)]
enum SessionAction {
    /// 创建会话
    Create {
        #[arg(long)]
        session_id: String,
        #[arg(long)]
        peer_a: String,
        #[arg(long)]
        peer_b: String,
        #[arg(long, default_value = "")]
        ephemeral_pub: String,
        #[arg(long, value_delimiter = ',', default_value = "AES-256-GCM")]
        cipher_suites: Vec<String>,
        #[arg(long, default_value = "")]
        credential_digest_a: String,
        #[arg(long, default_value = "")]
        credential_digest_b: String,
        #[arg(long, default_value = "")]
        handshake_transcript_digest: String,
        #[arg(long)]
        expires_at: Option<String>,
        #[arg(long, default_value = ROOT_AGENT_ID)]
        agent: String,
    },
    /// 读取会话
    Read {
        session_id: String,
    },
    /// 接受会话
    Accept {
        session_id: String,
        #[arg(long)]
        credential_digest_responder: String,
        #[arg(long)]
        ephemeral_pub: String,
        #[arg(long, default_value = "AES-256-GCM")]
        selected_cipher_suite: String,
        #[arg(long)]
        handshake_transcript_digest: String,
        #[arg(long)]
        expires_at: Option<String>,
        #[arg(long, default_value = ROOT_AGENT_ID)]
        agent: String,
    },
    /// 关闭 session
    Close {
        session_id: String,
        #[arg(long)]
        reason: Option<String>,
        #[arg(long, default_value = ROOT_AGENT_ID)]
        agent: String,
    },
}

#[derive(Subcommand)]
enum CnvAction {
    /// CNV 全链路校验
    Verify {
        #[arg(long)]
        receipt: String,
    },
}

#[derive(Subcommand)]
enum ApprovalCliAction {
    /// 列出待我审批的请求
    Pending {
        #[arg(long, default_value = ROOT_AGENT_ID)]
        agent: String,
    },
    /// 查看请求详情（含传导链）
    Show {
        /// 请求 ID
        id: String,
        #[arg(long, default_value = ROOT_AGENT_ID)]
        agent: String,
    },
    /// 审批通过
    Approve {
        /// 请求 ID
        id: String,
        /// 授予使用次数
        #[arg(long, default_value = "1")]
        count: u32,
        /// 备注
        #[arg(long)]
        note: Option<String>,
        #[arg(long, default_value = ROOT_AGENT_ID)]
        agent: String,
    },
    /// 驳回请求
    Reject {
        /// 请求 ID
        id: String,
        /// 原因
        #[arg(long)]
        reason: Option<String>,
        #[arg(long, default_value = ROOT_AGENT_ID)]
        agent: String,
    },
    /// 越权上传
    Escalate {
        /// 请求 ID
        id: String,
        /// 原因
        #[arg(long)]
        reason: Option<String>,
        #[arg(long, default_value = ROOT_AGENT_ID)]
        agent: String,
    },
    /// 创建预授权
    Preauth {
        /// 被授权者 agent ID
        #[arg(long)]
        grantee: String,
        /// 操作类型（如 push, file_write）
        #[arg(long)]
        action: String,
        /// 授权次数
        #[arg(long, default_value = "1")]
        count: u32,
        #[arg(long, default_value = ROOT_AGENT_ID)]
        agent: String,
    },
    /// 列出预授权
    PreauthList {
        #[arg(long, default_value = ROOT_AGENT_ID)]
        agent: String,
    },
    /// 删除预授权（仅 root 或授权者）
    PreauthDelete {
        /// 预授权 ID
        id: String,
        #[arg(long, default_value = ROOT_AGENT_ID)]
        agent: String,
    },
    /// 查看审批策略
    Policy {
        #[arg(long, default_value = ROOT_AGENT_ID)]
        agent: String,
    },
    /// 更新审批策略（从 JSON 文件，仅 root）
    PolicySet {
        /// JSON 文件路径
        file: String,
        #[arg(long, default_value = ROOT_AGENT_ID)]
        agent: String,
    },
}

fn open_baize() -> anyhow::Result<Baize> {
    let db = "baize.db";
    let ws = ".baize/workspaces";
    let main = ".baize/main";
    Ok(Baize::init(db, ws, main)?)
}

/// 校验文件路径不包含路径穿越
fn validate_path(path: &std::path::Path) -> anyhow::Result<()> {
    for component in path.components() {
        if matches!(component, std::path::Component::ParentDir) {
            anyhow::bail!("path traversal not allowed: {}", path.display());
        }
    }
    Ok(())
}

fn parse_labels(input: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in input.split(',') {
        if let Some((k, v)) = pair.split_once('=') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    map
}

/// 从 --content 或 --content-file 解析内容
///
/// 解决 clap 将 YAML `---` 视为 `--` 选项终止符的问题：
/// 多行内容（YAML/JSON）应通过 --content-file 传入。
fn resolve_content(content: Option<String>, content_file: Option<String>) -> anyhow::Result<String> {
    match (content, content_file) {
        (Some(c), None) => Ok(c),
        (None, Some(f)) => {
            let path = std::path::Path::new(&f);
            validate_path(path)?;
            Ok(std::fs::read_to_string(path)?)
        }
        (None, None) => anyhow::bail!("either --content or --content-file is required"),
        (Some(_), Some(_)) => anyhow::bail!("cannot use both --content and --content-file"),
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { db, workspace, main_repo } => {
            let baize = Baize::init(&db, &workspace, &main_repo)?;
            println!("白泽仓库初始化完成");
            println!("  数据库: {}", db);
            println!("  工作区: {}", workspace);
            println!("  主仓库: {}", main_repo);
            println!("  Root CA: baize-root (level 4)");
            drop(baize);
            Ok(())
        }

        Commands::Agent { action } => {
            let mut baize = open_baize()?;
            match action {
                AgentAction::Register { name, level, zones, parent } => {
                    let (id, bundle) = baize.agent_register(
                        ROOT_AGENT_ID,
                        &name,
                        Level(level),
                        zones.iter().map(|s| s.as_str()).collect(),
                        parent.as_deref(),
                    )?;
                    println!("Agent 注册成功: {}", id);
                    println!("  Level: {}", bundle.identity.level);
                    println!("  Zones: {:?}", bundle.identity.zones);
                }
                AgentAction::Delegate { parent, name, level, zones } => {
                    let (id, bundle) = baize.agent_register(
                        ROOT_AGENT_ID,
                        &name,
                        Level(level),
                        zones.iter().map(|s| s.as_str()).collect(),
                        Some(&parent),
                    )?;
                    println!("子 Agent 注册成功: {} (父: {})", id, parent);
                    println!("  Level: {}", bundle.identity.level);
                    println!("  Zones: {:?}", bundle.identity.zones);
                }
                AgentAction::Revoke { agent_id } => {
                    baize.agent_revoke(ROOT_AGENT_ID, &agent_id)?;
                    println!("Agent {} 已撤销", agent_id);
                }
                AgentAction::List => {
                    let agents = baize.agent_list();
                    println!("已注册 Agent ({}):", agents.len());
                    for (id, identity) in agents {
                        println!("  {} | L{} | zones {:?} | parent {:?}",
                            id, identity.level, identity.zones, identity.parent_id);
                    }
                }
                AgentAction::Status { agent_id } => {
                    let status = baize.credential_status(&agent_id)?;
                    println!("Agent {} 状态: {}", agent_id, status);
                }
                AgentAction::Suspend { agent_id, reason } => {
                    baize.update_credential_status(
                        &agent_id,
                        baize_core::cert::CredentialStatus::Suspended,
                        &reason,
                    )?;
                    println!("Agent {} 已暂停", agent_id);
                }
                AgentAction::Reactivate { agent_id, reason } => {
                    baize.update_credential_status(
                        &agent_id,
                        baize_core::cert::CredentialStatus::Active,
                        &reason,
                    )?;
                    println!("Agent {} 已恢复", agent_id);
                }
                AgentAction::Proof { agent_id } => {
                    let now = chrono::Utc::now();
                    let proof_id = format!("proof-{}-{}", agent_id, now.timestamp_millis());
                    let expires = (now + chrono::Duration::minutes(5)).to_rfc3339();

                    // credential_digest: agent credential blob 的 hash
                    let (credential_digest, cert_labels) = {
                        let mut filter = HashMap::new();
                        filter.insert("type".to_string(), "agent-cert".to_string());
                        filter.insert("x-cert-agent".to_string(), agent_id.clone());
                        let certs = baize.storage.blob_query(&filter)?;
                        let cert = certs.first()
                            .ok_or_else(|| anyhow::anyhow!("agent certificate not found: {}", agent_id))?;
                        (cert.hash.clone(), cert.labels.clone())
                    };

                    // instance_state_attributes: 默认运行态属性
                    let instance_attrs = serde_json::json!({
                        "instance_id": agent_id,
                        "instance_status": "running"
                    });

                    // binding_context_digest: 使用 ASL 标准计算逻辑，与 server 端验证保持一致
                    let binding_digest = baize_asl::AslAdapter::compute_binding_context_digest(
                        &cert_labels,
                        &instance_attrs,
                    );

                    let proof = baize_asl::payload::RuntimeProofContent {
                        proof_id: proof_id.clone(),
                        credential_digest: credential_digest.clone(),
                        instance_state_attributes: instance_attrs,
                        binding_context_digest: binding_digest,
                        proof_anchor_mode: baize_asl::payload::ProofAnchorMode::CredentialAnchored,
                        issued_at: now.to_rfc3339(),
                        expires_at: expires.clone(),
                    };
                    let content = serde_json::to_string(&proof)?;
                    let labels = HashMap::from([
                        ("type".to_string(), "runtime-proof".to_string()),
                        ("x-proof-agent".to_string(), agent_id.clone()),
                        ("x-proof-credential".to_string(), credential_digest),
                    ]);
                    let blob = baize.pipe_blob_write(&agent_id, &content, &labels)?;
                    println!("运行态证明已生成:");
                    println!("  Hash: {}", blob.hash);
                    println!("  Proof ID: {}", proof_id);
                    println!("  Anchor: CredentialAnchored");
                    println!("  Expires: {}", expires);
                }
            }
            Ok(())
        }

        Commands::Blob { action } => {
            let baize = open_baize()?;
            match action {
                BlobAction::Write { content, content_file, labels, agent } => {
                    let c = resolve_content(content, content_file)?;
                    let lbls = labels.map(|s| parse_labels(&s)).unwrap_or_default();
                    let blob = baize.pipe_blob_write(&agent, &c, &lbls)?;
                    println!("Blob 写入成功: {}", blob.hash);
                    // 提示：ASL 操作应使用专用命令
                    if c.contains("\"intent_id\"") || c.contains("\"receipt_id\"")
                        || c.contains("\"authorization_id\"") || c.contains("\"session_id\"")
                    {
                        eprintln!("[提示] 检测到 ASL 结构内容，建议使用 bz intent/receipt/authz/session 命令代替 bz blob write");
                    }
                }
                BlobAction::Read { hash } => {
                    let blob = baize.storage.blob_read(&hash)?;
                    println!("Hash: {}", blob.hash);
                    println!("Content: {}", blob.content);
                    println!("Labels: {:?}", blob.labels);
                    println!("Created: {}", blob.created_at);
                }
                BlobAction::Query { labels } => {
                    let filter = labels.map(|s| parse_labels(&s)).unwrap_or_default();
                    let blobs = baize.storage.blob_query(&filter)?;
                    println!("找到 {} 个 blob:", blobs.len());
                    for b in blobs {
                        println!("  {} | {} | {:?}", b.hash, b.created_at, b.labels);
                    }
                }
            }
            Ok(())
        }

        Commands::Label { action } => {
            let baize = open_baize()?;
            match action {
                LabelAction::Add { entity_hash, key, value, agent } => {
                    baize.pipe_label_add(&agent, &entity_hash, &key, &value)?;
                    println!("Label 添加成功: {}={}", key, value);
                }
                LabelAction::Query { key, value } => {
                    let labels = baize.storage.label_query(&key, value.as_deref())?;
                    println!("找到 {} 个 label:", labels.len());
                    for l in labels {
                        println!("  {} | {}={}", l.entity_hash, l.key, l.value);
                    }
                }
            }
            Ok(())
        }

        Commands::Ref { action } => {
            let baize = open_baize()?;
            match action {
                RefAction::Get { name } => {
                    let oid = baize.git_ref_get(&name)?;
                    println!("{} → {}", name, oid);
                }
                RefAction::Set { name, oid } => {
                    baize.git_ref_set(&name, &oid)?;
                    println!("Ref 设置成功: {} → {}", name, oid);
                }
                RefAction::Delete { name } => {
                    baize.git_ref_delete(&name)?;
                    println!("Ref 已删除: {}", name);
                }
                RefAction::List => {
                    let refs = baize.git_ref_list()?;
                    println!("Git Refs ({}):", refs.len());
                    for r in refs {
                        println!("  {}", r);
                    }
                }
            }
            Ok(())
        }

        Commands::Log => {
            let baize = open_baize()?;
            match baize.git_log(50) {
                Ok(commits) => {
                    if commits.is_empty() {
                        println!("(无 git commit)");
                    } else {
                        for c in commits {
                            println!("{} {} ({})", &c.hash[..12.min(c.hash.len())], c.message, c.author);
                        }
                    }
                }
                Err(_) => println!("(主仓库无 Git 历史或未初始化)"),
            }
            Ok(())
        }

        Commands::Elevate { action } => {
            let mut baize = open_baize()?;
            match action {
                ElevateAction::Request { zones, mode, reason, agent, duration } => {
                    let m = match ElevationMode::from_str_lower(&mode) {
                        Some(m) => m,
                        None => anyhow::bail!("invalid mode '{}', expected: readonly, write, readwrite", mode),
                    };
                    let id = baize.elevation_request(
                        &agent,
                        zones.iter().map(|s| s.as_str()).collect(),
                        m,
                        &reason,
                        duration.as_deref(),
                    )?;
                    println!("借权申请已提交: {}", id);
                }
                ElevateAction::Approve { request_id, agent } => {
                    baize.elevation_approve(&request_id, &agent)?;
                    println!("借权已审批: {}", request_id);
                }
                ElevateAction::Return { request_id, agent } => {
                    baize.elevation_return(&request_id, &agent, &agent)?;
                    println!("借权已归还: {}", request_id);
                }
                ElevateAction::List => {
                    let reqs = baize.elevation_list()?;
                    println!("借权记录 ({}):", reqs.len());
                    for r in reqs {
                        let expires = r.expires_at
                            .map(|e| format!(" (expires: {})", e))
                            .unwrap_or_default();
                        println!("  {} | {} | {:?} | {:?}{}", r.id, r.agent_id, r.mode, r.status, expires);
                    }
                }
            }
            Ok(())
        }

        Commands::Trace { target } => {
            let baize = open_baize()?;
            let chain = baize.trace_identity(&target)?;
            println!("身份链 ({} 级):", chain.len());
            for id in &chain {
                println!("  {} | L{} | zones {:?} | parent {:?}",
                    id.agent_id, id.level, id.zones, id.parent_id);
            }
            Ok(())
        }

        Commands::Audit { action } => {
            match action {
                Some(AuditAction::ChainVerify) => {
                    let baize = open_baize()?;
                    let result = baize.verify_chain()?;
                    println!("审计链验证:");
                    println!("  有效: {}", result.valid);
                    println!("  链长: {}", result.chain_length);
                    if !result.head_digest.is_empty() {
                        println!("  链头: {}", &result.head_digest[..16.min(result.head_digest.len())]);
                        println!("  创世: {}", &result.genesis_digest[..16.min(result.genesis_digest.len())]);
                    }
                    if !result.errors.is_empty() {
                        println!("  错误:");
                        for e in &result.errors {
                            println!("    - {}", e);
                        }
                    }
                }
                Some(AuditAction::Log) | None => {
                    let baize = open_baize()?;
                    let mut filter = HashMap::new();
                    filter.insert("x-audit".to_string(), "true".to_string());
                    let blobs = baize.storage.blob_query(&filter)?;
                    println!("审计日志 ({} 条):", blobs.len());
                    for b in &blobs {
                        let chain_idx = b.labels.get("x-audit-chain-index")
                            .map(|s| s.as_str())
                            .unwrap_or("-");
                        println!("  {} | {} | {} | idx={}",
                            &b.hash[..12.min(b.hash.len())],
                            b.labels.get("x-audit-type").unwrap_or(&"-".to_string()),
                            b.labels.get("x-audit-agent").unwrap_or(&"-".to_string()),
                            chain_idx,
                        );
                    }
                }
            }
            Ok(())
        }

        Commands::Stats => {
            let baize = open_baize()?;
            match baize.repo_stats() {
                Ok(stats) => {
                    println!("仓库统计:");
                    println!("  Blobs:   {}", stats.total_blobs);
                    println!("  Commits: {}", stats.total_commits);
                    println!("  Refs:    {}", stats.total_refs);
                }
                Err(e) => println!("获取统计失败: {}", e),
            }
            Ok(())
        }

        Commands::Import { file, source, trust_level, agent } => {
            let path = std::path::Path::new(&file);
            validate_path(path)?;
            let baize = open_baize()?;
            let content = std::fs::read_to_string(path)?;
            let blob = baize.pipe_import(&agent, &content, &source, trust_level, None)?;
            println!("导入成功: {} (trust-level: {})", blob.hash, trust_level);
            Ok(())
        }

        Commands::Export { hash, output, agent } => {
            let out_path = std::path::Path::new(&output);
            validate_path(out_path)?;
            let baize = open_baize()?;
            let blob = baize.pipe_export(&agent, &hash)?;
            std::fs::write(out_path, &blob.content)?;
            println!("导出成功: {} → {}", hash, output);
            Ok(())
        }

        Commands::File { action } => {
            let baize = open_baize()?;
            match action {
                FileAction::Write { path, content, content_file, labels, agent } => {
                    let c = resolve_content(content, content_file)?;
                    let lbls = labels.map(|s| parse_labels(&s)).unwrap_or_default();
                    let record = baize.pipe_file_write(&agent, &path, c.as_bytes(), Some(lbls))?;
                    println!("文件写入成功: {}", record.path);
                    println!("  Hash: {}", record.hash);
                    println!("  Size: {} bytes", record.size);
                }
                FileAction::Read { path, agent } => {
                    let file = baize.pipe_file_read(&agent, &path)?;
                    println!("Path: {}", file.path);
                    println!("Hash: {}", file.hash);
                    println!("Size: {} bytes", file.size);
                    println!("---");
                    println!("{}", String::from_utf8_lossy(&file.content));
                }
                FileAction::Rm { path, agent } => {
                    baize.pipe_file_delete(&agent, &path)?;
                    println!("文件已删除: {}", path);
                }
                FileAction::Ls { agent } => {
                    let files = baize.pipe_file_list(&agent)?;
                    println!("文件列表 ({}):", files.len());
                    for f in &files {
                        println!("  {}", f);
                    }
                }
            }
            Ok(())
        }

        Commands::Push { message, r#ref, agent, auto_commit } => {
            let baize = open_baize()?;
            let result = baize.pipe_push(&agent, &message, r#ref.as_deref())?;
            println!("Push 成功: {} 个文件", result.files);
            if auto_commit {
                let oid = baize.git_commit_all(&message, &agent)?;
                println!("  Auto-commit: {}", &oid[..12.min(oid.len())]);
            } else if result.pending {
                println!("  状态: 等待 git commit（使用 --auto-commit 自动提交）");
            }
            Ok(())
        }

        Commands::Pull { r#ref, agent } => {
            let baize = open_baize()?;
            let result = baize.pipe_pull(&agent, r#ref.as_deref())?;
            println!("Pull 成功: {} 个文件", result.files);
            Ok(())
        }

        // ─── v1 新增 CLI 命令 ───

        Commands::Intent { action } => {
            match action {
                IntentAction::Create { content, content_file, agent } => {
                    let c = resolve_content(content, content_file)?;
                    let baize = open_baize()?;
                    let payload = baize_asl::AslAdapter::intent_from_blob(&c)?;
                    let labels = baize_asl::AslAdapter::intent_to_labels(&payload);
                    let blob = baize.pipe_blob_write(&agent, &c, &labels)?;
                    println!("意图创建成功: {}", blob.hash);
                }
                IntentAction::Derive { content, content_file, agent } => {
                    let c = resolve_content(content, content_file)?;
                    let baize = open_baize()?;
                    let payload = baize_asl::AslAdapter::sub_intent_from_blob(&c)?;
                    let labels = baize_asl::AslAdapter::sub_intent_to_labels(&payload);
                    let blob = baize.pipe_blob_write(&agent, &c, &labels)?;
                    println!("子意图派生成功: {}", blob.hash);
                }
                IntentAction::Read { hash } => {
                    let baize = open_baize()?;
                    let blob = baize.storage.blob_read(&hash)?;
                    println!("Hash: {}", blob.hash);
                    println!("Content: {}", blob.content);
                    println!("Labels: {:?}", blob.labels);
                }
                IntentAction::Query { status, owner } => {
                    let baize = open_baize()?;
                    let mut filter = HashMap::new();
                    filter.insert("type".to_string(), "intent".to_string());
                    if let Some(s) = status {
                        filter.insert("x-intent-status".to_string(), s);
                    }
                    if let Some(o) = owner {
                        filter.insert("x-intent-owner".to_string(), o);
                    }
                    let blobs = baize.storage.blob_query_metadata(&filter)?;
                    println!("找到 {} 条意图:", blobs.len());
                    for (hash, labels) in &blobs {
                        println!("  {} | {} | {}",
                            &hash[..12.min(hash.len())],
                            labels.get("x-intent-id").unwrap_or(&"-".to_string()),
                            labels.get("x-intent-status").unwrap_or(&"-".to_string()),
                        );
                    }
                }
            }
            Ok(())
        }

        Commands::Receipt { action } => {
            match action {
                ReceiptAction::Create { content, content_file, agent } => {
                    let c = resolve_content(content, content_file)?;
                    let baize = open_baize()?;
                    let payload = baize_asl::AslAdapter::receipt_from_blob(&c)?;
                    let labels = baize_asl::AslAdapter::receipt_to_labels(&payload);
                    let blob = baize.pipe_blob_write(&agent, &c, &labels)?;
                    println!("回执创建成功: {}", blob.hash);
                }
                ReceiptAction::Read { hash } => {
                    let baize = open_baize()?;
                    let blob = baize.storage.blob_read(&hash)?;
                    println!("Hash: {}", blob.hash);
                    println!("Content: {}", blob.content);
                    println!("Labels: {:?}", blob.labels);
                }
                ReceiptAction::Query { executor, status } => {
                    let baize = open_baize()?;
                    let mut filter = HashMap::new();
                    filter.insert("type".to_string(), "receipt".to_string());
                    if let Some(e) = executor {
                        filter.insert("x-receipt-executor".to_string(), e);
                    }
                    if let Some(s) = status {
                        filter.insert("x-receipt-status".to_string(), s);
                    }
                    let records = baize.storage.blob_query_metadata(&filter)?;
                    println!("找到 {} 条回执:", records.len());
                    for (hash, labels) in &records {
                        println!("  {} | {} | {} | {}",
                            &hash[..12.min(hash.len())],
                            labels.get("x-receipt-id").unwrap_or(&"-".to_string()),
                            labels.get("x-receipt-executor").unwrap_or(&"-".to_string()),
                            labels.get("x-receipt-status").unwrap_or(&"-".to_string()),
                        );
                    }
                }
            }
            Ok(())
        }

        Commands::Authz { action } => {
            match action {
                AuthzAction::Issue { content, content_file, agent } => {
                    let c = resolve_content(content, content_file)?;
                    let baize = open_baize()?;
                    let payload = baize_asl::AslAdapter::authorization_from_blob(&c)?;
                    let labels = baize_asl::AslAdapter::authorization_to_labels(&payload);
                    let blob = baize.pipe_blob_write(&agent, &c, &labels)?;
                    println!("授权签发成功: {}", blob.hash);
                }
                AuthzAction::Delegate { content, content_file, agent } => {
                    let c = resolve_content(content, content_file)?;
                    let baize = open_baize()?;
                    let payload = baize_asl::AslAdapter::authorization_from_blob(&c)?;
                    let labels = baize_asl::AslAdapter::authorization_to_labels(&payload);
                    let blob = baize.pipe_blob_write(&agent, &c, &labels)?;
                    println!("委托子授权成功: {}", blob.hash);
                }
                AuthzAction::Verify { hash, action_type } => {
                    let baize = open_baize()?;
                    let result = baize_asl::verify::verify_authorization(
                        baize.store(), &hash, &action_type,
                        &baize_asl::verify::ExecutionContext::default(),
                    )?;
                    println!("授权校验结果:");
                    println!("  有效: {}", result.valid);
                    println!("  校验项: {:?}", result.checks);
                    if !result.errors.is_empty() {
                        println!("  错误:");
                        for e in &result.errors {
                            println!("    - {}", e);
                        }
                    }
                }
                AuthzAction::Read { hash } => {
                    let baize = open_baize()?;
                    let blob = baize.storage.blob_read(&hash)?;
                    println!("Hash: {}", blob.hash);
                    println!("Content: {}", blob.content);
                    println!("Labels: {:?}", blob.labels);
                }
            }
            Ok(())
        }

        Commands::Session { action } => {
            match action {
                SessionAction::Create {
                    session_id, peer_a, peer_b,
                    ephemeral_pub, cipher_suites,
                    credential_digest_a, credential_digest_b,
                    handshake_transcript_digest,
                    expires_at, agent,
                } => {
                    let baize = open_baize()?;
                    let now = chrono::Utc::now();
                    let expires = expires_at.unwrap_or_else(|| {
                        (now + chrono::Duration::minutes(30)).to_rfc3339()
                    });
                    let content = serde_json::json!({
                        "session_id": session_id,
                        "peer_a": peer_a,
                        "peer_b": peer_b,
                        "credential_hash_a": credential_digest_a,
                        "credential_hash_b": credential_digest_b,
                        "handshake_transcript_hash": handshake_transcript_digest,
                        "ephemeral_pub": ephemeral_pub,
                        "cipher_suites": cipher_suites,
                        "established_at": now.to_rfc3339(),
                        "expires_at": expires,
                    }).to_string();
                    let labels = HashMap::from([
                        ("type".to_string(), "session-init".to_string()),
                        ("x-session-id".to_string(), session_id.clone()),
                        ("x-session-peer-a".to_string(), peer_a.clone()),
                        ("x-session-peer-b".to_string(), peer_b.clone()),
                        ("x-session-status".to_string(), "active".to_string()),
                    ]);
                    let blob = baize.pipe_blob_write(&agent, &content, &labels)?;
                    println!("会话创建成功:");
                    println!("  Hash: {}", blob.hash);
                    println!("  Session ID: {}", session_id);
                    println!("  Peer A: {}", peer_a);
                    println!("  Peer B: {}", peer_b);
                    println!("  Status: active");
                }
                SessionAction::Read { session_id } => {
                    let baize = open_baize()?;
                    let mut filter = HashMap::new();
                    filter.insert("type".to_string(), "session-init".to_string());
                    filter.insert("x-session-id".to_string(), session_id.clone());
                    let blobs = baize.storage.blob_query(&filter)?;
                    if let Some(blob) = blobs.first() {
                        println!("Session ID: {}", session_id);
                        println!("Hash: {}", blob.hash);
                        println!("Content: {}", blob.content);
                        println!("Labels: {:?}", blob.labels);
                        println!("Created: {}", blob.created_at);
                    } else {
                        println!("会话 {} 未找到", session_id);
                    }
                }
                SessionAction::Accept {
                    session_id,
                    credential_digest_responder,
                    ephemeral_pub,
                    selected_cipher_suite,
                    handshake_transcript_digest,
                    expires_at,
                    agent,
                } => {
                    let baize = open_baize()?;

                    // 查找对应的 session-init blob
                    let mut filter = HashMap::new();
                    filter.insert("type".to_string(), "session-init".to_string());
                    filter.insert("x-session-id".to_string(), session_id.clone());
                    let init_blobs = baize.storage.blob_query(&filter)?;
                    if init_blobs.is_empty() {
                        anyhow::bail!("session {} not found", session_id);
                    }
                    let init_blob = &init_blobs[0];

                    let now = chrono::Utc::now();
                    let expires = expires_at.unwrap_or_else(|| {
                        (now + chrono::Duration::minutes(30)).to_rfc3339()
                    });

                    let content = serde_json::json!({
                        "session_id": session_id,
                        "initiator": init_blob.labels.get("x-session-peer-a").unwrap_or(&String::new()),
                        "responder": init_blob.labels.get("x-session-peer-b").unwrap_or(&String::new()),
                        "credential_digest_responder": credential_digest_responder,
                        "session_init_digest": init_blob.hash,
                        "ephemeral_pub": ephemeral_pub,
                        "selected_cipher_suite": selected_cipher_suite,
                        "handshake_transcript_digest": handshake_transcript_digest,
                        "established_at": now.to_rfc3339(),
                        "expires_at": expires,
                    }).to_string();

                    let labels = HashMap::from([
                        ("type".to_string(), "session-accept".to_string()),
                        ("x-session-id".to_string(), session_id.clone()),
                        ("x-session-peer-a".to_string(), init_blob.labels.get("x-session-peer-a").cloned().unwrap_or_default()),
                        ("x-session-peer-b".to_string(), init_blob.labels.get("x-session-peer-b").cloned().unwrap_or_default()),
                        ("x-session-status".to_string(), "active".to_string()),
                        ("parent".to_string(), init_blob.hash.clone()),
                    ]);
                    let blob = baize.pipe_blob_write(&agent, &content, &labels)?;
                    println!("会话接受成功:");
                    println!("  Hash: {}", blob.hash);
                    println!("  Session ID: {}", session_id);
                    println!("  Status: active");
                }
                SessionAction::Close { session_id, reason, agent } => {
                    let baize = open_baize()?;

                    // 验证 session 存在
                    let mut filter = HashMap::new();
                    filter.insert("type".to_string(), "session-init".to_string());
                    filter.insert("x-session-id".to_string(), session_id.clone());
                    let sessions = baize.storage.blob_query(&filter)?;
                    if sessions.is_empty() {
                        anyhow::bail!("session {} not found", session_id);
                    }

                    // 检查是否已关闭
                    let mut close_filter = HashMap::new();
                    close_filter.insert("type".to_string(), "session-close".to_string());
                    close_filter.insert("x-session-id".to_string(), session_id.clone());
                    let close_blobs = baize.storage.blob_query(&close_filter)?;
                    if !close_blobs.is_empty() {
                        anyhow::bail!("session {} already closed", session_id);
                    }

                    let now = chrono::Utc::now().to_rfc3339();
                    let close_content = serde_json::json!({
                        "session_id": session_id,
                        "action": "close",
                        "closed_by": agent,
                        "reason": reason.unwrap_or_default(),
                    }).to_string();
                    let labels = HashMap::from([
                        ("type".to_string(), "session-close".to_string()),
                        ("x-session-id".to_string(), session_id.clone()),
                        ("x-session-status".to_string(), "closed".to_string()),
                        ("x-session-closed-at".to_string(), now),
                    ]);
                    let blob = baize.pipe_blob_write(&agent, &close_content, &labels)?;
                    println!("Session {} 已关闭: {}", session_id, blob.hash);
                }
            }
            Ok(())
        }

        Commands::Cnv { action } => {
            match action {
                CnvAction::Verify { receipt } => {
                    let baize = open_baize()?;
                    let result = baize_asl::verify::cnv_verify(baize.store(), &receipt)?;
                    println!("CNV 全链路校验:");
                    println!("  有效: {}", result.valid);
                    if !result.errors.is_empty() {
                        println!("  错误:");
                        for e in &result.errors {
                            println!("    - {}", e);
                        }
                    }
                }
            }
            Ok(())
        }

        Commands::Approval { action } => {
            match action {
                ApprovalCliAction::Pending { agent } => {
                    let baize = open_baize()?;
                    let requests = baize.approval_pending(&agent)?;
                    if requests.is_empty() {
                        println!("无待审批请求");
                    } else {
                        println!("待审批请求 ({}):", requests.len());
                        for r in &requests {
                            println!("  {} | {} → {} | {} | {}",
                                &r.id[..8.min(r.id.len())],
                                r.requester_id,
                                r.action,
                                r.status,
                                r.created_at
                            );
                        }
                    }
                }
                ApprovalCliAction::Show { id, agent } => {
                    let baize = open_baize()?;
                    let req = baize.approval_show(&id, &agent)?;
                    println!("请求 ID: {}", req.id);
                    println!("请求者: {} (L{})", req.requester_id, req.requester_level);
                    println!("操作: {}", req.action);
                    println!("状态: {}", req.status);
                    if let Some(ref pending) = req.pending_at {
                        println!("等待: {}", pending);
                    }
                    println!("授予: {} (剩余 {})", req.granted_count, req.remaining_count);
                    println!("创建: {}", req.created_at);
                    if !req.chain.is_empty() {
                        println!("传导链:");
                        for hop in &req.chain {
                            println!("  {} [L{}] → {} ({})",
                                hop.agent_id, hop.level, hop.decision, hop.decided_at
                            );
                        }
                    }
                }
                ApprovalCliAction::Approve { id, count, note, agent } => {
                    let baize = open_baize()?;
                    let status = baize.approval_approve(&id, &agent, count, note.as_deref())?;
                    println!("已审批: {} → {}", id, status);
                }
                ApprovalCliAction::Reject { id, reason, agent } => {
                    let baize = open_baize()?;
                    let status = baize.approval_reject(&id, &agent, reason.as_deref())?;
                    println!("已驳回: {} → {}", id, status);
                }
                ApprovalCliAction::Escalate { id, reason, agent } => {
                    let baize = open_baize()?;
                    let status = baize.approval_escalate(&id, &agent, reason.as_deref())?;
                    println!("已越权: {} → {}", id, status);
                }
                ApprovalCliAction::Preauth { grantee, action, count, agent } => {
                    let baize = open_baize()?;
                    let approval_action = action.parse::<baize_core::approval::ApprovalAction>()
                        .map_err(|e| anyhow::anyhow!("无效操作类型: {}", e))?;
                    let pa = baize.approval_preauth(&agent, &grantee, &approval_action, count)?;
                    println!("预授权创建: {} ({} → {}, {} 次)", pa.id, pa.granter_id, pa.grantee_id, pa.remaining_count);
                }
                ApprovalCliAction::PreauthList { agent } => {
                    let baize = open_baize()?;
                    let list = baize.approval_list_preauth(&agent)?;
                    if list.is_empty() {
                        println!("无预授权");
                    } else {
                        println!("预授权 ({}):", list.len());
                        for pa in &list {
                            println!("  {} | {} → {} | {} | {}/{}",
                                &pa.id[..8.min(pa.id.len())],
                                pa.granter_id, pa.grantee_id,
                                pa.action, pa.remaining_count, pa.granted_count
                            );
                        }
                    }
                }
                ApprovalCliAction::PreauthDelete { id, agent } => {
                    let baize = open_baize()?;
                    baize.approval_delete_preauth(&id, &agent)?;
                    println!("已删除预授权: {}", id);
                }
                ApprovalCliAction::Policy { agent: _ } => {
                    let baize = open_baize()?;
                    let rules = baize.approval_policy_get();
                    if rules.is_empty() {
                        println!("当前策略: 自动通过（无规则）");
                    } else {
                        println!("审批规则 ({}):", rules.len());
                        for (i, rule) in rules.iter().enumerate() {
                            println!("  [{}] {} L{}-L{}", i + 1, rule.action, rule.level_range.0, rule.level_range.1);
                            for lc in &rule.levels {
                                println!("    L{}: auto={}, max={}", lc.level, lc.auto, lc.max_grant_count);
                            }
                        }
                    }
                }
                ApprovalCliAction::PolicySet { file, agent } => {
                    if agent != ROOT_AGENT_ID {
                        anyhow::bail!("只有 root 可以修改审批策略");
                    }
                    let baize = open_baize()?;
                    let path = std::path::Path::new(&file);
                    validate_path(path)?;
                    let content = std::fs::read_to_string(path)?;
                    let rules: Vec<baize_core::approval::ApprovalRule> = serde_json::from_str(&content)?;
                    baize.approval_policy_update(rules)?;
                    println!("策略已更新");
                }
            }
            Ok(())
        }

        Commands::Serve { addr, db, workspace, main_repo } => {
            println!("白泽 HTTP 服务启动: {}", addr);
            let baize = Baize::init(&db, &workspace, &main_repo)?;
            // tokio runtime for async serve
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                if let Err(e) = baize_server::api::serve(baize, &addr).await {
                    eprintln!("服务错误: {}", e);
                }
            });
            Ok(())
        }
    }
}
