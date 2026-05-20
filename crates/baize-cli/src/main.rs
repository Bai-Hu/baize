use std::collections::HashMap;

use baize_core::scope::{ElevationMode, Level};
use baize_core::ROOT_AGENT_ID;
use baize_server::pipeline::{
    AgentRegistry, ElevationManager, DataOps, FileSync, GitOps,
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
        content: String,
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
        content: String,
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
        content: String,
        #[arg(long, default_value = ROOT_AGENT_ID)]
        agent: String,
    },
    /// 派生子意图
    Derive {
        #[arg(long)]
        content: String,
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
        content: String,
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
        content: String,
        #[arg(long, default_value = ROOT_AGENT_ID)]
        agent: String,
    },
    /// 委托子授权
    Delegate {
        #[arg(long)]
        content: String,
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
                    baize.agent_revoke(&agent_id)?;
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
                    let credential_digest = {
                        let mut filter = HashMap::new();
                        filter.insert("type".to_string(), "agent-cert".to_string());
                        filter.insert("x-cert-agent".to_string(), agent_id.clone());
                        let certs = baize.storage.blob_query(&filter)?;
                        certs.first()
                            .map(|b| b.hash.clone())
                            .ok_or_else(|| anyhow::anyhow!("agent certificate not found: {}", agent_id))?
                    };

                    // instance_state_attributes: 默认运行态属性
                    let instance_attrs = serde_json::json!({
                        "instance_id": agent_id,
                        "instance_status": "running"
                    });

                    // binding_context_digest: credential_digest + timestamp 摘要
                    let binding_input = format!("{}:{}", credential_digest, now.to_rfc3339());
                    let binding_digest = format!("sha256:{}", {
                        use sha2::Digest;
                        let mut hasher = sha2::Sha256::new();
                        hasher.update(binding_input.as_bytes());
                        hex::encode(hasher.finalize())
                    });

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
                BlobAction::Write { content, labels, agent } => {
                    let lbls = labels.map(|s| parse_labels(&s)).unwrap_or_default();
                    let blob = baize.pipe_blob_write(&agent, &content, &lbls)?;
                    println!("Blob 写入成功: {}", blob.hash);
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
                FileAction::Write { path, content, labels, agent } => {
                    let lbls = labels.map(|s| parse_labels(&s)).unwrap_or_default();
                    let record = baize.pipe_file_write(&agent, &path, content.as_bytes(), Some(lbls))?;
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

        Commands::Push { message, r#ref, agent } => {
            let baize = open_baize()?;
            let result = baize.pipe_push(&agent, &message, r#ref.as_deref())?;
            println!("Push 成功: {} 个文件", result.files);
            if result.pending {
                println!("  状态: 等待用户审批 git commit");
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
                IntentAction::Create { content, agent } => {
                    let baize = open_baize()?;
                    let payload = baize_asl::AslAdapter::intent_from_blob(&content)?;
                    let labels = baize_asl::AslAdapter::intent_to_labels(&payload);
                    let blob = baize.pipe_blob_write(&agent, &content, &labels)?;
                    println!("意图创建成功: {}", blob.hash);
                }
                IntentAction::Derive { content, agent } => {
                    let baize = open_baize()?;
                    let payload = baize_asl::AslAdapter::sub_intent_from_blob(&content)?;
                    let labels = baize_asl::AslAdapter::sub_intent_to_labels(&payload);
                    let blob = baize.pipe_blob_write(&agent, &content, &labels)?;
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
                ReceiptAction::Create { content, agent } => {
                    let baize = open_baize()?;
                    let payload = baize_asl::AslAdapter::receipt_from_blob(&content)?;
                    let labels = baize_asl::AslAdapter::receipt_to_labels(&payload);
                    let blob = baize.pipe_blob_write(&agent, &content, &labels)?;
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
                AuthzAction::Issue { content, agent } => {
                    let baize = open_baize()?;
                    let payload = baize_asl::AslAdapter::authorization_from_blob(&content)?;
                    let labels = baize_asl::AslAdapter::authorization_to_labels(&payload);
                    let blob = baize.pipe_blob_write(&agent, &content, &labels)?;
                    println!("授权签发成功: {}", blob.hash);
                }
                AuthzAction::Delegate { content, agent } => {
                    let baize = open_baize()?;
                    let payload = baize_asl::AslAdapter::authorization_from_blob(&content)?;
                    let labels = baize_asl::AslAdapter::authorization_to_labels(&payload);
                    let blob = baize.pipe_blob_write(&agent, &content, &labels)?;
                    println!("委托子授权成功: {}", blob.hash);
                }
                AuthzAction::Verify { hash, action_type } => {
                    let baize = open_baize()?;
                    let result = baize_asl::verify::verify_authorization(
                        &baize.storage, &hash, &action_type,
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
                    let result = baize_asl::verify::cnv_verify(&baize.storage, &receipt)?;
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
