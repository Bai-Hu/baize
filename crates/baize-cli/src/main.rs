use std::collections::HashMap;

use baize_core::scope::{ElevationMode, Level};
use baize_core::ROOT_AGENT_ID;
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

    /// Commit 操作
    Commit {
        #[command(subcommand)]
        action: CommitAction,
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

    /// 追溯查询
    Trace {
        /// 数据 hash 或 identity id
        target: String,
        /// 身份链追溯
        #[arg(long)]
        identity: bool,
    },

    /// 审计日志
    Audit,

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
enum CommitAction {
    /// 创建 commit
    Create {
        #[arg(long, value_delimiter = ',')]
        blobs: Vec<String>,
        #[arg(short, long)]
        message: String,
        #[arg(long)]
        parent: Option<String>,
        #[arg(long, default_value = ROOT_AGENT_ID)]
        agent: String,
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
    /// 设置 ref
    Set {
        name: String,
        commit_hash: String,
        #[arg(long, default_value = ROOT_AGENT_ID)]
        agent: String,
    },
    /// 获取 ref
    Get {
        name: String,
    },
    /// 删除 ref
    Delete {
        name: String,
        #[arg(long, default_value = ROOT_AGENT_ID)]
        agent: String,
    },
    /// 列出 ref
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

        Commands::Commit { action } => {
            let baize = open_baize()?;
            match action {
                CommitAction::Create { blobs, message, parent, agent } => {
                    let commit = baize.pipe_commit_create(&agent, &blobs, &message, parent.as_deref())?;
                    println!("Commit 创建成功: {}", commit.hash);
                    println!("  Message: {}", commit.message);
                    println!("  Blobs: {:?}", commit.blob_hashes);
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
                RefAction::Set { name, commit_hash, agent } => {
                    baize.pipe_ref_set(&agent, &name, &commit_hash)?;
                    println!("Ref 设置成功: {} → {}", name, commit_hash);
                }
                RefAction::Get { name } => {
                    let r = baize.storage.ref_get(&name)?;
                    println!("{} → {}", r.name, r.commit_hash);
                }
                RefAction::Delete { name, agent } => {
                    baize.pipe_ref_delete(&agent, &name)?;
                    println!("Ref {} 已删除", name);
                }
                RefAction::List => {
                    let refs = baize.storage.ref_list()?;
                    println!("Refs ({}):", refs.len());
                    for r in refs {
                        println!("  {} → {}", r.name, r.commit_hash);
                    }
                }
            }
            Ok(())
        }

        Commands::Log => {
            let baize = open_baize()?;
            let commits = baize.storage.commit_log(None)?;
            if commits.is_empty() {
                println!("(无 commit)");
            } else {
                for c in commits {
                    let author_str = c.author.as_deref().unwrap_or("-");
                    println!("{} {} ({})", &c.hash[..12.min(c.hash.len())], c.message, author_str);
                    if let Some(ref p) = c.parent_hash {
                        println!("  parent: {}", &p[..12.min(p.len())]);
                    }
                }
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

        Commands::Trace { target, identity } => {
            let baize = open_baize()?;
            if identity {
                let chain = baize.trace_identity(&target)?;
                println!("身份链 ({} 级):", chain.len());
                for id in &chain {
                    println!("  {} | L{} | zones {:?} | parent {:?}",
                        id.agent_id, id.level, id.zones, id.parent_id);
                }
            } else {
                let chain = baize.trace_data(&target)?;
                println!("数据链 ({} 级):", chain.len());
                for c in &chain {
                    println!("  {} {}", &c.hash[..12.min(c.hash.len())], c.message);
                }
            }
            Ok(())
        }

        Commands::Audit => {
            let baize = open_baize()?;
            let mut filter = HashMap::new();
            filter.insert("x-audit".to_string(), "true".to_string());
            let blobs = baize.storage.blob_query(&filter)?;
            println!("审计日志 ({} 条):", blobs.len());
            for b in &blobs {
                println!("  {} | {} | {}",
                    &b.hash[..12.min(b.hash.len())],
                    b.labels.get("x-audit-type").unwrap_or(&"-".to_string()),
                    b.labels.get("x-audit-agent").unwrap_or(&"-".to_string()),
                );
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
            println!("  Commit: {}", result.commit_hash);
            println!("  Ref: {}", result.ref_name);
            Ok(())
        }

        Commands::Pull { r#ref, agent } => {
            let baize = open_baize()?;
            let result = baize.pipe_pull(&agent, r#ref.as_deref())?;
            println!("Pull 成功: {} 个文件", result.files);
            println!("  Commit: {}", result.commit_hash);
            println!("  Ref: {}", result.ref_name);
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
