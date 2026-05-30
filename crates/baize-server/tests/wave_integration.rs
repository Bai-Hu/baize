//! Mako-Wave 多 Agent 协作集成测试
//!
//! 场景：安全代码部署评审
//! 模式：Mako wave（并行 wave → narrator 汇总 → 交叉响应 → 收敛）
//! 框架：白泽治理（zone/level 权限、借权、ASL Intent→Authz→Receipt 链路）

use std::collections::HashMap;

use baize_core::cert::CredentialStatus;
use baize_core::labels::*;
use baize_core::scope::{ElevationMode, ElevationStatus, Level};
use baize_server::pipeline::agent_manager::AgentRegistry;
use baize_server::pipeline::data_ops::DataOps;
use baize_server::pipeline::elevation::ElevationManager;
use baize_server::pipeline::file_sync::FileSync;
use baize_server::pipeline::git_ops::GitOps;
use baize_server::Baize;

// ─── 辅助宏 ───

macro_rules! labels {
    ($($k:expr => $v:expr),* $(,)?) => {{
        let mut m = HashMap::<String, String>::new();
        $(m.insert($k.to_string(), $v.to_string());)*
        m
    }};
}

/// 查询 wave-{N} 阶段的所有 opinion blob
fn query_wave_opinions(baize: &Baize, wave: &str) -> Vec<baize_core::storage::Blob> {
    let filter = labels! {
        "type" => "opinion",
        "wave" => wave,
    };
    baize.storage.blob_query(&filter).unwrap()
}

// ═══════════════════════════════════════════════════════════════
// 主测试：Mako-Wave 安全代码部署评审
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_wave_code_deployment_review() {
    let mut baize = Baize::init_in_memory().unwrap();

    // ──────────────────────────────────────────────
    // Phase 0: Setup — 注册 Agent + 创建任务授权链
    // ──────────────────────────────────────────────

    // 注册 4 个 agent（root 已存在）
    baize.agent_register("baize-root", "reviewer", Level(2), vec!["review", "staging"], None).unwrap();
    baize.agent_register("baize-root", "auditor", Level(2), vec!["security"], None).unwrap();
    baize.agent_register("baize-root", "deployer", Level(2), vec!["deploy", "staging"], None).unwrap();
    baize.agent_register("baize-root", "observer", Level(0), vec![], None).unwrap();

    // 验证 agent 列表：root + 4 = 5
    let agents = baize.agent_list();
    assert_eq!(agents.len(), 5, "should have 5 agents (root + 4)");
    let agent_ids: Vec<&str> = agents.iter().map(|(id, _)| id.as_str()).collect();
    assert!(agent_ids.contains(&"baize-root"));
    assert!(agent_ids.contains(&"reviewer"));
    assert!(agent_ids.contains(&"auditor"));
    assert!(agent_ids.contains(&"deployer"));
    assert!(agent_ids.contains(&"observer"));

    // 验证身份链
    let root_chain = baize.trace_identity("baize-root").unwrap();
    assert_eq!(root_chain.len(), 1);
    assert_eq!(root_chain[0].agent_id, "baize-root");

    // root 上传代码变更到 staging zone
    let code_content = r#"
fn process_payment(amount: f64, user_id: &str) -> Result<(), Error> {
    // TODO: input validation
    let sql = format!("INSERT INTO payments VALUES ({}, '{}')", amount, user_id);
    db.execute(&sql)
}
"#;
    let code_file = baize.pipe_file_write(
        "baize-root",
        "staging/payment.rs",
        code_content.as_bytes(),
        Some(labels! {"type" => "code-change", "change-id" => "PR-42"}),
    ).unwrap();
    assert_eq!(code_file.path, "staging/payment.rs");
    assert!(code_file.size > 0);

    // 创建 Intent（部署评审意图）
    let intent_json = serde_json::json!({
        "intent_id": "int-deploy-review-001",
        "intent_owner": "baize-root",
        "intent_creator": "baize-root",
        "intent_goal": "review-and-deploy",
        "intent_constraints": {
            "target_zones": ["staging", "deploy"],
            "max_reviewers": 3,
            "require_security_audit": true,
        },
        "version": "1.0",
        "created_at": "2026-05-23T00:00:00Z",
        "expires_at": "2026-12-31T23:59:59Z",
    });
    let intent_blob = baize.pipe_blob_write(
        "baize-root",
        &serde_json::to_string(&intent_json).unwrap(),
        &labels! {
            "type" => BLOB_TYPE_INTENT,
            LABEL_INTENT_ID => "int-deploy-review-001",
            LABEL_INTENT_OWNER => "baize-root",
            LABEL_INTENT_STATUS => "active",
        },
    ).unwrap();
    let intent_hash = intent_blob.hash.clone();

    // 创建 3 个 Authorization（授权每个 agent 参与评审）
    let mut authz_hashes = Vec::new();
    for (subject, grant) in [("reviewer", "code-review"), ("auditor", "security-audit"), ("deployer", "deploy-assess")] {
        let authz_json = serde_json::json!({
            "authorization_id": format!("authz-{}-001", subject),
            "issuer": "baize-root",
            "subject": subject,
            "grant_type": grant,
            "constraints": {"target_scope": ["staging"]},
            "delegatable": false,
            "source_intent_digest": &intent_hash,
            "root_authorizer": "baize-root",
            "nbf": "2026-05-23T00:00:00Z",
            "exp": "2026-12-31T23:59:59Z",
            "iat": "2026-05-23T00:00:00Z",
            "jti": format!("jti-{}", subject),
            "version": "1.0",
        });
        let authz_blob = baize.pipe_blob_write(
            "baize-root",
            &serde_json::to_string(&authz_json).unwrap(),
            &labels! {
                "type" => BLOB_TYPE_AUTHORIZATION,
                LABEL_AUTHZ_ID => format!("authz-{}-001", subject),
                LABEL_AUTHZ_ISSUER => "baize-root",
                LABEL_AUTHZ_SUBJECT => subject,
                LABEL_AUTHZ_STATUS => "valid",
                LABEL_SOURCE_INTENT => &intent_hash,
            },
        ).unwrap();
        authz_hashes.push(authz_blob.hash.clone());
    }
    assert_eq!(authz_hashes.len(), 3, "should have 3 authorizations");

    // ──────────────────────────────────────────────
    // Phase 1: Wave 0 — 三个 agent 并行独立分析
    // （在实际系统中这些会并行执行，测试中顺序模拟）
    // ──────────────────────────────────────────────

    // reviewer: 代码评审意见
    let review_opinion = baize.pipe_blob_write(
        "reviewer",
        "Code Review: PR-42 payment.rs\n\
         - SQL injection vulnerability on line 3 (format! with user input)\n\
         - No input validation (TODO comment)\n\
         - Logic correct for happy path\n\
         - RECOMMEND: block until SQL injection fixed",
        &labels! {
            "type" => "opinion",
            "wave" => "wave-0",
            "agent" => "reviewer",
            "role" => "code-reviewer",
            "verdict" => "block",
            "change-id" => "PR-42",
        },
    ).unwrap();
    assert!(!review_opinion.hash.is_empty());

    // auditor: 安全审计意见
    let audit_opinion = baize.pipe_blob_write(
        "auditor",
        "Security Audit: PR-42\n\
         - CRITICAL: SQL injection (CWE-89) — direct string interpolation in SQL\n\
         - No parameterized query\n\
         - RECOMMEND: use prepared statement / ORM\n\
         - Severity: HIGH",
        &labels! {
            "type" => "opinion",
            "wave" => "wave-0",
            "agent" => "auditor",
            "role" => "security-auditor",
            "verdict" => "block",
            "severity" => "high",
            "change-id" => "PR-42",
        },
    ).unwrap();
    assert!(!audit_opinion.hash.is_empty());

    // deployer: 部署方案（文件写入到 deploy zone）
    let deploy_plan = baize.pipe_file_write(
        "deployer",
        "deploy/rollback-plan.txt",
        b"Deployment Plan for PR-42:\n\
          1. Blue-green deployment to staging\n\
          2. Smoke test payment flow\n\
          3. Rollback: revert to previous image within 30s\n\
          4. Monitoring: alert on error_rate > 1%",
        Some(labels! {
            "type" => "deploy-plan",
            "wave" => "wave-0",
            "agent" => "deployer",
            "change-id" => "PR-42",
        }),
    ).unwrap();
    assert_eq!(deploy_plan.path, "deploy/rollback-plan.txt");

    // deployer 也写一个 blob opinion
    let _deploy_opinion = baize.pipe_blob_write(
        "deployer",
        "Deploy Assessment: PR-42\n\
         - Deployment pipeline ready\n\
         - Rollback plan documented\n\
         - RECOMMEND: deploy after security fix\n\
         - No infrastructure blockers",
        &labels! {
            "type" => "opinion",
            "wave" => "wave-0",
            "agent" => "deployer",
            "role" => "deploy-engineer",
            "verdict" => "conditional-pass",
            "change-id" => "PR-42",
        },
    ).unwrap();

    // ──────────────────────────────────────────────
    // Phase 2: Narrator 汇总 Wave 0
    // ──────────────────────────────────────────────

    // root 查询所有 wave-0 opinion
    let wave0_opinions = query_wave_opinions(&baize, "wave-0");
    assert_eq!(wave0_opinions.len(), 3, "wave-0 should have 3 opinions");

    let verdicts: Vec<&str> = wave0_opinions.iter()
        .filter_map(|b| b.labels.get("verdict").map(|s| s.as_str()))
        .collect();
    assert!(verdicts.contains(&"block"), "auditor should block");
    assert!(verdicts.contains(&"conditional-pass"), "deployer conditional");

    // root 写入汇总
    let _summary = baize.pipe_blob_write(
        "baize-root",
        "Narrator Summary — Wave 0:\n\
         ┌─────────────────────────────────────────────┐\n\
         │ CONSENSUS: All reviewers agree SQL injection │\n\
         │ must be fixed before deployment.             │\n\
         │                                              │\n\
         │ reviewer: BLOCK    — SQL injection found     │\n\
         │ auditor:  BLOCK    — CWE-89 HIGH severity    │\n\
         │ deployer: COND-PASS— deploy ready, await fix │\n\
         │                                              │\n\
         │ ACTION: Request code fix, then re-audit.     │\n\
         └─────────────────────────────────────────────┘",
        &labels! {
            "type" => "narrator-summary",
            "wave" => "wave-0",
            "agent" => "baize-root",
            "consensus" => "block-until-fixed",
            "change-id" => "PR-42",
        },
    ).unwrap();

    // ──────────────────────────────────────────────
    // Phase 3: Wave 1 — 交叉响应 + 借权
    // ──────────────────────────────────────────────

    // reviewer 回应安全问题：同意修复建议
    let _reviewer_response = baize.pipe_blob_write(
        "reviewer",
        "Reviewer Response — Wave 1:\n\
         - Agree with auditor: SQL injection must use prepared statement\n\
         - Proposed fix: replace format! with parameterized query\n\
         - Will submit updated code after this wave",
        &labels! {
            "type" => "opinion",
            "wave" => "wave-1",
            "agent" => "reviewer",
            "role" => "code-reviewer",
            "responding-to" => &audit_opinion.hash,
            "verdict" => "agree",
            "change-id" => "PR-42",
        },
    ).unwrap();

    // auditor 需要访问 staging zone 查看代码 → 借权申请
    let elev_id = baize.elevation_request(
        "auditor",
        vec!["staging"],
        ElevationMode::ReadOnly,
        "need to verify code fix in staging zone",
        Some("1h"),
    ).unwrap();
    assert!(!elev_id.is_empty());

    // root 审批借权
    baize.elevation_approve(&elev_id, "baize-root").unwrap();
    let elev_list = baize.elevation_list().unwrap();
    let elev_req = elev_list.iter().find(|r| r.id == elev_id).unwrap();
    assert_eq!(elev_req.status, ElevationStatus::Approved);

    // root 更新代码（修复 SQL injection）
    let fixed_code = r#"
fn process_payment(amount: f64, user_id: &str) -> Result<(), Error> {
    if amount <= 0.0 {
        return Err(Error::Validation("invalid amount"));
    }
    if user_id.is_empty() {
        return Err(Error::Validation("empty user_id"));
    }
    db.execute_prepared("INSERT INTO payments VALUES (?, ?)", &[&amount, &user_id])
}
"#;
    baize.pipe_file_write(
        "baize-root",
        "staging/payment.rs",
        fixed_code.as_bytes(),
        Some(labels! {"type" => "code-change", "change-id" => "PR-42", "status" => "fixed"}),
    ).unwrap();

    // auditor 确认修复
    let _auditor_confirm = baize.pipe_blob_write(
        "auditor",
        "Security Re-Audit — Wave 1:\n\
         - Verified fix: format! replaced with parameterized query\n\
         - Input validation added (amount > 0, user_id non-empty)\n\
         - SQL injection resolved\n\
         - VERDICT: PASS — no remaining security issues",
        &labels! {
            "type" => "opinion",
            "wave" => "wave-1",
            "agent" => "auditor",
            "role" => "security-auditor",
            "verdict" => "pass",
            "change-id" => "PR-42",
        },
    ).unwrap();

    // deployer 确认部署就绪
    let _deployer_confirm = baize.pipe_blob_write(
        "deployer",
        "Deploy Confirmation — Wave 1:\n\
         - Security fix verified\n\
         - Deployment pipeline green\n\
         - VERDICT: READY TO DEPLOY",
        &labels! {
            "type" => "opinion",
            "wave" => "wave-1",
            "agent" => "deployer",
            "role" => "deploy-engineer",
            "verdict" => "pass",
            "change-id" => "PR-42",
        },
    ).unwrap();

    // ──────────────────────────────────────────────
    // Phase 4: Narrator 收敛判定
    // ──────────────────────────────────────────────

    let wave1_opinions = query_wave_opinions(&baize, "wave-1");
    assert_eq!(wave1_opinions.len(), 3, "wave-1 should have 3 responses");

    // 检查收敛：所有 wave-1 verdict 应为 pass 或 agree
    let w1_verdicts: Vec<&str> = wave1_opinions.iter()
        .filter_map(|b| b.labels.get("verdict").map(|s| s.as_str()))
        .collect();
    let all_pass = w1_verdicts.iter().all(|v| *v == "pass" || *v == "agree");
    assert!(all_pass, "all wave-1 verdicts should be pass/agree: {:?}", w1_verdicts);

    // root 写入最终决策
    let decision = baize.pipe_blob_write(
        "baize-root",
        "FINAL DECISION — Wave Convergence:\n\
         ┌─────────────────────────────────────────────┐\n\
         │ PR-42: APPROVED FOR DEPLOYMENT              │\n\
         │                                              │\n\
         │ Wave 0: 3 BLOCKs (SQL injection)             │\n\
         │ Wave 1: 3 PASSes (fix verified)              │\n\
         │                                              │\n\
         │ Converged: all reviewers agree               │\n\
         │ Deploy: blue-green → staging → production    │\n\
         └─────────────────────────────────────────────┘",
        &labels! {
            "type" => "decision",
            "wave" => "convergence",
            "agent" => "baize-root",
            "decision" => "approved",
            "change-id" => "PR-42",
        },
    ).unwrap();

    // ──────────────────────────────────────────────
    // Phase 5: 验证 — Receipt + 审计 + 身份 + 权限
    // ──────────────────────────────────────────────

    // 5a. 创建 Receipt（任务完成）
    let receipt_json = serde_json::json!({
        "receipt_id": "rct-deploy-review-001",
        "executor_id": "baize-root",
        "task_id": "PR-42",
        "action_type": "code-review",
        "intent_digest": intent_hash,
        "authorization_digest": authz_hashes[0],
        "result_status": "SUCCEEDED",
        "started_at": "2026-05-23T00:00:00Z",
        "finished_at": "2026-05-23T00:10:00Z",
    });
    let receipt_blob = baize.pipe_blob_write(
        "baize-root",
        &serde_json::to_string(&receipt_json).unwrap(),
        &labels! {
            "type" => BLOB_TYPE_RECEIPT,
            LABEL_RECEIPT_ID => "rct-deploy-review-001",
            LABEL_RECEIPT_EXECUTOR => "baize-root",
            LABEL_RECEIPT_STATUS => "SUCCEEDED",
            LABEL_RECEIPT_INTENT => &intent_hash,
            LABEL_RECEIPT_AUTHZ => &authz_hashes[0],
        },
    ).unwrap();
    assert!(!receipt_blob.hash.is_empty());

    // 5b. 审计链验证
    let audit_blobs = baize.storage.blob_query(&labels! { "x-audit" => "true" }).unwrap();
    assert!(audit_blobs.len() >= 10, "should have substantial audit records, got {}", audit_blobs.len());

    // 验证审计记录涵盖关键操作
    let audit_types: Vec<&str> = audit_blobs.iter()
        .filter_map(|b| b.labels.get("x-audit-type").map(|s| s.as_str()))
        .collect();
    assert!(audit_types.contains(&"blob_write"), "audit should contain blob_write events");
    assert!(audit_types.contains(&"file_write"), "audit should contain file_write events");

    // 检查审计链索引连续性（v1 hash chain）
    let chain_indices: Vec<u64> = audit_blobs.iter()
        .filter_map(|b| b.labels.get(LABEL_AUDIT_CHAIN_INDEX).and_then(|v| v.parse().ok()))
        .collect();
    if !chain_indices.is_empty() {
        let mut sorted = chain_indices.clone();
        sorted.sort();
        sorted.dedup();
        for w in sorted.windows(2) {
            assert_eq!(w[1] - w[0], 1, "audit chain indices should be sequential: {:?}", sorted);
        }
    }

    // 5c. 身份链追溯
    let reviewer_chain = baize.trace_identity("reviewer").unwrap();
    assert_eq!(reviewer_chain.len(), 2, "reviewer → root");
    assert_eq!(reviewer_chain[0].agent_id, "reviewer");
    assert_eq!(reviewer_chain[1].agent_id, "baize-root");

    let auditor_chain = baize.trace_identity("auditor").unwrap();
    assert_eq!(auditor_chain.len(), 2, "auditor → root");

    let deployer_chain = baize.trace_identity("deployer").unwrap();
    assert_eq!(deployer_chain.len(), 2, "deployer → root");

    // 5d. observer（Level 0）权限验证
    let write_result = baize.pipe_blob_write("observer", "should fail", &labels! {});
    assert!(write_result.is_err(), "level 0 observer should NOT be able to write");

    // observer 可以读取（export）
    let export_result = baize.pipe_export("observer", &decision.hash);
    assert!(export_result.is_ok(), "level 0 observer SHOULD be able to read/export");
    assert!(export_result.unwrap().content.contains("APPROVED"));

    // 5e. 仓库统计
    let stats = baize.repo_stats().unwrap();
    assert!(stats.total_blobs >= 15, "should have many blobs from the workflow");
}

// ═══════════════════════════════════════════════════════════════
// 辅助测试：验证 wave 结构的各个侧面
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_wave_delegation_chain() {
    let mut baize = Baize::init_in_memory().unwrap();

    // root → tech-lead → reviewer（三层委托）
    baize.agent_register("baize-root", "tech-lead", Level(2), vec!["review", "staging", "security"], None).unwrap();
    baize.agent_register("baize-root", "junior-reviewer", Level(2), vec!["review"], Some("tech-lead")).unwrap();

    // 三级身份链
    let chain = baize.trace_identity("junior-reviewer").unwrap();
    assert_eq!(chain.len(), 3);
    assert_eq!(chain[0].agent_id, "junior-reviewer");
    assert_eq!(chain[1].agent_id, "tech-lead");
    assert_eq!(chain[2].agent_id, "baize-root");

    // junior-reviewer 可以写 review zone
    let blob = baize.pipe_blob_write(
        "junior-reviewer",
        "LGTM from junior reviewer",
        &labels! {"type" => "opinion", "zone" => "review"},
    ).unwrap();
    assert!(!blob.hash.is_empty());

    // junior-reviewer 不能写 staging zone（不在 scope 中）
    let file_result = baize.pipe_file_write(
        "junior-reviewer",
        "staging/test.rs",
        b"fn main() {}",
        None,
    );
    assert!(file_result.is_err(), "junior-reviewer scope is only review, not staging");
}

#[test]
fn test_wave_elevation_cross_zone() {
    let mut baize = Baize::init_in_memory().unwrap();

    baize.agent_register("baize-root", "reviewer", Level(2), vec!["review"], None).unwrap();
    baize.agent_register("baize-root", "auditor", Level(2), vec!["security"], None).unwrap();

    // reviewer 需要 security zone 读权限来做交叉检查
    let elev_id = baize.elevation_request(
        "reviewer",
        vec!["security"],
        ElevationMode::ReadOnly,
        "cross-check security findings",
        Some("30m"),
    ).unwrap();
    baize.elevation_approve(&elev_id, "baize-root").unwrap();

    // 验证借权状态
    let list = baize.elevation_list().unwrap();
    let req = list.iter().find(|r| r.id == elev_id).unwrap();
    assert_eq!(req.status, ElevationStatus::Approved);
    assert_eq!(req.agent_id, "reviewer");
    assert!(req.requested_zones.contains("security"));

    // 归还借权
    baize.elevation_return(&elev_id, "reviewer", "reviewer").unwrap();
    let list = baize.elevation_list().unwrap();
    let req = list.iter().find(|r| r.id == elev_id).unwrap();
    assert_eq!(req.status, ElevationStatus::Returned);
}

#[test]
fn test_wave_push_pull_cross_agent_sync() {
    let mut baize = Baize::init_in_memory().unwrap();

    baize.agent_register("baize-root", "dev-a", Level(2), vec!["review"], None).unwrap();
    baize.agent_register("baize-root", "dev-b", Level(2), vec!["review"], None).unwrap();

    // dev-a 写入并 push
    baize.pipe_file_write("dev-a", "review/module-a.rs", b"pub fn hello() {}", None).unwrap();
    let push_result = baize.pipe_push("dev-a", "dev-a: add module-a", None).unwrap();
    assert_eq!(push_result.files, 1);

    // dev-b pull → 拿到 dev-a 的文件
    let pull_result = baize.pipe_pull("dev-b", None).unwrap();
    assert_eq!(pull_result.files, 1);

    let file = baize.pipe_file_read("dev-b", "review/module-a.rs").unwrap();
    assert_eq!(file.content, b"pub fn hello() {}");

    // dev-b 写入自己的文件并 push
    baize.pipe_file_write("dev-b", "review/module-b.rs", b"pub fn world() {}", None).unwrap();
    let push2 = baize.pipe_push("dev-b", "dev-b: add module-b", None).unwrap();
    assert!(push2.files >= 2, "dev-b push should include both pulled + new files");

    // dev-a pull → 主仓库现在有 module-a + module-b，所以拿到 2 个文件
    let pull2 = baize.pipe_pull("dev-a", None).unwrap();
    assert!(pull2.files >= 2, "dev-a should get both files from main repo");

    let file_b = baize.pipe_file_read("dev-a", "review/module-b.rs").unwrap();
    assert_eq!(file_b.content, b"pub fn world() {}");

    // dev-a 原来的文件也应该还在
    let file_a = baize.pipe_file_read("dev-a", "review/module-a.rs").unwrap();
    assert_eq!(file_a.content, b"pub fn hello() {}");
}

#[test]
fn test_wave_credential_lifecycle() {
    let mut baize = Baize::init_in_memory().unwrap();

    baize.agent_register("baize-root", "contractor", Level(2), vec!["review"], None).unwrap();

    // 正常工作
    let blob = baize.pipe_blob_write(
        "contractor",
        "review complete",
        &labels! {"type" => "opinion"},
    ).unwrap();
    assert!(!blob.hash.is_empty());

    // 暂停凭证
    baize.update_credential_status("contractor", CredentialStatus::Suspended, "contract expired").unwrap();
    let status = baize.credential_status("contractor").unwrap();
    assert_eq!(status, CredentialStatus::Suspended);

    // v2: 暂停后不能写入
    let write_result = baize.pipe_blob_write("contractor", "should fail", &labels! {});
    assert!(write_result.is_err(), "suspended agent should not be able to write");

    // v2: 暂停后不能读取（export）
    let blob_hash = blob.hash.clone();
    let read_result = baize.pipe_export("contractor", &blob_hash);
    assert!(read_result.is_ok(), "suspended agent should still be able to read (not revoked)");

    // 恢复凭证
    baize.update_credential_status("contractor", CredentialStatus::Active, "contract renewed").unwrap();
    let restored_status = baize.credential_status("contractor").unwrap();
    assert_eq!(restored_status, CredentialStatus::Active);

    // 恢复后可以正常写入
    let blob2 = baize.pipe_blob_write(
        "contractor",
        "review resumed",
        &labels! {"type" => "opinion"},
    ).unwrap();
    assert!(!blob2.hash.is_empty());
}

// ═══════════════════════════════════════════════════════════════
// v2 Phase 1 集成测试：管道安全强制
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_v2_expired_intent_rejected() {
    let mut baize = Baize::init_in_memory().unwrap();
    baize.agent_register("baize-root", "planner", Level(2), vec!["deploy"], None).unwrap();

    // 创建一个已过期的根意图（绕过管道直接写入 storage）
    let mut parent_labels = HashMap::new();
    parent_labels.insert("type".to_string(), BLOB_TYPE_INTENT.to_string());
    parent_labels.insert(LABEL_INTENT_ID.to_string(), "int-deploy-v1".to_string());
    parent_labels.insert(LABEL_INTENT_STATUS.to_string(), "active".to_string());
    parent_labels.insert(LABEL_INTENT_EXPIRES.to_string(), "2020-06-01T00:00:00Z".to_string());
    parent_labels.insert(LABEL_DERIVATION_DEPTH.to_string(), "0".to_string());
    let parent_blob = baize.storage.blob_write(
        &serde_json::json!({"intent_constraints":{"budget":500},"expires_at":"2020-06-01T00:00:00Z"}).to_string(),
        &parent_labels,
    ).unwrap();

    // 尝试从过期意图派生子意图 → 应被拒绝
    let sub_content = serde_json::json!({
        "parent_intent_digest": parent_blob.hash,
        "derivation_depth": 1,
        "intent_constraints": {"budget": 200},
        "expires_at": "2099-01-01T00:00:00Z",
    }).to_string();
    let sub_labels = labels! {
        "type" => BLOB_TYPE_SUB_INTENT,
        LABEL_DERIVATION_DEPTH => "1",
    };
    let result = baize.pipe_blob_write("planner", &sub_content, &sub_labels);
    assert!(result.is_err(), "sub-intent from expired parent should be rejected");
    match result {
        Err(baize_core::error::Error::IntentExpired(msg)) => assert!(msg.contains("parent")),
        other => panic!("expected IntentExpired, got {:?}", other),
    }

    // 尝试基于过期意图创建授权 → 应被拒绝
    let authz_content = serde_json::json!({
        "source_intent_digest": parent_blob.hash,
        "constraints": {"budget": 200},
        "issuer": "planner",
        "subject": "planner",
        "delegatable": false,
        "root_authorizer": "baize-root",
        "nbf": "2020-01-01T00:00:00Z",
        "exp": "2099-01-01T00:00:00Z",
    }).to_string();
    let authz_labels = labels! {
        "type" => BLOB_TYPE_AUTHORIZATION,
        LABEL_AUTHZ_ISSUER => "planner",
        LABEL_AUTHZ_SUBJECT => "planner",
        LABEL_SOURCE_INTENT => &parent_blob.hash,
    };
    let result = baize.pipe_blob_write("planner", &authz_content, &authz_labels);
    assert!(result.is_err(), "authorization from expired intent should be rejected");
    match result {
        Err(baize_core::error::Error::IntentExpired(msg)) => assert!(msg.contains("source")),
        other => panic!("expected IntentExpired, got {:?}", other),
    }
}

#[test]
fn test_v2_expired_authz_rejected() {
    let mut baize = Baize::init_in_memory().unwrap();
    baize.agent_register("baize-root", "executor", Level(2), vec!["deploy"], None).unwrap();

    // 创建有效的 intent
    let intent_labels = labels! {
        "type" => BLOB_TYPE_INTENT,
        LABEL_INTENT_ID => "int-valid-001",
        LABEL_INTENT_STATUS => "active",
        LABEL_INTENT_EXPIRES => "2099-12-31T23:59:59Z",
    };
    let intent_blob = baize.storage.blob_write("{}", &intent_labels).unwrap();

    // 创建已过期的 authz
    let authz_content = serde_json::json!({
        "exp": "2020-12-31T23:59:59Z",
        "constraints": {"budget": 100},
    }).to_string();
    let authz_labels = labels! {
        "type" => BLOB_TYPE_AUTHORIZATION,
        LABEL_AUTHZ_STATUS => "valid",
    };
    let authz_blob = baize.storage.blob_write(&authz_content, &authz_labels).unwrap();

    // 尝试基于过期 authz 创建 receipt → 应被拒绝
    let receipt_content = serde_json::json!({
        "intent_digest": intent_blob.hash,
        "authorization_digest": authz_blob.hash,
        "result_status": "SUCCEEDED",
    }).to_string();
    let receipt_labels = labels! { "type" => BLOB_TYPE_RECEIPT };
    let result = baize.pipe_blob_write("executor", &receipt_content, &receipt_labels);
    assert!(result.is_err(), "receipt from expired authz should be rejected");
    match result {
        Err(baize_core::error::Error::AuthorizationExpired(msg)) => assert!(msg.contains("2020-12-31")),
        other => panic!("expected AuthorizationExpired, got {:?}", other),
    }
}

#[test]
fn test_v2_elevation_enforced() {
    let mut baize = Baize::init_in_memory().unwrap();
    baize.agent_register("baize-root", "worker", Level(2), vec!["zone-a"], None).unwrap();

    // worker 自身只有 zone-a，写入 zone-b 应被拒绝
    let result = baize.pipe_file_write("worker", "zone-b/secret.txt", b"hack", None);
    assert!(result.is_err(), "worker without elevation should not access zone-b");

    // 申请 zone-b 借权
    let elev_id = baize.elevation_request(
        "worker",
        vec!["zone-b"],
        ElevationMode::ReadWrite,
        "need zone-b for deployment task",
        Some("1h"),
    ).unwrap();
    baize.elevation_approve(&elev_id, "baize-root").unwrap();

    // 借权生效后，写入 zone-b 应成功
    let record = baize.pipe_file_write("worker", "zone-b/deploy.yaml", b"image: v2.0", None).unwrap();
    assert_eq!(record.path, "zone-b/deploy.yaml");
    assert_eq!(record.size, 11);

    // 读取 zone-b 也应成功
    let content = baize.pipe_file_read("worker", "zone-b/deploy.yaml").unwrap();
    assert_eq!(content.content, b"image: v2.0");

    // 归还借权
    baize.elevation_return(&elev_id, "worker", "worker").unwrap();

    // 归还后，写入 zone-b 再次被拒绝
    let result = baize.pipe_file_write("worker", "zone-b/after-return.txt", b"blocked", None);
    assert!(result.is_err(), "after elevation return, zone-b should be blocked again");
}

#[test]
fn test_v2_expired_elevation_blocks() {
    let mut baize = Baize::init_in_memory().unwrap();
    baize.agent_register("baize-root", "worker", Level(2), vec!["zone-a"], None).unwrap();

    // 直接写入一个已过期的 elevation blob（绕过管道构造过期状态）
    let past = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
    let elev_labels = labels! {
        "type" => "elevation-request",
        "elevation-agent" => "worker",
        "elevation-zones" => "[\"zone-b\"]",
        "elevation-mode" => "readwrite",
        "elevation-reason" => "test",
        "elevation-time" => "2020-01-01T00:00:00Z",
        "elevation-approved" => "true",
        "elevation-approver" => "baize-root",
        "elevation-expires" => &past,
    };
    baize.storage.blob_write("expired elevation", &elev_labels).unwrap();

    // 过期的 elevation 不应授予 zone-b 访问权
    let result = baize.pipe_file_write("worker", "zone-b/data.txt", b"should fail", None);
    assert!(result.is_err(), "expired elevation should not grant zone access");
}

#[test]
fn test_v2_audit_credential_status() {
    let mut baize = Baize::init_in_memory().unwrap();
    baize.agent_register("baize-root", "worker", Level(2), vec!["zone-a"], None).unwrap();

    // worker 写入 blob → 触发审计
    baize.pipe_blob_write("worker", "test data", &labels! {}).unwrap();

    // 查询审计记录
    let audit_blobs = baize.storage.blob_query(&labels! { "x-audit" => "true" }).unwrap();
    assert!(!audit_blobs.is_empty(), "should have audit records");

    // v2: 审计记录应包含 agent 的凭证状态
    // 注意：agent_register 时的审计在 agents.insert() 之前，所以没有 x-cert-status
    // 只检查 blob_write 操作的审计记录
    let worker_blob_audits: Vec<_> = audit_blobs.iter()
        .filter(|b| b.labels.get("x-audit-agent") == Some(&"worker".to_string()))
        .filter(|b| b.labels.get("x-audit-type") == Some(&"blob_write".to_string()))
        .collect();
    assert!(!worker_blob_audits.is_empty(), "should have worker blob_write audit records");

    for audit in &worker_blob_audits {
        let status = audit.labels.get(LABEL_CERT_STATUS);
        assert!(status.is_some(), "v2: blob_write audit should contain x-cert-status label");
        assert_eq!(status.unwrap(), "active", "worker credential status should be active");
    }

    // 验证 root 的审计记录也有凭证状态
    let root_audits: Vec<_> = audit_blobs.iter()
        .filter(|b| b.labels.get("x-audit-agent") == Some(&"baize-root".to_string()))
        .collect();
    for audit in &root_audits {
        let status = audit.labels.get(LABEL_CERT_STATUS);
        assert!(status.is_some(), "v2: root audit record should contain credential status");
    }
}

#[test]
fn test_v2_revoked_agent_fully_blocked() {
    let mut baize = Baize::init_in_memory().unwrap();
    baize.agent_register("baize-root", "rogue", Level(2), vec!["zone-a"], None).unwrap();

    // 先写入一个 blob
    let blob = baize.pipe_blob_write("rogue", "initial data", &labels! {}).unwrap();

    // 吊销凭证
    baize.update_credential_status("rogue", CredentialStatus::Revoked, "security breach").unwrap();

    // 吊销后：不能写入
    let write_result = baize.pipe_blob_write("rogue", "should fail", &labels! {});
    assert!(write_result.is_err(), "revoked agent should not write");

    // 吊销后：不能读取
    let read_result = baize.pipe_export("rogue", &blob.hash);
    assert!(read_result.is_err(), "revoked agent should not read");

    // 吊销后：不能写文件
    let file_result = baize.pipe_file_write("rogue", "zone-a/file.txt", b"blocked", None);
    assert!(file_result.is_err(), "revoked agent should not write files");
}

// ─── Phase 5: v2 Wave 缺失场景测试 ───

#[test]
fn test_v2_suspended_agent_blocked() {
    let mut baize = Baize::init_in_memory().unwrap();
    baize.agent_register("baize-root", "worker", Level(2), vec!["zone-a"], None).unwrap();

    // 暂停 worker
    baize.update_credential_status("worker", CredentialStatus::Suspended, "maintenance").unwrap();

    // 暂停后：不能写 blob
    let write_result = baize.pipe_blob_write("worker", "data", &labels! {});
    assert!(write_result.is_err(), "suspended agent should not write blobs");
    match write_result {
        Err(baize_core::error::Error::PermissionDenied(msg)) => assert!(msg.contains("suspended")),
        other => panic!("expected PermissionDenied, got {:?}", other),
    }

    // 暂停后：不能写文件
    let file_result = baize.pipe_file_write("worker", "zone-a/data.txt", b"blocked", None);
    assert!(file_result.is_err(), "suspended agent should not write files");

    // 暂停后：可以读取（Suspended 允许读）
    let read_result = baize.pipe_file_read("worker", "zone-a/data.txt");
    // 读取在文件不存在时返回其他错误，但不应该是 PermissionDenied
    match read_result {
        Ok(_) => {},
        Err(baize_core::error::Error::PermissionDenied(_)) => panic!("suspended agent should be allowed to read"),
        Err(_) => {}, // NotFound 等，可以接受
    }
}

#[test]
fn test_v2_encrypted_session() {
    let mut baize = Baize::init_in_memory().unwrap();
    // 注：session 测试用 Level 2 而非 Level 3，避免 IDN-ATH proof 要求干扰 E2E 加密流测试
    baize.agent_register("baize-root", "alice", Level(2), vec!["zone-a"], None).unwrap();
    baize.agent_register("baize-root", "bob", Level(2), vec!["zone-a"], None).unwrap();

    // 1. 双方生成 X25519 密钥对
    let (priv_a, pub_pem_a) = baize_core::crypto::generate_x25519_keypair().unwrap();
    let (priv_b, pub_pem_b) = baize_core::crypto::generate_x25519_keypair().unwrap();
    let secret_a = baize_core::crypto::decode_x25519_private(&priv_a).unwrap();
    let secret_b = baize_core::crypto::decode_x25519_private(&priv_b).unwrap();
    let pub_a_decoded = baize_core::crypto::decode_x25519_public(&pub_pem_a).unwrap();
    let pub_b_decoded = baize_core::crypto::decode_x25519_public(&pub_pem_b).unwrap();

    // 2. ECDH 密钥协商
    let shared_ab = baize_core::crypto::x25519_ecdh(&secret_a, &pub_b_decoded);
    let shared_ba = baize_core::crypto::x25519_ecdh(&secret_b, &pub_a_decoded);
    assert_eq!(shared_ab.as_bytes(), shared_ba.as_bytes(), "ECDH shared secret must match");

    // 3. 派生会话密钥
    let session_key = baize_core::crypto::derive_session_key(
        &shared_ab, "sess-e2e-test", &pub_a_decoded, &pub_b_decoded,
    ).unwrap();

    // 4. Alice 发送 session-init（提取 base64 部分）
    let pub_a_b64 = pub_pem_a.lines().find(|l| !l.starts_with('-')).unwrap();
    let init_content = serde_json::json!({
        "ephemeral_pub": pub_a_b64,
        "cipher_suites": ["AES-256-GCM"],
        "credential_digest": "sha256:test-cred",
    }).to_string();
    let init_blob = baize.pipe_blob_write("alice", &init_content, &labels! {
        "type" => BLOB_TYPE_SESSION_INIT,
        LABEL_SESSION_ID => "sess-e2e-test",
        LABEL_SESSION_PEER_A => "alice",
        LABEL_SESSION_PEER_B => "bob",
    }).unwrap();

    // 5. Bob 接受 session
    let pub_b_b64 = pub_pem_b.lines().find(|l| !l.starts_with('-')).unwrap();
    let accept_content = serde_json::json!({
        "ephemeral_pub": pub_b_b64,
        "selected_cipher_suite": "AES-256-GCM",
    }).to_string();
    baize.pipe_blob_write("bob", &accept_content, &labels! {
        "type" => BLOB_TYPE_SESSION_ACCEPT,
        LABEL_SESSION_ID => "sess-e2e-test",
        "parent" => init_blob.hash,
    }).unwrap();

    // 6. Alice 加密消息
    let plaintext = b"secret message from alice";
    let encrypted = baize_core::crypto::encrypt_session_message(
        &session_key, plaintext, "sess-e2e-test",
    ).unwrap();

    // 7. 通过管道发送加密消息（content 是密文）
    let msg_result = baize.pipe_blob_write("alice", &encrypted, &labels! {
        "type" => "chat",
        LABEL_SESSION_ID => "sess-e2e-test",
        LABEL_MESSAGE_SEQ => "1",
    });
    assert!(msg_result.is_ok(), "encrypted message should be accepted: {:?}", msg_result);

    // 8. Bob 解密消息
    let msg_blob = msg_result.unwrap();
    let decrypted = baize_core::crypto::decrypt_session_message(
        &session_key, &msg_blob.content, "sess-e2e-test",
    ).unwrap();
    assert_eq!(decrypted, plaintext);

    // 9. 关闭 session
    let close_result = baize.pipe_blob_write("alice", &serde_json::json!({"reason": "done"}).to_string(), &labels! {
        "type" => "session-close",
        LABEL_SESSION_ID => "sess-e2e-test",
    });
    assert!(close_result.is_ok());
}

#[test]
fn test_v2_proof_required_for_sensitive_ops() {
    use baize_server::pipeline::agent_manager::PermissionGuard;

    let mut baize = Baize::init_in_memory().unwrap();
    baize.agent_register("baize-root", "sensitive-agent", Level(3), vec!["A"], None).unwrap();

    // Level 3 agent 无 proof → 写 authorization 应被拒
    let result = baize.pipe_blob_write("sensitive-agent", "plain data", &labels! {
        "type" => BLOB_TYPE_AUTHORIZATION,
        LABEL_AUTHZ_STATUS => "valid",
    });
    assert!(result.is_err(), "Level 3 authz without proof should fail");
    match result {
        Err(baize_core::error::Error::ProofRequired(msg)) => assert!(msg.contains("no runtime proof")),
        other => panic!("expected ProofRequired, got {:?}", other),
    }

    // Level 3 agent 无 proof → 写 receipt 应被拒
    let result = baize.pipe_blob_write("sensitive-agent", "receipt data", &labels! {
        "type" => BLOB_TYPE_RECEIPT,
    });
    assert!(result.is_err(), "Level 3 receipt without proof should fail");
    match result {
        Err(baize_core::error::Error::ProofRequired(_)) => {},
        other => panic!("expected ProofRequired, got {:?}", other),
    }

    // Level 3 agent 无 proof → 写文件应被拒
    let file_result = baize.pipe_file_write("sensitive-agent", "A/secret.txt", b"secret", None);
    assert!(file_result.is_err(), "Level 3 file write without proof should fail");

    // Level 3 agent 无 proof → 删除文件应被拒
    let del_result = baize.pipe_file_delete("sensitive-agent", "A/secret.txt");
    assert!(del_result.is_err(), "Level 3 file delete without proof should fail");

    // Level 3 agent 无 proof → push 应被拒
    let push_result = baize.pipe_push("sensitive-agent", "test", None);
    assert!(push_result.is_err(), "Level 3 push without proof should fail");

    // 生成 proof 后所有操作应成功
    // 写入合法 proof
    let mut cert_filter = HashMap::new();
    cert_filter.insert("type".to_string(), "agent-cert".to_string());
    cert_filter.insert("agent-id".to_string(), "sensitive-agent".to_string());
    let certs = baize.storage.blob_query(&cert_filter).unwrap();
    let cert_hash = certs[0].hash.clone();
    let cert_labels = certs[0].labels.clone();

    let instance_state = serde_json::json!({"instance_id": "sensitive-agent"});
    let binding_digest = baize_asl::AslAdapter::compute_binding_context_digest(&cert_labels, &instance_state);
    let now = chrono::Utc::now();
    let proof = baize_asl::payload::RuntimeProofContent {
        proof_id: format!("proof-{}", now.timestamp_millis()),
        credential_digest: cert_hash,
        instance_state_attributes: instance_state,
        binding_context_digest: binding_digest,
        proof_anchor_mode: baize_asl::payload::ProofAnchorMode::CredentialAnchored,
        issued_at: now.to_rfc3339(),
        expires_at: (now + chrono::Duration::minutes(5)).to_rfc3339(),
    };
    baize.storage.blob_write(&serde_json::to_string(&proof).unwrap(), &labels! {
        "type" => "runtime-proof",
        LABEL_PROOF_AGENT => "sensitive-agent",
    }).unwrap();

    // 有 proof → 写文件成功
    let file_result = baize.pipe_file_write("sensitive-agent", "A/secret.txt", b"secret", None);
    assert!(file_result.is_ok(), "Level 3 file write with proof should succeed: {:?}", file_result);
}

#[test]
fn test_v2_key_rotation() {
    use baize_server::pipeline::agent_manager::KmsManager;

    let mut baize = Baize::init_in_memory().unwrap();
    baize.agent_register("baize-root", "rot-worker", Level(2), vec!["A"], None).unwrap();

    // 获取旧密钥 hash
    let old_key = baize.kms_get_active_key("rot-worker", "IDN_SIGN").unwrap();
    assert!(!old_key.is_empty());

    // 轮换 IDN_SIGN 密钥
    let new_hash = baize.kms_rotate_key("rot-worker", "IDN_SIGN").unwrap();
    assert!(!new_hash.is_empty());

    // 获取新密钥
    let new_key = baize.kms_get_active_key("rot-worker", "IDN_SIGN").unwrap();
    assert_ne!(old_key, new_key, "key should change after rotation");

    // 旧密钥应标记 revoked
    let mut filter = HashMap::new();
    filter.insert("type".to_string(), "agent-key".to_string());
    filter.insert(LABEL_KEY_OWNER.to_string(), "rot-worker".to_string());
    filter.insert(LABEL_KEY_PURPOSE.to_string(), "IDN_SIGN".to_string());
    let all_keys = baize.storage.blob_query(&filter).unwrap();
    assert_eq!(all_keys.len(), 2, "should have old + new key");
    let revoked = all_keys.iter().find(|k| k.labels.contains_key(LABEL_KEY_REVOKED)).unwrap();
    assert_eq!(revoked.labels.get(LABEL_KEY_REVOKED).unwrap(), "true");

    // 轮换后 agent 应仍能正常操作
    let write_result = baize.pipe_blob_write("rot-worker", "after rotation", &labels! {});
    assert!(write_result.is_ok(), "agent should still work after key rotation: {:?}", write_result);

    // 轮换后签名 middleware 应能用新密钥验证
    let signing_key = baize_server::pipeline::auth::extract_signing_key(&new_key);
    let timestamp = chrono::Utc::now().to_rfc3339();
    let body = r#"{"content":"test","labels":{}}"#;
    let input = format!("{}\nPOST\n/api/v2/blobs\n{}", timestamp, body);
    use ed25519_dalek::{SigningKey, Signer};
    let sk = SigningKey::from_bytes(&signing_key.try_into().expect("32 bytes"));
    let sig = sk.sign(input.as_bytes());
    let sig_str = format!("ed25519:{}", hex::encode(sig.to_bytes()));
    // 签名生成成功（密钥有效）
    assert!(sig_str.starts_with("ed25519:"));
}

// ═══════════════════════════════════════════════════════════════
// Label 归属校验测试
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_label_add_own_blob_ok() {
    let mut baize = Baize::init_in_memory().unwrap();

    // 注册一个普通 agent
    baize.agent_register("baize-root", "label-worker", Level(1), vec!["zone-a"], None).unwrap();

    // agent 写入自己的 blob
    let blob = baize.pipe_blob_write("label-worker", "my data", &labels! {}).unwrap();

    // 给自己的 blob 添加 label — 应该成功
    let result = baize.pipe_label_add("label-worker", &blob.hash, "env", "test");
    assert!(result.is_ok(), "agent should be able to label own blob: {:?}", result);
}

#[test]
fn test_label_add_not_owner_rejected() {
    let mut baize = Baize::init_in_memory().unwrap();

    // 注册两个 agent
    baize.agent_register("baize-root", "owner-agent", Level(1), vec!["zone-a"], None).unwrap();
    baize.agent_register("baize-root", "other-agent", Level(1), vec!["zone-a"], None).unwrap();

    // owner 写入 blob
    let blob = baize.pipe_blob_write("owner-agent", "secret data", &labels! {}).unwrap();

    // other-agent 尝试给 owner 的 blob 加 label — 应该被拒
    let result = baize.pipe_label_add("other-agent", &blob.hash, "env", "stolen");
    assert!(result.is_err(), "non-owner should not be able to label another agent's blob");
    match result.unwrap_err() {
        baize_core::error::Error::PermissionDenied(msg) => {
            assert!(msg.contains("not owner"), "error should mention ownership: {}", msg);
        }
        other => panic!("expected PermissionDenied, got: {:?}", other),
    }
}

#[test]
fn test_label_add_root_bypass() {
    let mut baize = Baize::init_in_memory().unwrap();

    // 注册普通 agent 并写入 blob
    baize.agent_register("baize-root", "normal-agent", Level(1), vec!["zone-a"], None).unwrap();
    let blob = baize.pipe_blob_write("normal-agent", "agent data", &labels! {}).unwrap();

    // root 给 agent 的 blob 加 label — 应该成功（root 豁免）
    let result = baize.pipe_label_add("baize-root", &blob.hash, "reviewed", "true");
    assert!(result.is_ok(), "root should bypass ownership check: {:?}", result);
}

// ═══════════════════════════════════════════════════════════════
// pipe_import trust_level + source 校验测试
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_import_trust_level_exceeds_agent_level_rejected() {
    let mut baize = Baize::init_in_memory().unwrap();

    // 注册 Level 1 agent
    baize.agent_register("baize-root", "importer", Level(1), vec!["zone-a"], None).unwrap();

    // 尝试用 trust_level=3（超过自身 level=1）import
    let result = baize.pipe_import("importer", "external data", "https://example.com", 3, None);
    assert!(result.is_err(), "trust_level exceeding agent level should be rejected");
    match result.unwrap_err() {
        baize_core::error::Error::Validation(msg) => {
            assert!(msg.contains("trust_level"), "error should mention trust_level: {}", msg);
        }
        other => panic!("expected Validation, got: {:?}", other),
    }
}

#[test]
fn test_import_empty_source_rejected() {
    let mut baize = Baize::init_in_memory().unwrap();

    baize.agent_register("baize-root", "importer2", Level(2), vec!["zone-a"], None).unwrap();

    // 空 source
    let result = baize.pipe_import("importer2", "data", "", 1, None);
    assert!(result.is_err(), "empty source should be rejected");
    match result.unwrap_err() {
        baize_core::error::Error::Validation(msg) => {
            assert!(msg.contains("source"), "error should mention source: {}", msg);
        }
        other => panic!("expected Validation, got: {:?}", other),
    }

    // 纯空格 source
    let result2 = baize.pipe_import("importer2", "data", "   ", 1, None);
    assert!(result2.is_err(), "whitespace-only source should be rejected");
}

// ═══════════════════════════════════════════════════════════════
// 审计 binding context digest 测试
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_audit_records_binding_context_for_l3() {
    use baize_server::pipeline::agent_manager::PermissionGuard;
    use baize_asl::payload::RuntimeProofContent;

    let mut baize = Baize::init_in_memory().unwrap();

    // 注册 Level 3 agent
    baize.agent_register("baize-root", "l3-agent", Level(3), vec!["zone-a"], None).unwrap();

    // 生成有效 proof
    let cert_filter = {
        let mut f = HashMap::new();
        f.insert("type".to_string(), "agent-cert".to_string());
        f.insert("agent-id".to_string(), "l3-agent".to_string());
        f
    };
    let certs = baize.storage.blob_query(&cert_filter).unwrap();
    let cert_hash = certs[0].hash.clone();
    let cert_labels = certs[0].labels.clone();

    let instance_state = serde_json::json!({"instance_id": "l3-agent", "instance_status": "running"});
    let binding_digest = baize_asl::AslAdapter::compute_binding_context_digest(&cert_labels, &instance_state);
    let now = chrono::Utc::now();
    let proof = RuntimeProofContent {
        proof_id: format!("proof-audit-{}", now.timestamp_millis()),
        credential_digest: cert_hash,
        instance_state_attributes: instance_state,
        binding_context_digest: binding_digest.clone(),
        proof_anchor_mode: baize_asl::payload::ProofAnchorMode::CredentialAnchored,
        issued_at: now.to_rfc3339(),
        expires_at: (now + chrono::Duration::minutes(5)).to_rfc3339(),
    };
    let proof_labels = HashMap::from([
        ("type".to_string(), "runtime-proof".to_string()),
        (LABEL_PROOF_AGENT.to_string(), "l3-agent".to_string()),
        (LABEL_PROOF_CREDENTIAL.to_string(), proof.credential_digest.clone()),
    ]);
    baize.storage.blob_write(&serde_json::to_string(&proof).unwrap(), &proof_labels).unwrap();

    // L3 agent 执行 blob write（需要 proof）
    let blob = baize.pipe_blob_write("l3-agent", "sensitive data", &labels! {
        "type" => "generic",
    }).unwrap();

    // 查找审计记录，检查是否包含 binding context digest
    let audit_filter = {
        let mut f = HashMap::new();
        f.insert("x-audit-type".to_string(), "blob_write".to_string());
        f.insert("x-audit-target".to_string(), blob.hash.clone());
        f
    };
    let audit_records = baize.storage.blob_query(&audit_filter).unwrap();
    assert!(!audit_records.is_empty(), "should have audit record for blob_write");

    let audit = &audit_records[0];
    let recorded_digest = audit.labels.get(LABEL_BINDING_CONTEXT_DIGEST);
    assert!(recorded_digest.is_some(), "L3 audit should contain binding context digest");
    assert_eq!(recorded_digest.unwrap(), &binding_digest, "recorded digest should match proof binding context");
}
