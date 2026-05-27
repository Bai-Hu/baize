//! 端到端场景集成测试
//!
//! 场景: 四层 Agent 树协作完成生产环境部署
//! Agent 树: root → commander → planner/executor → monitor

mod common;
use common::*;
use serde_json::{json, Value};
use http::StatusCode;

async fn setup_agent(app: &axum::Router, name: &str, level: u8, zones: &[&str], parent: Option<&str>) {
    let mut body = json!({"name": name, "level": level, "zones": zones});
    if let Some(p) = parent {
        body["parent_id"] = json!(p);
    }
    send(app, post_json("/api/v0/agents", body, Some("baize-root"))).await;
}

// ═══════════════════════════════════════════════════════════════
// E2E-1: 完整多 Agent 部署生命周期
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn e2e_full_deployment_lifecycle() {
    let app = test_app();
    let t0 = now_rfc3339();
    let t_exp = now_plus_minutes(60);
    let t_sub_exp = now_plus_minutes(30);

    // Phase 1: IDN — 注册四层 Agent 树
    setup_agent(&app, "commander", 3, &["deploy", "infra"], None).await;
    setup_agent(&app, "planner", 2, &["deploy"], Some("commander")).await;
    setup_agent(&app, "executor", 2, &["deploy", "infra"], Some("commander")).await;
    setup_agent(&app, "monitor", 1, &["deploy"], Some("executor")).await;

    // 验证身份链
    let (_, b) = send(&app, get_req("/api/v0/trace/identity/monitor")).await;
    let chain = b["chain"].as_array().unwrap();
    assert_eq!(chain.len(), 4);
    assert_eq!(chain[0]["agent_id"], "monitor");
    assert_eq!(chain[1]["agent_id"], "executor");
    assert_eq!(chain[2]["agent_id"], "commander");
    assert_eq!(chain[3]["agent_id"], "baize-root");

    // Phase 2: INF — 密钥轮换
    let (s, b) = send(&app, post_json("/api/v1/agents/executor/keys/rotate", json!({"purpose": "INT_SIGN"}), Some("executor"))).await;
    assert_eq!(s, StatusCode::OK);
    assert!(!b["new_key_hash"].as_str().unwrap().is_empty());

    // Phase 3: IDN-ATH — 运行态证明
    let (s, b) = send(&app, post_json("/api/v1/agents/commander/proof", json!({
        "instance_state_attributes": {"instance_id": "cmd-01", "instance_status": "running"},
        "proof_anchor_mode": "CREDENTIAL_ANCHORED"
    }), Some("baize-root"))).await;
    assert_eq!(s, StatusCode::CREATED);
    assert!(!b["proof_id"].as_str().unwrap().is_empty());

    // Phase 4: INT — 创建意图 + 子意图
    let intent = json!({
        "intent_id": "deploy-v2", "intent_owner": "commander", "intent_creator": "commander", "task_id": "T-001",
        "intent_goal": "Deploy v2 to production",
        "intent_constraints": {"target_scope": ["deploy", "infra"], "max_budget": 1000, "time_scope": {"deadline": t_exp}},
        "version": "1.0", "created_at": t0, "expires_at": t_exp
    }).to_string();
    let (_, b) = send(&app, post_json("/api/v1/intents", json!({"content": intent}), Some("commander"))).await;
    let intent_hash = b["hash"].as_str().unwrap().to_string();

    let sub_intent = json!({
        "sub_intent_id": "sub-db", "parent_intent_digest": intent_hash, "deriver_id": "planner",
        "subject": "db-migration", "derivation_depth": 1,
        "intent_goal": "Run DB migration",
        "intent_constraints": {"target_scope": ["deploy"], "max_budget": 500, "time_scope": {"deadline": t_exp}},
        "created_at": t0, "expires_at": t_sub_exp
    }).to_string();
    let (s, b) = send(&app, post_json("/api/v1/intents/derive", json!({"content": sub_intent}), Some("planner"))).await;
    assert_eq!(s, StatusCode::CREATED);
    let sub_hash = b["hash"].as_str().unwrap().to_string();

    // Phase 5: AZN — 签发授权 + 委托
    let authz = json!({
        "authorization_id": "authz-exec", "issuer": "commander", "subject": "executor",
        "grant_type": "execute", "constraints": {"target_scope": ["deploy"], "max_budget": 500},
        "delegatable": true, "delegation_depth_remaining": 2, "delegation_mode": "BOUNDED",
        "source_intent_digest": intent_hash, "root_authorizer": "commander",
        "nbf": t0, "exp": t_exp, "iat": t0, "jti": "j-exec", "version": "1.0"
    }).to_string();
    let (_, b) = send(&app, post_json("/api/v1/authorizations", json!({"content": authz}), Some("commander"))).await;
    let authz_hash = b["hash"].as_str().unwrap().to_string();

    // AZN-VER
    let (s, b) = send(&app, post_json(&format!("/api/v1/authorizations/{}/verify", authz_hash), json!({
        "action_type": "execute", "subject": "executor", "amount": 300.0
    }), Some("commander"))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["valid"], true);

    // Phase 6: LNK — 会话
    let (s, b) = send(&app, post_json("/api/v1/sessions", json!({
        "session_id": "sess-deploy", "peer_a": "commander", "peer_b": "executor",
        "ephemeral_pub": gen_ephemeral_pub(), "cipher_suites": ["AES-256-GCM"],
        "credential_digest_a": "sha256:a", "credential_digest_b": "sha256:b",
        "handshake_transcript_digest": "sha256:t"
    }), Some("commander"))).await;
    assert_eq!(s, StatusCode::CREATED);

    send(&app, post_json("/api/v1/sessions/sess-deploy/accept", json!({
        "credential_digest_responder": "sha256:b", "ephemeral_pub": gen_ephemeral_pub(),
        "selected_cipher_suite": "AES-256-GCM", "handshake_transcript_digest": "sha256:t2"
    }), Some("executor"))).await;

    send(&app, post_json("/api/v1/sessions/sess-deploy/close", json!({"reason": "done"}), Some("commander"))).await;

    // Phase 7: RCT — 回执 + CNV
    let receipt = json!({
        "receipt_id": "rct-001", "executor_id": "executor", "task_id": "T-001",
        "action_type": "execute", "intent_digest": sub_hash,
        "authorization_digest": authz_hash, "result_status": "SUCCEEDED",
        "execution_result": "Migration completed",
        "started_at": t0, "finished_at": now_rfc3339()
    }).to_string();
    let (_, b) = send(&app, post_json("/api/v1/receipts", json!({"content": receipt}), Some("executor"))).await;
    let rct_hash = b["hash"].as_str().unwrap().to_string();

    let (s, b) = send(&app, post_json("/api/v1/cnv/verify", json!({"receipt_digest": rct_hash}), Some("executor"))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["valid"], true);

    // Phase 8: File — 协作文件操作
    send(&app, post_json("/api/v0/files/deploy/config.yaml", json!({"content": "app: v2\nreplicas: 3"}), Some("executor"))).await;
    send(&app, post_json("/api/v0/files/infra/terraform.tf", json!({"content": "resource {}"}), Some("executor"))).await;

    let (s, b) = send(&app, post_json("/api/v0/push", json!({"message": "deploy v2"}), Some("executor"))).await;
    assert_eq!(s, StatusCode::CREATED);
    assert!(b["files"].as_u64().unwrap() >= 2);

    let (s, b) = send(&app, post_json("/api/v0/pull", json!({}), Some("planner"))).await;
    assert_eq!(s, StatusCode::OK);
    assert!(b["files"].as_u64().unwrap() >= 1);

    // Phase 9: Elevation
    let (_, b) = send(&app, post_json("/api/v0/elevation", json!({
        "agent_id": "monitor", "zones": ["infra"], "mode": "readonly", "reason": "monitoring", "duration": "30m"
    }), None)).await;
    let elev_id = b["request_id"].as_str().unwrap();
    send(&app, post_json(&format!("/api/v0/elevation/{}/approve", elev_id), json!({}), Some("baize-root"))).await;

    // Phase 10: IDN-LCM — 挂起/恢复
    send(&app, put_json("/api/v1/agents/executor/status", json!({"status": "suspended", "reason": "security"}), "baize-root")).await;
    let (s, _) = send(&app, post_json("/api/v0/blobs", json!({"content": "x"}), Some("executor"))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    send(&app, put_json("/api/v1/agents/executor/status", json!({"status": "active", "reason": "cleared"}), "baize-root")).await;
    let (s, _) = send(&app, post_json("/api/v0/blobs", json!({"content": "ok"}), Some("executor"))).await;
    assert_eq!(s, StatusCode::CREATED);

    // Phase 11: Audit
    let (s, b) = send(&app, post_json("/api/v1/audit/verify-chain", json!({}), Some("baize-root"))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["valid"], true);
    assert!(b["chain_length"].as_u64().unwrap() > 10);

    // Phase 12: Import/Export
    let (s, b) = send(&app, post_json("/api/v0/import", json!({
        "content": "metrics", "source": "prom", "trust_level": 2, "labels": {"cat": "metrics"}
    }), Some("executor"))).await;
    assert_eq!(s, StatusCode::CREATED);
    let imp_hash = b["hash"].as_str().unwrap();

    let (s, b) = send(&app, get_req_with_agent(&format!("/api/v0/export/{}", imp_hash), "planner")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["content"], "metrics");

    // Phase 13: Zone 隔离验证
    let (s, _) = send(&app, post_json("/api/v0/files/staging/x.txt", json!({"content": "z"}), Some("monitor"))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

// ═══════════════════════════════════════════════════════════════
// E2E-2: 波次协作评审（Mako-Wave 简化版）
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn e2e_wave_collaboration_review() {
    let app = test_app();
    setup_agent(&app, "reviewer", 2, &["review", "staging"], None).await;
    setup_agent(&app, "auditor", 2, &["security"], None).await;
    setup_agent(&app, "deployer", 2, &["deploy", "staging"], None).await;

    // 创建评审意图
    let intent = json!({
        "intent_id": "int-review-42", "intent_owner": "baize-root", "intent_creator": "baize-root",
        "intent_goal": "review-and-deploy", "intent_constraints": {"target_scope": ["staging", "deploy"]},
        "version": "1.0", "created_at": now_rfc3339(), "expires_at": now_plus_minutes(120)
    }).to_string();
    let (_, b) = send(&app, post_json("/api/v1/intents", json!({"content": intent}), Some("baize-root"))).await;
    let intent_hash = b["hash"].as_str().unwrap().to_string();

    // Wave 0: 三个 agent 并行写意见 blob
    send(&app, post_json("/api/v0/blobs", json!({
        "content": "Code review: LGTM", "labels": {"type": "opinion", "wave": "wave-0", "agent": "reviewer", "verdict": "pass", "change-id": "PR-42"}
    }), Some("reviewer"))).await;

    send(&app, post_json("/api/v0/blobs", json!({
        "content": "Security audit: no issues", "labels": {"type": "opinion", "wave": "wave-0", "agent": "auditor", "verdict": "pass", "change-id": "PR-42"}
    }), Some("auditor"))).await;

    send(&app, post_json("/api/v0/blobs", json!({
        "content": "Deploy plan: ready", "labels": {"type": "opinion", "wave": "wave-0", "agent": "deployer", "verdict": "pass", "change-id": "PR-42"}
    }), Some("deployer"))).await;

    // 查询 wave-0 意见
    let (s, b) = send(&app, post_json("/api/v0/blobs/query", json!({"labels": {"type": "opinion", "wave": "wave-0"}}), None)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b.as_array().unwrap().len(), 3);

    // Narrator 汇总
    send(&app, post_json("/api/v0/blobs", json!({
        "content": "Consensus: all pass", "labels": {"type": "narrator-summary", "wave": "wave-0", "consensus": "approved", "change-id": "PR-42"}
    }), Some("baize-root"))).await;

    // 签发授权给 deployer
    let authz = json!({
        "authorization_id": "authz-dep", "issuer": "baize-root", "subject": "deployer",
        "grant_type": "execute", "constraints": {"target_scope": ["deploy"]},
        "delegatable": false, "source_intent_digest": intent_hash,
        "root_authorizer": "baize-root", "nbf": now_rfc3339(),
        "exp": now_plus_minutes(60), "iat": now_rfc3339(), "jti": "j-dep", "version": "1.0"
    }).to_string();
    let (_, b) = send(&app, post_json("/api/v1/authorizations", json!({"content": authz}), Some("baize-root"))).await;
    let authz_hash = b["hash"].as_str().unwrap().to_string();

    // 创建回执
    let receipt = json!({
        "receipt_id": "rct-dep", "executor_id": "deployer", "task_id": "PR-42",
        "action_type": "execute", "intent_digest": intent_hash,
        "authorization_digest": authz_hash, "result_status": "SUCCEEDED",
        "started_at": now_rfc3339(), "finished_at": now_rfc3339()
    }).to_string();
    let (_, b) = send(&app, post_json("/api/v1/receipts", json!({"content": receipt}), Some("deployer"))).await;
    let rct_hash = b["hash"].as_str().unwrap().to_string();

    // CNV 验证
    let (s, b) = send(&app, post_json("/api/v1/cnv/verify", json!({"receipt_digest": rct_hash}), Some("deployer"))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["valid"], true);
}

// ═══════════════════════════════════════════════════════════════
// E2E-3: 跨 Agent Push/Pull 文件同步
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn e2e_cross_agent_file_sync() {
    let app = test_app();
    setup_agent(&app, "alice", 2, &["shared"], None).await;
    setup_agent(&app, "bob", 2, &["shared"], None).await;

    // alice 写文件并 push
    send(&app, post_json("/api/v0/files/shared/doc.txt", json!({"content": "hello from alice"}), Some("alice"))).await;
    let (s, b) = send(&app, post_json("/api/v0/push", json!({"message": "alice update"}), Some("alice"))).await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(b["files"], 1);

    // bob pull 并读取
    let (s, b) = send(&app, post_json("/api/v0/pull", json!({}), Some("bob"))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["files"], 1);

    let (s, b) = send(&app, get_req_with_agent("/api/v0/files/shared/doc.txt", "bob")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["content"], "hello from alice");

    // bob 追加并 push
    send(&app, post_json("/api/v0/files/shared/notes.txt", json!({"content": "bob notes"}), Some("bob"))).await;
    send(&app, post_json("/api/v0/push", json!({"message": "bob update"}), Some("bob"))).await;

    // alice pull 拿到两个文件
    let (s, b) = send(&app, post_json("/api/v0/pull", json!({}), Some("alice"))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["files"], 2);
}

// ═══════════════════════════════════════════════════════════════
// E2E-4: 借权审批链
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn e2e_elevation_approval_chain() {
    let app = test_app();
    setup_agent(&app, "ops", 3, &["A", "B", "C"], None).await;
    setup_agent(&app, "worker", 2, &["A"], Some("ops")).await;

    // worker 申请 zone B（超出自身 scope）
    let (_, b) = send(&app, post_json("/api/v0/elevation", json!({
        "agent_id": "worker", "zones": ["B"], "mode": "readonly", "reason": "need B"
    }), None)).await;
    let elev_id = b["request_id"].as_str().unwrap();

    // ops 审批（ops 有 zone B）
    let (s, _) = send(&app, post_json(&format!("/api/v0/elevation/{}/approve", elev_id), json!({}), Some("ops"))).await;
    assert_eq!(s, StatusCode::OK);

    // 非 parent 不能审批
    setup_agent(&app, "stranger", 3, &["B"], None).await;
    let (_, b) = send(&app, post_json("/api/v0/elevation", json!({
        "agent_id": "worker", "zones": ["B"], "mode": "readonly", "reason": "again"
    }), None)).await;
    let elev2 = b["request_id"].as_str().unwrap();
    let (s, _) = send(&app, post_json(&format!("/api/v0/elevation/{}/approve", elev2), json!({}), Some("stranger"))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // root 可以审批任何请求
    let (_, b) = send(&app, post_json("/api/v0/elevation", json!({
        "agent_id": "worker", "zones": ["Z"], "mode": "readonly", "reason": "need Z"
    }), None)).await;
    let elev3 = b["request_id"].as_str().unwrap();
    let (s, _) = send(&app, post_json(&format!("/api/v0/elevation/{}/approve", elev3), json!({}), Some("baize-root"))).await;
    assert_eq!(s, StatusCode::OK);
}
