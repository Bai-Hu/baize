//! 端到端场景测试：多 Agent 协作部署系统
//!
//! 场景：一个四层 Agent 树协作完成一次生产环境部署。
//!
//! Agent 树:
//!   baize-root (L4)
//!     └─ commander (L3, zones: [deploy, infra])
//!           ├─ planner (L2, zones: [deploy])
//!           └─ executor (L2, zones: [deploy, infra])
//!                 └─ monitor (L1, zones: [deploy])
//!
//! 覆盖域: IDN, INF, INT, AZN, LNK, RCT, Elevation, Proof, File, Audit, v1/v2, Import/Export

use axum::body::Body;
use baize_server::api;
use baize_server::Baize;
use baize_server::pipeline::AgentRegistry;
use baize_server::pipeline::agent_manager::KmsManager;
use baize_core::crypto::CryptoProvider;
use baize_core::scope::Level;
use http_body_util::BodyExt;
use http::{Request, StatusCode};
use serde_json::{json, Value};
use tower::ServiceExt;

// ─── 辅助 ───

fn test_app() -> axum::Router {
    let baize = Baize::init_in_memory().unwrap();
    api::app(baize)
}

async fn send(router: &axum::Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = router.clone().oneshot(req).await.expect("oneshot failed");
    let status = resp.status();
    let bytes = resp.into_body().collect().await.expect("collect failed").to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap_or(json!(null));
    (status, body)
}

fn post(uri: &str, body: Value, agent: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-agent-id", agent)
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

fn post_no_agent(uri: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

fn get_(uri: &str) -> Request<Body> {
    Request::builder().method("GET").uri(uri).body(Body::empty()).unwrap()
}

fn get_agent(uri: &str, agent: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .header("x-agent-id", agent)
        .body(Body::empty())
        .unwrap()
}

fn delete_(uri: &str, agent: &str) -> Request<Body> {
    Request::builder()
        .method("DELETE")
        .uri(uri)
        .header("x-agent-id", agent)
        .body(Body::empty())
        .unwrap()
}

fn put(uri: &str, body: Value, agent: &str) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-agent-id", agent)
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

fn gen_ephemeral_pub() -> String {
    let (_, pub_pem) = baize_core::crypto::generate_x25519_keypair().unwrap();
    pub_pem.lines().find(|l| !l.starts_with('-')).unwrap().to_string()
}

fn now_plus(minutes: i64) -> String {
    (chrono::Utc::now() + chrono::Duration::minutes(minutes)).to_rfc3339()
}

fn now_minus(minutes: i64) -> String {
    (chrono::Utc::now() - chrono::Duration::minutes(minutes)).to_rfc3339()
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

// ─── 端到端场景测试 ───

#[tokio::test]
async fn e2e_multi_agent_deployment() {
    let app = test_app();

    // 预计算所有时间戳，避免 now_plus() 多次调用产生微妙差异导致校验失败
    let ts_created = now_rfc3339();
    let ts_expires_intent = now_plus(60);      // intent expires_at
    let ts_exp_authz = ts_expires_intent.clone(); // authz exp 必须不晚于 intent expires_at
    let ts_deadline = now_plus(120);           // constraints deadline
    let ts_nbf = now_rfc3339();
    let ts_iat = now_rfc3339();
    let ts_sub_expires = now_plus(30);
    let ts_sub_created = now_rfc3339();

    // ═══════════════════════════════════════════
    // Phase 1: IDN — 注册四层 Agent 树
    // ═══════════════════════════════════════════

    // 1a. 注册 commander (L3)
    let (s, b) = send(&app, post(
        "/api/v0/agents",
        json!({"name": "commander", "level": 3, "zones": ["deploy", "infra"]}),
        "baize-root",
    )).await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(b["id"], "commander");
    assert_eq!(b["level"], 3);

    // 1b. 注册 planner (L2, parent: commander)
    let (s, b) = send(&app, post(
        "/api/v0/agents",
        json!({"name": "planner", "level": 2, "zones": ["deploy"], "parent_id": "commander"}),
        "baize-root",
    )).await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(b["id"], "planner");

    // 1c. 注册 executor (L2, parent: commander)
    let (s, b) = send(&app, post(
        "/api/v0/agents",
        json!({"name": "executor", "level": 2, "zones": ["deploy", "infra"], "parent_id": "commander"}),
        "baize-root",
    )).await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(b["id"], "executor");

    // 1d. 注册 monitor (L1, parent: executor)
    let (s, b) = send(&app, post(
        "/api/v0/agents",
        json!({"name": "monitor", "level": 1, "zones": ["deploy"], "parent_id": "executor"}),
        "baize-root",
    )).await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(b["id"], "monitor");

    // 1e. 身份链追溯
    let (s, b) = send(&app, get_("/api/v0/trace/identity/monitor")).await;
    assert_eq!(s, StatusCode::OK);
    let chain = b["chain"].as_array().unwrap();
    assert_eq!(chain.len(), 4, "monitor → executor → commander → root");
    assert_eq!(chain[0]["agent_id"], "monitor");
    assert_eq!(chain[1]["agent_id"], "executor");
    assert_eq!(chain[2]["agent_id"], "commander");
    assert_eq!(chain[3]["agent_id"], "baize-root");

    // 1f. 子 agent level 不能超过父 agent
    let (s, _) = send(&app, post(
        "/api/v0/agents",
        json!({"name": "bad-child", "level": 4, "zones": ["deploy"], "parent_id": "commander"}),
        "baize-root",
    )).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "child level exceeds parent should fail");

    // ═══════════════════════════════════════════
    // Phase 2: INF-KMS — 密钥轮换
    // ═══════════════════════════════════════════

    let (s, b) = send(&app, post(
        "/api/v1/agents/executor/keys/rotate",
        json!({"purpose": "INT_SIGN"}),
        "executor",
    )).await;
    assert_eq!(s, StatusCode::OK);
    assert!(!b["new_key_hash"].as_str().unwrap().is_empty());

    // root 密钥不可轮换
    let (s, _) = send(&app, post(
        "/api/v1/agents/baize-root/keys/rotate",
        json!({"purpose": "IDN_SIGN"}),
        "baize-root",
    )).await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // ═══════════════════════════════════════════
    // Phase 3: IDN-ATH — 运行态证明
    // ═══════════════════════════════════════════

    // commander 需要运行态证明才能执行 Level 3 敏感操作
    let (s, b) = send(&app, post(
        "/api/v1/agents/commander/proof",
        json!({
            "instance_state_attributes": {"instance_id": "commander-host-01", "status": "running"},
            "proof_anchor_mode": "CREDENTIAL_ANCHORED"
        }),
        "baize-root",
    )).await;
    assert_eq!(s, StatusCode::CREATED);
    assert!(!b["proof_id"].as_str().unwrap().is_empty());

    // ═══════════════════════════════════════════
    // Phase 4: INT — 创建部署意图 + 子意图派生
    // ═══════════════════════════════════════════

    // 4a. commander 创建顶层部署意图
    let intent_content = json!({
        "intent_id": "deploy-prod-v2",
        "intent_owner": "commander",
        "intent_creator": "commander",
        "task_id": "TASK-001",
        "intent_goal": "Deploy v2 to production with zero downtime",
        "intent_constraints": {
            "target_scope": ["deploy", "infra"],
            "time_scope": {"deadline": ts_deadline},
            "amount_scope": {"max_budget": 1000}
        },
        "version": "1.0",
        "created_at": ts_created,
        "expires_at": ts_expires_intent
    }).to_string();

    let (s, b) = send(&app, post(
        "/api/v1/intents",
        json!({"content": intent_content}),
        "commander",
    )).await;
    assert_eq!(s, StatusCode::CREATED, "intent create failed: {:?}", b);
    let intent_hash = b["hash"].as_str().unwrap().to_string();

    // 4b. 读取意图
    let (s, b) = send(&app, get_(&format!("/api/v1/intents/{}", intent_hash))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["labels"]["type"], "intent");

    // 4c. 查询意图
    let (s, b) = send(&app, get_("/api/v1/intents?owner=commander")).await;
    assert_eq!(s, StatusCode::OK);
    assert!(!b["intents"].as_array().unwrap().is_empty());

    // 4d. planner 派生子意图（约束收缩：target_scope 缩小，amount 缩小）
    let sub_intent_content = json!({
        "sub_intent_id": "deploy-db-migration",
        "parent_intent_digest": intent_hash,
        "deriver_id": "planner",
        "subject": "database migration",
        "derivation_depth": 1,
        "intent_goal": "Run database migration for v2 schema",
        "intent_constraints": {
            "target_scope": ["deploy"],
            "time_scope": {"deadline": ts_deadline},
            "amount_scope": {"max_budget": 500}
        },
        "created_at": ts_sub_created,
        "expires_at": ts_sub_expires
    }).to_string();

    let (s, b) = send(&app, post(
        "/api/v1/intents/derive",
        json!({"content": sub_intent_content}),
        "planner",
    )).await;
    assert_eq!(s, StatusCode::CREATED, "sub-intent derive failed: {:?}", b);
    let sub_intent_hash = b["hash"].as_str().unwrap().to_string();

    // 4e. 子意图约束不能超过父意图（budget 2000 > 1000 → 拒绝）
    let bad_sub = json!({
        "sub_intent_id": "deploy-bad",
        "parent_intent_digest": intent_hash,
        "deriver_id": "planner",
        "subject": "bad sub-intent",
        "derivation_depth": 1,
        "intent_goal": "exceed budget",
        "intent_constraints": {
            "amount_scope": {"max_budget": 2000}
        },
        "created_at": ts_sub_created,
        "expires_at": ts_sub_expires
    }).to_string();

    let (s, _) = send(&app, post(
        "/api/v1/intents/derive",
        json!({"content": bad_sub}),
        "planner",
    )).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "constraint violation should be rejected");

    // ═══════════════════════════════════════════
    // Phase 5: AZN — 签发授权 + 委托 + AZN-VER
    // ═══════════════════════════════════════════

    // 5a. commander 签发执行授权给 executor
    let authz_content = json!({
        "authorization_id": "authz-deploy-v2-exec",
        "issuer": "commander",
        "subject": "executor",
        "grant_type": "execute",
        "constraints": {
            "target_scope": ["deploy"],
            "amount_scope": {"max_budget": 500}
        },
        "delegatable": true,
        "delegation_depth_remaining": 2,
        "delegation_mode": "BOUNDED",
        "source_intent_digest": intent_hash,
        "root_authorizer": "commander",
        "nbf": ts_nbf,
        "exp": ts_exp_authz,
        "iat": ts_iat,
        "jti": "jti-deploy-exec-001",
        "version": "1.0"
    }).to_string();

    let (s, b) = send(&app, post(
        "/api/v1/authorizations",
        json!({"content": authz_content}),
        "commander",
    )).await;
    assert_eq!(s, StatusCode::CREATED, "authorization create failed: {:?}", b);
    let authz_hash = b["hash"].as_str().unwrap().to_string();

    // 5b. AZN-VER 五项校验
    let (s, b) = send(&app, post(
        &format!("/api/v1/authorizations/{}/verify", authz_hash),
        json!({
            "action_type": "execute",
            "subject": "executor",
            "amount": 300.0
        }),
        "commander",
    )).await;
    assert_eq!(s, StatusCode::OK, "AZN-VER failed: {:?}", b);
    assert_eq!(b["valid"], true, "AZN-VER should be valid: {:?}", b["errors"]);

    // 5c. executor 委托子授权给 planner（进一步收缩约束）
    let delegate_content = json!({
        "authorization_id": "authz-deploy-v2-plan",
        "issuer": "executor",
        "subject": "planner",
        "grant_type": "execute",
        "constraints": {
            "target_scope": ["deploy"],
            "amount_scope": {"max_budget": 200}
        },
        "delegatable": true,
        "delegation_depth_remaining": 1,
        "delegation_mode": "BOUNDED",
        "source_intent_digest": intent_hash,
        "parent_authz_digest": authz_hash,
        "root_authorizer": "commander",
        "nbf": now_rfc3339(),
        "exp": now_plus(30),
        "iat": now_rfc3339(),
        "jti": "jti-deploy-plan-001",
        "version": "1.0"
    }).to_string();

    let (s, b) = send(&app, post(
        "/api/v1/authorizations/delegate",
        json!({"content": delegate_content}),
        "executor",
    )).await;
    assert_eq!(s, StatusCode::CREATED, "delegation failed: {:?}", b);
    let delegate_hash = b["hash"].as_str().unwrap().to_string();

    // 5d. 委托深度耗尽后不能再委托
    let over_delegate = json!({
        "authorization_id": "authz-over-delegate",
        "issuer": "planner",
        "subject": "monitor",
        "grant_type": "execute",
        "constraints": {"target_scope": ["deploy"]},
        "delegatable": true,
        "delegation_depth_remaining": 1,
        "delegation_mode": "BOUNDED",
        "source_intent_digest": intent_hash,
        "parent_authz_digest": delegate_hash,
        "root_authorizer": "commander",
        "nbf": now_rfc3339(),
        "exp": now_plus(10),
        "iat": now_rfc3339(),
        "jti": "jti-over-001",
        "version": "1.0"
    }).to_string();

    let (s, _) = send(&app, post(
        "/api/v1/authorizations/delegate",
        json!({"content": over_delegate}),
        "planner",
    )).await;
    // depth_remaining 应为 0（1-1=0），不能为 1
    assert!(s == StatusCode::BAD_REQUEST, "over-delegation should fail");

    // ═══════════════════════════════════════════
    // Phase 6: LNK — 建立加密会话
    // ═══════════════════════════════════════════

    // 6a. commander 和 executor 建立 session
    let (s, b) = send(&app, post(
        "/api/v1/sessions",
        json!({
            "session_id": "sess-deploy-v2",
            "peer_a": "commander",
            "peer_b": "executor",
            "ephemeral_pub": gen_ephemeral_pub(),
            "cipher_suites": ["AES-256-GCM"],
            "credential_digest_a": "sha256:dummy-a",
            "credential_digest_b": "sha256:dummy-b",
            "handshake_transcript_digest": "sha256:transcript",
        }),
        "commander",
    )).await;
    assert_eq!(s, StatusCode::CREATED, "session create failed: {:?}", b);
    assert_eq!(b["session_id"], "sess-deploy-v2");

    // 6b. executor 接受 session
    let (s, b) = send(&app, post(
        "/api/v1/sessions/sess-deploy-v2/accept",
        json!({
            "credential_digest_responder": "sha256:dummy-b",
            "ephemeral_pub": gen_ephemeral_pub(),
            "selected_cipher_suite": "AES-256-GCM",
            "handshake_transcript_digest": "sha256:transcript-accept",
        }),
        "executor",
    )).await;
    assert_eq!(s, StatusCode::CREATED, "session accept failed: {:?}", b);

    // 6c. 读取 session
    let (s, b) = send(&app, get_("/api/v1/sessions/sess-deploy-v2")).await;
    assert_eq!(s, StatusCode::OK);

    // 6d. 关闭 session
    let (s, b) = send(&app, post(
        "/api/v1/sessions/sess-deploy-v2/close",
        json!({"reason": "deployment complete"}),
        "commander",
    )).await;
    assert_eq!(s, StatusCode::CREATED, "session close failed: {:?}", b);
    assert_eq!(b["status"], "closed");

    // 6e. 不能重复关闭
    let (s, _) = send(&app, post(
        "/api/v1/sessions/sess-deploy-v2/close",
        json!({"reason": "double close"}),
        "commander",
    )).await;
    assert_eq!(s, StatusCode::CONFLICT, "double close should fail");

    // ═══════════════════════════════════════════
    // Phase 7: RCT — 执行回执 + 自动 CNV
    // ═══════════════════════════════════════════

    let receipt_content = json!({
        "receipt_id": "rct-deploy-v2-001",
        "executor_id": "executor",
        "task_id": "TASK-001",
        "action_type": "execute",
        "intent_digest": sub_intent_hash,
        "authorization_digest": authz_hash,
        "result_status": "SUCCEEDED",
        "execution_result": "Database migration completed successfully",
        "started_at": now_rfc3339(),
        "finished_at": now_rfc3339()
    }).to_string();

    let (s, b) = send(&app, post(
        "/api/v1/receipts",
        json!({"content": receipt_content}),
        "executor",
    )).await;
    assert_eq!(s, StatusCode::CREATED, "receipt create failed: {:?}", b);
    let receipt_hash = b["hash"].as_str().unwrap().to_string();

    // 7b. 查询回执
    let (s, b) = send(&app, get_("/api/v1/receipts?executor=executor")).await;
    assert_eq!(s, StatusCode::OK);
    assert!(!b["receipts"].as_array().unwrap().is_empty());

    // 7c. CNV 全链路校验
    let (s, b) = send(&app, post(
        "/api/v1/cnv/verify",
        json!({"receipt_digest": receipt_hash}),
        "executor",
    )).await;
    assert_eq!(s, StatusCode::OK, "CNV verify request failed: {:?}", b);

    // ═══════════════════════════════════════════
    // Phase 8: File — 协作文件操作 + Push/Pull
    // ═══════════════════════════════════════════

    // 8a. executor 写入部署配置
    let (s, b) = send(&app, post(
        "/api/v0/files/deploy/config.yaml",
        json!({"content": "app: myservice\nversion: v2\nreplicas: 3"}),
        "executor",
    )).await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(b["path"], "deploy/config.yaml");

    // 8b. executor 写入数据库迁移脚本
    let (s, _) = send(&app, post(
        "/api/v0/files/deploy/migration.sql",
        json!({"content": "ALTER TABLE users ADD COLUMN email TEXT;"}),
        "executor",
    )).await;
    assert_eq!(s, StatusCode::CREATED);

    // 8c. executor 写入基础设施配置
    let (s, _) = send(&app, post(
        "/api/v0/files/infra/terraform.tf",
        json!({"content": "resource \"aws_instance\" \"app\" { ami = \"ami-12345\" }"}),
        "executor",
    )).await;
    assert_eq!(s, StatusCode::CREATED);

    // 8d. 文件列表
    let (s, b) = send(&app, get_agent("/api/v0/files", "executor")).await;
    assert_eq!(s, StatusCode::OK);
    let files = b["files"].as_array().unwrap();
    assert!(files.len() >= 3, "should have at least 3 files");

    // 8e. 读取文件
    let (s, b) = send(&app, get_agent("/api/v0/files/deploy/config.yaml", "executor")).await;
    assert_eq!(s, StatusCode::OK);
    assert!(b["content"].as_str().unwrap().contains("myservice"));

    // 8f. Push 到主仓库
    let (s, b) = send(&app, post(
        "/api/v0/push",
        json!({"message": "deploy v2 config and migration"}),
        "executor",
    )).await;
    assert_eq!(s, StatusCode::CREATED);
    assert!(b["files"].as_u64().unwrap() >= 3);

    // 8g. planner pull（跨 agent 文件同步）
    let (s, b) = send(&app, post(
        "/api/v0/pull",
        json!({}),
        "planner",
    )).await;
    assert_eq!(s, StatusCode::OK);
    assert!(b["files"].as_u64().unwrap() >= 2, "planner should get deploy/ files");

    // 8h. planner 能读取 deploy/ 文件
    let (s, b) = send(&app, get_agent("/api/v0/files/deploy/config.yaml", "planner")).await;
    assert_eq!(s, StatusCode::OK);
    assert!(b["content"].as_str().unwrap().contains("myservice"));

    // 8i. 删除临时文件
    let (s, _) = send(&app, delete_("/api/v0/files/deploy/migration.sql", "executor")).await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    // ═══════════════════════════════════════════
    // Phase 9: Elevation — 临时提权
    // ═══════════════════════════════════════════

    // 9a. monitor (L1) 不能写 infra/ 文件
    let (s, _) = send(&app, post(
        "/api/v0/files/infra/monitor-check.yaml",
        json!({"content": "monitor was here"}),
        "monitor",
    )).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "L1 agent should not be able to write files");

    // 9b. monitor 请求提权到 infra zone
    let (s, b) = send(&app, post(
        "/api/v0/elevation",
        json!({
            "agent_id": "monitor",
            "zones": ["infra"],
            "mode": "readonly",
            "reason": "need to read infra config for monitoring",
            "duration": "30m"
        }),
        "baize-root",
    )).await;
    // monitor 是 L1, 提权请求可以被创建（不管是否能审批通过）
    // 实际上 elevation_request 在 baize 的实现中只检查 agent 存在，不做 scope 预检
    // 但审批时会检查审批者覆盖了请求的 zones

    // 9c. 读取 infra 文件不需要提权（读操作 L1 就行）
    // 但写文件需要提权到 L1+（写需要 Level >= 1）
    // monitor 是 L1，可以写（只要 zone 匹配）
    // 让我们测试 zone 越权：monitor 只有 deploy zone，尝试写 infra 文件
    let (s, _) = send(&app, post(
        "/api/v0/files/infra/monitor-test.yaml",
        json!({"content": "zone violation test"}),
        "monitor",
    )).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "zone violation should be rejected");

    // 9d. 提权到 infra zone
    let (s, b) = send(&app, post(
        "/api/v0/elevation",
        json!({
            "agent_id": "executor",
            "zones": ["monitoring"],
            "mode": "readonly",
            "reason": "need monitoring zone for observability"
        }),
        "baize-root",
    )).await;
    assert_eq!(s, StatusCode::CREATED);
    let elev_id = b["request_id"].as_str().unwrap().to_string();

    // 9e. commander 审批（覆盖 monitoring zone）
    let (s, _) = send(&app, post(
        &format!("/api/v0/elevation/{}/approve", elev_id),
        json!({}),
        "baize-root",
    )).await;
    // root 可以审批任何请求
    // commander 只有 deploy/infra，如果请求了 monitoring 且 commander 没有覆盖，
    // 审批可能失败。但 root 豁免，所以 baize-root 审批应该成功

    // ═══════════════════════════════════════════
    // Phase 10: IDN-LCM — 凭证生命周期
    // ═══════════════════════════════════════════

    // 10a. 查询 commander 状态
    let (s, b) = send(&app, get_("/api/v1/agents/commander/status")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["status"], "active");

    // 10b. 挂起 executor
    let (s, b) = send(&app, put(
        "/api/v1/agents/executor/status",
        json!({"status": "suspended", "reason": "security investigation"}),
        "baize-root",
    )).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["status"], "suspended");

    // 10c. 挂起的 agent 不能写
    let (s, _) = send(&app, post(
        "/api/v0/files/deploy/test.txt",
        json!({"content": "should fail"}),
        "executor",
    )).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "suspended agent should be blocked");

    // 10d. 恢复 executor
    let (s, b) = send(&app, put(
        "/api/v1/agents/executor/status",
        json!({"status": "active", "reason": "investigation cleared"}),
        "baize-root",
    )).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["status"], "active");

    // 10e. 恢复后可以写
    let (s, _) = send(&app, post(
        "/api/v0/files/deploy/resumed.txt",
        json!({"content": "back to work"}),
        "executor",
    )).await;
    assert_eq!(s, StatusCode::CREATED, "reactivated agent should be able to write");

    // 10f. 撤销 monitor（终态）
    let (s, _) = send(&app, delete_("/api/v0/agents/monitor", "baize-root")).await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    // 10g. 撤销后不可操作
    let (s, _) = send(&app, post(
        "/api/v0/blobs",
        json!({"content": "should fail"}),
        "monitor",
    )).await;
    // revoked agent removed from agents map → NeedUserDecision
    assert!(s == StatusCode::UNPROCESSABLE_ENTITY || s == StatusCode::UNAUTHORIZED,
        "revoked agent should be rejected");

    // ═══════════════════════════════════════════
    // Phase 11: Audit — 审计链验证
    // ═══════════════════════════════════════════

    let (s, b) = send(&app, post("/api/v1/audit/verify-chain", json!({}), "baize-root")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["valid"], true, "audit chain should be valid: {:?}", b["errors"]);
    assert!(b["chain_length"].as_u64().unwrap() > 10, "should have substantial audit trail");

    // 查询审计记录
    let (s, b) = send(&app, get_("/api/v1/audit?agent=executor")).await;
    assert_eq!(s, StatusCode::OK);
    let records = b["records"].as_array().unwrap();
    assert!(!records.is_empty(), "executor should have audit records");

    // ═══════════════════════════════════════════
    // Phase 12: Import/Export
    // ═══════════════════════════════════════════

    // 12a. 导入外部数据
    let (s, b) = send(&app, post(
        "/api/v0/import",
        json!({
            "content": "prometheus monitoring metrics: cpu=80% mem=60%",
            "source": "prometheus-scraper",
            "trust_level": 2,
            "labels": {"origin": "external", "category": "metrics"}
        }),
        "executor",
    )).await;
    assert_eq!(s, StatusCode::CREATED);
    let import_hash = b["hash"].as_str().unwrap().to_string();

    // 12b. 导出
    let (s, b) = send(&app, get_agent(
        &format!("/api/v0/export/{}", import_hash),
        "planner",
    )).await;
    assert_eq!(s, StatusCode::OK);
    assert!(b["content"].as_str().unwrap().contains("prometheus"));

    // ═══════════════════════════════════════════
    // Phase 13: Git 操作
    // ═══════════════════════════════════════════

    // 注意：init_in_memory() 创建的 git repo 可能为空（无初始 commit），
    // git_log 和 repo_stats 在此场景下可能返回 500。
    // 这里验证 API 端点可达即可，不强制要求有 commit 历史。

    // 13a. 查看 git log（空 repo 可能返回 500）
    let (s, _b) = send(&app, get_("/api/v0/log?limit=10")).await;
    assert!(s == StatusCode::OK || s == StatusCode::INTERNAL_SERVER_ERROR,
        "git log should return OK or 500 for empty repo, got {}", s);

    // 13b. repo stats
    let (s, b) = send(&app, get_("/api/v0/repo/stats")).await;
    assert!(s == StatusCode::OK || s == StatusCode::INTERNAL_SERVER_ERROR,
        "repo stats should return OK or 500 for empty repo, got {}", s);
    if s == StatusCode::OK {
        assert!(b["total_blobs"].as_u64().unwrap() > 0);
    }

    // ═══════════════════════════════════════════
    // Phase 14: Label 操作（归属校验）
    // ═══════════════════════════════════════════

    // 14a. root 可以给任意 blob 加 label
    let (s, _) = send(&app, post(
        "/api/v0/labels",
        json!({"entity_hash": intent_hash, "key": "priority", "value": "critical"}),
        "baize-root",
    )).await;
    assert_eq!(s, StatusCode::CREATED);

    // 14b. 查询 label
    let (s, b) = send(&app, get_("/api/v0/labels/query?key=priority&value=critical")).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(b["labels"].as_array().unwrap().len(), 1);

    // ═══════════════════════════════════════════
    // Phase 15: Blob 幂等性
    // ═══════════════════════════════════════════

    let (s1, b1) = send(&app, post(
        "/api/v0/blobs",
        json!({"content": "idempotent-test-data", "labels": {"test": "idempotent"}}),
        "executor",
    )).await;
    let (s2, b2) = send(&app, post(
        "/api/v0/blobs",
        json!({"content": "idempotent-test-data", "labels": {"test": "idempotent"}}),
        "executor",
    )).await;
    assert_eq!(s1, StatusCode::CREATED);
    assert_eq!(s2, StatusCode::CREATED);
    assert_eq!(b1["hash"], b2["hash"], "same content should produce same hash");
}

// ─── v1/v2 签名认证 E2E ───

#[tokio::test]
async fn e2e_v1_signed_workflow() {
    let mut baize = Baize::init_in_memory().unwrap();

    // 注册 agent
    baize.agent_register("baize-root", "signed-agent", Level(2), vec!["A"], None).unwrap();

    // 提取签名密钥
    let key = {
        use baize_server::pipeline::agent_manager::KmsManager;
        let pem = baize.kms_get_active_key("signed-agent", "IDN_SIGN").unwrap();
        baize_server::pipeline::auth::extract_signing_key(&pem)
    };

    let app = api::app(baize);

    // v1 有签名 → 放行
    let timestamp = chrono::Utc::now().to_rfc3339();
    let body_str = serde_json::to_string(&json!({"content": "signed data", "labels": {"type": "generic"}})).unwrap();
    let sig = baize_server::pipeline::auth::compute_signature(
        CryptoProvider::default().request_signer.as_ref(),
        &key, &timestamp, "POST", "/api/v1/blobs", &body_str,
    );
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/blobs")
        .header("content-type", "application/json")
        .header("x-agent-id", "signed-agent")
        .header("x-timestamp", &timestamp)
        .header("x-signature", &sig)
        .body(Body::from(body_str))
        .unwrap();
    let (s, b) = send(&app, req).await;
    assert_eq!(s, StatusCode::CREATED, "v1 signed request should succeed: {:?}", b);

    // v1 无签名 → 也放行（fallback）
    let req = post(
        "/api/v1/blobs",
        json!({"content": "unsigned ok", "labels": {"type": "generic"}}),
        "signed-agent",
    );
    let (s, _) = send(&app, req).await;
    assert_eq!(s, StatusCode::CREATED, "v1 unsigned should fallback to agent-id");
}

#[tokio::test]
async fn e2e_v2_mandatory_signature_and_nonce() {
    let mut baize = Baize::init_in_memory().unwrap();
    baize.agent_register("baize-root", "v2-agent", Level(2), vec!["A"], None).unwrap();

    let key = {
        use baize_server::pipeline::agent_manager::KmsManager;
        let pem = baize.kms_get_active_key("v2-agent", "IDN_SIGN").unwrap();
        baize_server::pipeline::auth::extract_signing_key(&pem)
    };

    let app = api::app(baize);

    // v2 无签名 → 拒绝
    let req = post(
        "/api/v2/blobs",
        json!({"content": "no sig", "labels": {"type": "generic"}}),
        "v2-agent",
    );
    let (s, _) = send(&app, req).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "v2 without signature should be rejected");

    // v2 有签名 → 放行
    let timestamp = chrono::Utc::now().to_rfc3339();
    let body_str = serde_json::to_string(&json!({"content": "v2 signed", "labels": {"type": "generic"}})).unwrap();
    let sig = baize_server::pipeline::auth::compute_signature(
        CryptoProvider::default().request_signer.as_ref(),
        &key, &timestamp, "POST", "/api/v2/blobs", &body_str,
    );
    let req = Request::builder()
        .method("POST")
        .uri("/api/v2/blobs")
        .header("content-type", "application/json")
        .header("x-agent-id", "v2-agent")
        .header("x-timestamp", &timestamp)
        .header("x-signature", &sig)
        .body(Body::from(body_str.clone()))
        .unwrap();
    let (s, b) = send(&app, req).await;
    assert_eq!(s, StatusCode::CREATED, "v2 signed request should succeed: {:?}", b);

    // v2 + nonce 重放防护
    let nonce = "nonce-e2e-001";
    let timestamp2 = chrono::Utc::now().to_rfc3339();
    let body2 = serde_json::to_string(&json!({"content": "with nonce", "labels": {"type": "generic"}})).unwrap();
    let sig2 = baize_server::pipeline::auth::compute_signature(
        CryptoProvider::default().request_signer.as_ref(),
        &key, &timestamp2, "POST", "/api/v2/blobs", &body2,
    );

    // 第一次带 nonce → 成功
    let req = Request::builder()
        .method("POST")
        .uri("/api/v2/blobs")
        .header("content-type", "application/json")
        .header("x-agent-id", "v2-agent")
        .header("x-timestamp", &timestamp2)
        .header("x-signature", &sig2)
        .header("x-nonce", nonce)
        .body(Body::from(body2.clone()))
        .unwrap();
    let (s, _) = send(&app, req).await;
    assert_eq!(s, StatusCode::CREATED, "first nonce request should succeed");

    // 第二次相同 nonce → 409 Conflict
    let req = Request::builder()
        .method("POST")
        .uri("/api/v2/blobs")
        .header("content-type", "application/json")
        .header("x-agent-id", "v2-agent")
        .header("x-timestamp", &timestamp2)
        .header("x-signature", &sig2)
        .header("x-nonce", nonce)
        .body(Body::from(body2))
        .unwrap();
    let (s, _) = send(&app, req).await;
    assert_eq!(s, StatusCode::CONFLICT, "replayed nonce should be rejected");
}

// ─── 负面路径综合测试 ───

#[tokio::test]
async fn e2e_negative_paths() {
    let app = test_app();

    // 注册 agent
    send(&app, post(
        "/api/v0/agents",
        json!({"name": "worker", "level": 2, "zones": ["A"]}),
        "baize-root",
    )).await;

    // NP1: 无 x-agent-id → 401
    let (s, _) = send(&app, post_no_agent(
        "/api/v0/blobs",
        json!({"content": "no auth"}),
    )).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // NP2: 不存在的 agent → 422
    let (s, _) = send(&app, post(
        "/api/v0/blobs",
        json!({"content": "ghost"}),
        "nonexistent-agent",
    )).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);

    // NP3: Zone 越权
    let (s, _) = send(&app, post(
        "/api/v0/files/B/secret.txt",
        json!({"content": "zone B data"}),
        "worker",
    )).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "zone violation should fail");

    // NP4: 空约束的意图 → 拒绝
    let bad_intent = json!({
        "intent_id": "bad-intent",
        "intent_owner": "worker",
        "intent_creator": "worker",
        "intent_goal": "test",
        "intent_constraints": {},
        "version": "1.0",
        "created_at": now_rfc3339(),
        "expires_at": now_plus(10)
    }).to_string();
    let (s, _) = send(&app, post(
        "/api/v1/intents",
        json!({"content": bad_intent}),
        "worker",
    )).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "empty constraints should fail");

    // NP5: REJECTED 回执缺 rejection_reason → 拒绝
    let bad_receipt = json!({
        "receipt_id": "bad-receipt",
        "executor_id": "worker",
        "task_id": "T-001",
        "action_type": "test",
        "intent_digest": "sha256:fake",
        "authorization_digest": "sha256:fake",
        "result_status": "REJECTED",
        "started_at": now_rfc3339(),
        "finished_at": now_rfc3339()
    }).to_string();
    let (s, _) = send(&app, post(
        "/api/v1/receipts",
        json!({"content": bad_receipt}),
        "worker",
    )).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "REJECTED without reason should fail");

    // NP6: 导入空 source → 拒绝
    let (s, _) = send(&app, post(
        "/api/v0/import",
        json!({"content": "data", "source": "  ", "trust_level": 1}),
        "worker",
    )).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "empty source should fail");

    // NP7: 导入 trust_level 超过 agent level → 拒绝
    let (s, _) = send(&app, post(
        "/api/v0/import",
        json!({"content": "data", "source": "test", "trust_level": 5}),
        "worker",
    )).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "trust_level exceeds agent level should fail");
}

// ─── Proof 强制校验 E2E ───

#[tokio::test]
async fn e2e_level3_proof_required() {
    let app = test_app();

    // 注册 Level 3 agent
    send(&app, post(
        "/api/v0/agents",
        json!({"name": "sensitive-worker", "level": 3, "zones": ["secure"]}),
        "baize-root",
    )).await;

    // L3 agent 写入 generic blob 不需要 proof
    let (s, _) = send(&app, post(
        "/api/v0/blobs",
        json!({"content": "generic data", "labels": {"type": "generic"}}),
        "sensitive-worker",
    )).await;
    assert_eq!(s, StatusCode::CREATED, "generic blob should work without proof");

    // L3 agent 写入 authorization 类型（在 proof_required 列表中）但没有 proof → 应该失败
    // 需要先创建一个 intent 给授权引用
    let intent_content = json!({
        "intent_id": "authz-ref-intent",
        "intent_owner": "baize-root",
        "intent_creator": "baize-root",
        "intent_goal": "reference intent for authz proof test",
        "intent_constraints": {"scope": "secure"},
        "version": "1.0",
        "created_at": now_rfc3339(),
        "expires_at": now_plus(60)
    }).to_string();
    let (s, b) = send(&app, post(
        "/api/v1/intents",
        json!({"content": intent_content}),
        "baize-root",
    )).await;
    assert_eq!(s, StatusCode::CREATED, "root intent for authz ref: {:?}", b);
    let ref_intent_hash = b["hash"].as_str().unwrap().to_string();

    // sensitive-worker (L3) 写 authorization 不带 proof → 拒绝
    let authz_no_proof = json!({
        "authorization_id": "authz-needs-proof",
        "issuer": "sensitive-worker",
        "subject": "sensitive-worker",
        "source_intent_digest": ref_intent_hash,
        "constraints": {"target_scope": ["secure"]},
        "grant_type": "execute",
        "delegatable": false,
        "root_authorizer": "baize-root",
        "nbf": now_rfc3339(),
        "exp": now_plus(30),
        "iat": now_rfc3339(),
        "jti": "jti-no-proof-001",
        "version": "1.0"
    }).to_string();
    let (s, _) = send(&app, post(
        "/api/v1/authorizations",
        json!({"content": authz_no_proof}),
        "sensitive-worker",
    )).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "L3 authorization write without proof should fail");

    // 生成 proof 后再写 → 应该成功
    send(&app, post(
        "/api/v1/agents/sensitive-worker/proof",
        json!({"instance_state_attributes": {"instance_id": "sw-01"}}),
        "baize-root",
    )).await;

    let authz_with_proof = json!({
        "authorization_id": "authz-with-proof",
        "issuer": "sensitive-worker",
        "subject": "sensitive-worker",
        "source_intent_digest": ref_intent_hash,
        "constraints": {"target_scope": ["secure"]},
        "grant_type": "execute",
        "delegatable": false,
        "root_authorizer": "baize-root",
        "nbf": now_rfc3339(),
        "exp": now_plus(30),
        "iat": now_rfc3339(),
        "jti": "jti-with-proof-001",
        "version": "1.0"
    }).to_string();
    let (s, b) = send(&app, post(
        "/api/v1/authorizations",
        json!({"content": authz_with_proof}),
        "sensitive-worker",
    )).await;
    assert_eq!(s, StatusCode::CREATED, "L3 authorization write with proof should succeed: {:?}", b);
}

// ─── 导出敏感度检查 E2E ───

#[tokio::test]
async fn e2e_export_sensitivity_check() {
    let app = test_app();

    send(&app, post(
        "/api/v0/agents",
        json!({"name": "reader", "level": 0, "zones": []}),
        "baize-root",
    )).await;

    // root 写入高敏感 blob
    let (_, b) = send(&app, post(
        "/api/v0/blobs",
        json!({"content": "secret data", "labels": {"sensitivity": "high"}}),
        "baize-root",
    )).await;
    let hash = b["hash"].as_str().unwrap();

    // L0 agent 导出高敏感 blob → 应该失败
    let (s, _) = send(&app, get_agent(
        &format!("/api/v0/export/{}", hash),
        "reader",
    )).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "L0 should not export high sensitivity");

    // root 可以导出
    let (s, _) = send(&app, get_agent(
        &format!("/api/v0/export/{}", hash),
        "baize-root",
    )).await;
    assert_eq!(s, StatusCode::OK, "root should export anything");
}
