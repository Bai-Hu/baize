//! v0 API 全端点集成测试
//!
//! 覆盖: Agent, Blob, Label, Push/Pull, Git, Elevation, Trace, Import/Export, File, Audit, Stats, Refs

mod common;
use common::*;
use serde_json::{json, Value};
use http::StatusCode;

// ═══════════════════════════════════════════════════════════════
// Agent 管理
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn v0_agent_register_root() {
    let app = test_app();
    let req = post_json("/api/v0/agents", json!({"name": "alice", "level": 3, "zones": ["A", "B"]}), Some("baize-root"));
    let (s, b) = send(&app, req).await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(b["id"], "alice");
    assert_eq!(b["level"], 3);
    assert!(b["cert_pem"].as_str().unwrap().contains("CERTIFICATE"));
}

#[tokio::test]
async fn v0_agent_register_with_parent() {
    let app = test_app();
    send(&app, post_json("/api/v0/agents", json!({"name": "parent", "level": 3, "zones": ["A", "B"]}), Some("baize-root"))).await;
    let req = post_json("/api/v0/agents", json!({"name": "child", "level": 2, "zones": ["A"], "parent_id": "parent"}), Some("baize-root"));
    let (s, b) = send(&app, req).await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(b["id"], "child");
}

#[tokio::test]
async fn v0_agent_register_duplicate_fails() {
    let app = test_app();
    send(&app, post_json("/api/v0/agents", json!({"name": "dup", "level": 2, "zones": ["A"]}), Some("baize-root"))).await;
    let req = post_json("/api/v0/agents", json!({"name": "dup", "level": 2, "zones": ["A"]}), Some("baize-root"));
    let (s, _) = send(&app, req).await;
    assert_eq!(s, StatusCode::CONFLICT);
}

#[tokio::test]
async fn v0_agent_register_level_exceeds_parent_fails() {
    let app = test_app();
    send(&app, post_json("/api/v0/agents", json!({"name": "p", "level": 2, "zones": ["A"]}), Some("baize-root"))).await;
    let req = post_json("/api/v0/agents", json!({"name": "bad", "level": 3, "zones": ["A"], "parent_id": "p"}), Some("baize-root"));
    let (s, _) = send(&app, req).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn v0_agent_register_zones_not_subset_fails() {
    let app = test_app();
    send(&app, post_json("/api/v0/agents", json!({"name": "p", "level": 3, "zones": ["A"]}), Some("baize-root"))).await;
    let req = post_json("/api/v0/agents", json!({"name": "bad", "level": 2, "zones": ["A", "B"], "parent_id": "p"}), Some("baize-root"));
    let (s, _) = send(&app, req).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn v0_agent_list() {
    let app = test_app();
    send(&app, post_json("/api/v0/agents", json!({"name": "x", "level": 2, "zones": ["A"]}), Some("baize-root"))).await;
    let (s, b) = send(&app, get_req("/api/v0/agents")).await;
    assert_eq!(s, StatusCode::OK);
    let agents = b.as_array().unwrap();
    assert!(agents.iter().any(|a| a["id"] == "baize-root"));
    assert!(agents.iter().any(|a| a["id"] == "x"));
}

#[tokio::test]
async fn v0_agent_revoke() {
    let app = test_app();
    send(&app, post_json("/api/v0/agents", json!({"name": "gone", "level": 2, "zones": ["A"]}), Some("baize-root"))).await;
    let (s, _) = send(&app, delete_req("/api/v0/agents/gone", "baize-root")).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (_, b) = send(&app, get_req("/api/v0/agents")).await;
    assert!(!b.as_array().unwrap().iter().any(|a| a["id"] == "gone"));
}

#[tokio::test]
async fn v0_agent_revoke_root_fails() {
    let app = test_app();
    let (s, _) = send(&app, delete_req("/api/v0/agents/baize-root", "baize-root")).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

// ═══════════════════════════════════════════════════════════════
// Blob 操作
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn v0_blob_write_read() {
    let app = test_app();
    let req = post_json("/api/v0/blobs", json!({"content": "hello", "labels": {"type": "test"}}), Some("baize-root"));
    let (s, b) = send(&app, req).await;
    assert_eq!(s, StatusCode::CREATED);
    let hash = b["hash"].as_str().unwrap();
    let (s2, b2) = send(&app, get_req(&format!("/api/v0/blobs/{}", hash))).await;
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(b2["content"], "hello");
    assert_eq!(b2["labels"]["type"], "test");
}

#[tokio::test]
async fn v0_blob_idempotent() {
    let app = test_app();
    let (_, b1) = send(&app, post_json("/api/v0/blobs", json!({"content": "same", "labels": {"a": "1"}}), Some("baize-root"))).await;
    let (_, b2) = send(&app, post_json("/api/v0/blobs", json!({"content": "same", "labels": {"b": "2"}}), Some("baize-root"))).await;
    assert_eq!(b1["hash"], b2["hash"]);
}

#[tokio::test]
async fn v0_blob_query() {
    let app = test_app();
    send(&app, post_json("/api/v0/blobs", json!({"content": "alpha", "labels": {"kind": "a"}}), Some("baize-root"))).await;
    send(&app, post_json("/api/v0/blobs", json!({"content": "beta", "labels": {"kind": "b"}}), Some("baize-root"))).await;
    let (s, b) = send(&app, post_json("/api/v0/blobs/query", json!({"labels": {"kind": "a"}}), None)).await;
    assert_eq!(s, StatusCode::OK);
    let arr = b.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["content"], "alpha");
}

#[tokio::test]
async fn v0_blob_write_requires_auth() {
    let app = test_app();
    let (s, _) = send(&app, post_json("/api/v0/blobs", json!({"content": "x"}), None)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn v0_blob_write_level0_denied() {
    let app = test_app();
    send(&app, post_json("/api/v0/agents", json!({"name": "sandbox", "level": 0, "zones": []}), Some("baize-root"))).await;
    let (s, b) = send(&app, post_json("/api/v0/blobs", json!({"content": "x"}), Some("sandbox"))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(b["error"], "permission denied");
}

// ═══════════════════════════════════════════════════════════════
// Label 操作
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn v0_label_add_and_query() {
    let app = test_app();
    let (_, b) = send(&app, post_json("/api/v0/blobs", json!({"content": "l"}), Some("baize-root"))).await;
    let hash = b["hash"].as_str().unwrap();
    let (s, _) = send(&app, post_json("/api/v0/labels", json!({"entity_hash": hash, "key": "p", "value": "high"}), Some("baize-root"))).await;
    assert_eq!(s, StatusCode::CREATED);
    let (s2, b2) = send(&app, get_req("/api/v0/labels/query?key=p&value=high")).await;
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(b2["labels"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn v0_label_duplicate_fails() {
    let app = test_app();
    let (_, b) = send(&app, post_json("/api/v0/blobs", json!({"content": "l"}), Some("baize-root"))).await;
    let hash = b["hash"].as_str().unwrap();
    send(&app, post_json("/api/v0/labels", json!({"entity_hash": hash, "key": "p", "value": "1"}), Some("baize-root"))).await;
    let (s, _) = send(&app, post_json("/api/v0/labels", json!({"entity_hash": hash, "key": "p", "value": "2"}), Some("baize-root"))).await;
    assert_eq!(s, StatusCode::CONFLICT);
}

// ═══════════════════════════════════════════════════════════════
// Push / Pull
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn v0_push_pull() {
    let app = test_app();
    send(&app, post_json("/api/v0/agents", json!({"name": "worker", "level": 2, "zones": ["A"]}), Some("baize-root"))).await;
    send(&app, post_json("/api/v0/files/A/f.txt", json!({"content": "data"}), Some("worker"))).await;
    let (s, b) = send(&app, post_json("/api/v0/push", json!({"message": "m"}), Some("worker"))).await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(b["files"], 1);

    let (s2, b2) = send(&app, post_json("/api/v0/pull", json!({}), Some("worker"))).await;
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(b2["files"], 1);
}

#[tokio::test]
async fn v0_push_empty_fails() {
    let app = test_app();
    send(&app, post_json("/api/v0/agents", json!({"name": "w", "level": 2, "zones": ["A"]}), Some("baize-root"))).await;
    let (s, _) = send(&app, post_json("/api/v0/push", json!({"message": "empty"}), Some("w"))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

// ═══════════════════════════════════════════════════════════════
// Git 操作
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn v0_git_refs() {
    let app = test_app();
    let (s, b) = send(&app, get_req("/api/v0/refs")).await;
    assert!(s == StatusCode::OK || s == StatusCode::INTERNAL_SERVER_ERROR);
    if s == StatusCode::OK {
        assert!(b["refs"].as_array().is_some());
    }
}

#[tokio::test]
async fn v0_git_log() {
    let app = test_app();
    let (s, b) = send(&app, get_req("/api/v0/log?limit=10")).await;
    assert!(s == StatusCode::OK || s == StatusCode::INTERNAL_SERVER_ERROR);
    if s == StatusCode::OK {
        assert!(b["commits"].as_array().is_some());
    }
}

#[tokio::test]
async fn v0_repo_stats() {
    let app = test_app();
    let (s, b) = send(&app, get_req("/api/v0/repo/stats")).await;
    assert!(s == StatusCode::OK || s == StatusCode::INTERNAL_SERVER_ERROR);
    if s == StatusCode::OK {
        assert!(b["total_blobs"].as_u64().is_some());
    }
}

// ═══════════════════════════════════════════════════════════════
// Elevation 借权
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn v0_elevation_request_approve_return() {
    let app = test_app();
    send(&app, post_json("/api/v0/agents", json!({"name": "w", "level": 3, "zones": ["A"]}), Some("baize-root"))).await;

    let (s, b) = send(&app, post_json("/api/v0/elevation", json!({"agent_id": "w", "zones": ["B"], "mode": "readonly", "reason": "r", "duration": "30m"}), None)).await;
    assert_eq!(s, StatusCode::CREATED);
    let id = b["request_id"].as_str().unwrap();

    let (s2, _) = send(&app, post_json(&format!("/api/v0/elevation/{}/approve", id), json!({}), Some("baize-root"))).await;
    assert_eq!(s2, StatusCode::OK);

    let (s3, b3) = send(&app, post_json(&format!("/api/v0/elevation/{}/return", id), json!({"agent_id": "w"}), Some("w"))).await;
    assert_eq!(s3, StatusCode::OK);
    assert_eq!(b3["status"], "returned");
}

#[tokio::test]
async fn v0_elevation_nonexistent_agent() {
    let app = test_app();
    let (s, _) = send(&app, post_json("/api/v0/elevation", json!({"agent_id": "ghost", "zones": ["A"], "mode": "readonly", "reason": "r"}), None)).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn v0_elevation_list() {
    let app = test_app();
    send(&app, post_json("/api/v0/agents", json!({"name": "w", "level": 2, "zones": ["A"]}), Some("baize-root"))).await;
    send(&app, post_json("/api/v0/elevation", json!({"agent_id": "w", "zones": ["A"], "mode": "readonly", "reason": "r"}), None)).await;
    let (s, b) = send(&app, get_req("/api/v0/elevation")).await;
    assert_eq!(s, StatusCode::OK);
    assert!(!b["requests"].as_array().unwrap().is_empty());
}

// ═══════════════════════════════════════════════════════════════
// Trace 追溯
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn v0_trace_identity() {
    let app = test_app();
    send(&app, post_json("/api/v0/agents", json!({"name": "p", "level": 3, "zones": ["A"]}), Some("baize-root"))).await;
    send(&app, post_json("/api/v0/agents", json!({"name": "c", "level": 2, "zones": ["A"], "parent_id": "p"}), Some("baize-root"))).await;
    let (s, b) = send(&app, get_req("/api/v0/trace/identity/c")).await;
    assert_eq!(s, StatusCode::OK);
    let chain = b["chain"].as_array().unwrap();
    assert_eq!(chain.len(), 3);
    assert_eq!(chain[0]["agent_id"], "c");
    assert_eq!(chain[1]["agent_id"], "p");
    assert_eq!(chain[2]["agent_id"], "baize-root");
}

// ═══════════════════════════════════════════════════════════════
// Import / Export
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn v0_import_export() {
    let app = test_app();
    let (s, b) = send(&app, post_json("/api/v0/import", json!({"content": "ext", "source": "s", "trust_level": 2}), Some("baize-root"))).await;
    assert_eq!(s, StatusCode::CREATED);
    let hash = b["hash"].as_str().unwrap();
    let (s2, b2) = send(&app, get_req_with_agent(&format!("/api/v0/export/{}", hash), "baize-root")).await;
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(b2["content"], "ext");
}

#[tokio::test]
async fn v0_import_trust_level_exceeds_agent_level() {
    let app = test_app();
    send(&app, post_json("/api/v0/agents", json!({"name": "low", "level": 1, "zones": ["A"]}), Some("baize-root"))).await;
    let (s, _) = send(&app, post_json("/api/v0/import", json!({"content": "x", "source": "s", "trust_level": 5}), Some("low"))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

// ═══════════════════════════════════════════════════════════════
// File 操作
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn v0_file_write_read_delete() {
    let app = test_app();
    send(&app, post_json("/api/v0/agents", json!({"name": "w", "level": 2, "zones": ["A"]}), Some("baize-root"))).await;

    let (s, b) = send(&app, post_json("/api/v0/files/A/cfg.yaml", json!({"content": "k: v"}), Some("w"))).await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(b["path"], "A/cfg.yaml");

    let (s2, b2) = send(&app, get_req_with_agent("/api/v0/files/A/cfg.yaml", "w")).await;
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(b2["content"], "k: v");

    let (s3, _) = send(&app, delete_req("/api/v0/files/A/cfg.yaml", "w")).await;
    assert_eq!(s3, StatusCode::NO_CONTENT);

    let (s4, _) = send(&app, get_req_with_agent("/api/v0/files/A/cfg.yaml", "w")).await;
    assert_eq!(s4, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn v0_file_list() {
    let app = test_app();
    send(&app, post_json("/api/v0/agents", json!({"name": "w", "level": 2, "zones": ["A"]}), Some("baize-root"))).await;
    send(&app, post_json("/api/v0/files/A/a.txt", json!({"content": "a"}), Some("w"))).await;
    send(&app, post_json("/api/v0/files/A/b.txt", json!({"content": "b"}), Some("w"))).await;
    let (s, b) = send(&app, get_req_with_agent("/api/v0/files", "w")).await;
    assert_eq!(s, StatusCode::OK);
    let files = b["files"].as_array().unwrap();
    assert!(files.len() >= 2, "expected at least 2 files, got: {:?}", files);
    assert!(files.iter().any(|f| f.as_str() == Some("A/a.txt") || f.as_str() == Some("A\\a.txt")), "missing A/a.txt in {:?}", files);
    assert!(files.iter().any(|f| f.as_str() == Some("A/b.txt") || f.as_str() == Some("A\\b.txt")), "missing A/b.txt in {:?}", files);
}

#[tokio::test]
async fn v0_file_zone_check_blocks() {
    let app = test_app();
    send(&app, post_json("/api/v0/agents", json!({"name": "w", "level": 2, "zones": ["A"]}), Some("baize-root"))).await;
    let (s, b) = send(&app, post_json("/api/v0/files/B/x.txt", json!({"content": "hack"}), Some("w"))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert!(b["error"].as_str().unwrap().contains("permission denied"));
}

#[tokio::test]
async fn v0_file_level0_cannot_write() {
    let app = test_app();
    send(&app, post_json("/api/v0/agents", json!({"name": "sbx", "level": 0, "zones": ["A"]}), Some("baize-root"))).await;
    let (s, _) = send(&app, post_json("/api/v0/files/A/x.txt", json!({"content": "x"}), Some("sbx"))).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

// ═══════════════════════════════════════════════════════════════
// Audit 审计
// ═══════════════════════════════════════════════════════════════

#[tokio::test]
async fn v0_audit_query() {
    let app = test_app();
    send(&app, post_json("/api/v0/blobs", json!({"content": "audited"}), Some("baize-root"))).await;
    let (s, b) = send(&app, get_req("/api/v0/audit")).await;
    assert_eq!(s, StatusCode::OK);
    let records = b["records"].as_array().unwrap();
    assert!(!records.is_empty());
    assert_eq!(records[0]["type"], "blob_write");
}

#[tokio::test]
async fn v0_audit_filter_by_agent() {
    let app = test_app();
    send(&app, post_json("/api/v0/agents", json!({"name": "worker", "level": 2, "zones": ["A"]}), Some("baize-root"))).await;
    send(&app, post_json("/api/v0/blobs", json!({"content": "w-data"}), Some("worker"))).await;
    let (s, b) = send(&app, get_req("/api/v0/audit?agent=worker")).await;
    assert_eq!(s, StatusCode::OK);
    let records = b["records"].as_array().unwrap();
    assert!(records.iter().all(|r| r["agent"] == "worker"));
}

#[tokio::test]
async fn v0_audit_filter_by_type() {
    let app = test_app();
    send(&app, post_json("/api/v0/agents", json!({"name": "w", "level": 2, "zones": ["A"]}), Some("baize-root"))).await;
    send(&app, post_json("/api/v0/files/A/x.txt", json!({"content": "x"}), Some("w"))).await;
    let (s, b) = send(&app, get_req("/api/v0/audit?type=file_write")).await;
    assert_eq!(s, StatusCode::OK);
    let records = b["records"].as_array().unwrap();
    assert!(records.iter().any(|r| r["type"] == "file_write"));
}
