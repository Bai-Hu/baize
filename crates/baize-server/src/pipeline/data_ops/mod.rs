//! 数据操作接口：blob 写入、label 追加、导入、导出
//!
//! v1 扩展：按 blob type label 分派校验逻辑（INT/AZN/LNK）

pub(crate) mod intent_ops;
pub(crate) mod authz_ops;
pub(crate) mod session_ops;

use std::collections::HashMap;

use baize_core::error::Error;
use baize_core::labels::*;
use baize_core::approval::{ApprovalAction, PendingOperation};

use super::Baize;
use super::auditor::Auditor;
use super::agent_manager::PermissionGuard;
use super::approval::ApprovalManager;

// session 消息校验（非 handler 路径，在注册表分流前直接调用）
use session_ops::validate_session_message_blob;

/// 数据操作接口：blob 写入、label 追加、导入、导出
pub trait DataOps {
    /// 管道：Blob 写入（含 ASL 校验）
    fn pipe_blob_write(
        &self,
        agent_id: &str,
        content: &str,
        labels: &HashMap<String, String>,
    ) -> Result<baize_core::storage::Blob, Error>;

    /// 管道：Label 追加
    fn pipe_label_add(
        &self,
        agent_id: &str,
        entity_hash: &str,
        key: &str,
        value: &str,
    ) -> Result<(), Error>;

    /// 管道：外部数据导入
    fn pipe_import(
        &self,
        agent_id: &str,
        content: &str,
        source: &str,
        trust_level: u8,
        extra_labels: Option<HashMap<String, String>>,
    ) -> Result<baize_core::storage::Blob, Error>;

    /// 管道：数据导出（含敏感度检查）
    fn pipe_export(
        &self,
        agent_id: &str,
        hash: &str,
    ) -> Result<baize_core::storage::Blob, Error>;
}

impl Baize {
    /// Blob 写入实际执行（审批通过后由 pipe_blob_write 或 replay_operation 调用）
    pub(crate) fn execute_blob_write(
        &self,
        agent_id: &str,
        content: &str,
        labels: &HashMap<String, String>,
    ) -> Result<baize_core::storage::Blob, Error> {
        let identity = self.verify_write_agent(agent_id)?;

        let blob_type = labels.get("type").map(|s| s.as_str()).unwrap_or("");

        // LNK session 消息分流：带 x-session-id 且非已知类型的一律走 session 消息校验
        let handler = self.protocol_registry.get(blob_type);
        let is_known = handler.is_some() || self.protocol_registry.is_known_type(blob_type);
        let is_session_msg = labels.contains_key(LABEL_SESSION_ID) && !is_known;
        if is_session_msg {
            validate_session_message_blob(self.store(), labels, agent_id)?;
        }

        // 通过注册表查找 handler 执行校验 + proof 检查
        if let Some(handler) = handler {
            if handler.requires_proof() && identity.level >= 3 && agent_id != baize_core::ROOT_AGENT_ID {
                self.require_valid_proof(agent_id)?;
            }
            let ctx = super::protocol::ValidationContext {
                storage: self.store(),
                identity: self.identity.as_ref(),
                agent_id,
            };
            handler.validate(&ctx, content, labels)?;
        }

        // 写入 blob
        let mut owned_labels = labels.clone();
        owned_labels.insert("agent".to_string(), agent_id.to_string());
        let blob = self.storage.blob_write(content, &owned_labels)?;

        // Post-write 副作用（含回滚）— 重新查找 handler（借 checker 要求）
        if let Some(handler) = self.protocol_registry.get(blob_type) {
            if let Err(e) = handler.post_write(self.store(), &blob) {
                if let Err(del_err) = self.storage.blob_delete(&blob.hash) {
                    eprintln!("[WARN] post_write rollback: failed to delete blob {}: {}", blob.hash, del_err);
                }
                return Err(e);
            }
        }

        self.audit("blob_write", agent_id, "success", Some(&blob.hash))?;
        Ok(blob)
    }
}

impl DataOps for Baize {
    fn pipe_blob_write(
        &self,
        agent_id: &str,
        content: &str,
        labels: &HashMap<String, String>,
    ) -> Result<baize_core::storage::Blob, Error> {
        let op = PendingOperation::BlobWrite {
            agent_id: agent_id.to_string(),
            content: content.to_string(),
            labels: labels.clone(),
        };
        self.check_approval_gate(agent_id, &ApprovalAction::BlobWrite, &op)?;
        self.execute_blob_write(agent_id, content, labels)
    }

    fn pipe_label_add(
        &self,
        agent_id: &str,
        entity_hash: &str,
        key: &str,
        value: &str,
    ) -> Result<(), Error> {
        let _identity = self.verify_write_agent(agent_id)?;

        // 校验目标 blob 存在
        let blob = self.storage.blob_read(entity_hash)
            .map_err(|_| Error::NotFound(format!("blob {}", entity_hash)))?;

        // blob 归属校验：agent 只能给自己的 blob 加 label（root 豁免）
        if agent_id != baize_core::ROOT_AGENT_ID {
            let blob_agent = blob.labels.get("agent");
            let blob_owner = blob.labels.get("x-key-owner")
                .or_else(|| blob.labels.get("x-cert-agent"));
            let is_owner = blob_agent.map(|a| a == agent_id).unwrap_or(false)
                || blob_owner.map(|a| a == agent_id).unwrap_or(false);
            if !is_owner {
                return Err(Error::PermissionDenied(
                    format!("agent {} cannot modify labels on blob {} (not owner)", agent_id, entity_hash)
                ));
            }
        }

        self.storage.label_add(entity_hash, key, value)?;
        self.audit("label_add", agent_id, "success", Some(entity_hash))?;
        Ok(())
    }

    fn pipe_import(
        &self,
        agent_id: &str,
        content: &str,
        source: &str,
        trust_level: u8,
        extra_labels: Option<HashMap<String, String>>,
    ) -> Result<baize_core::storage::Blob, Error> {
        let identity = self.verify_write_agent(agent_id)?;

        // trust_level 上限校验：不能超过 agent 自身 level
        if trust_level > identity.level {
            return Err(Error::Validation(
                format!("trust_level {} exceeds agent {} level {}", trust_level, agent_id, identity.level)
            ));
        }

        // source 非空校验
        if source.trim().is_empty() {
            return Err(Error::Validation("source cannot be empty for import".into()));
        }

        let mut labels = extra_labels.unwrap_or_default();
        labels.insert("source".to_string(), source.to_string());
        labels.insert("trust-level".to_string(), trust_level.to_string());
        labels.insert("imported".to_string(), "true".to_string());

        if trust_level == 0 {
            labels.insert("sandbox".to_string(), "true".to_string());
        }

        let blob = self.storage.blob_write(content, &labels)?;
        self.audit("import", agent_id, "success", Some(&blob.hash))?;
        Ok(blob)
    }

    fn pipe_export(
        &self,
        agent_id: &str,
        hash: &str,
    ) -> Result<baize_core::storage::Blob, Error> {
        let identity = self.verify_read_agent(agent_id)?;
        let blob = self.storage.blob_read(hash)?;

        // 敏感标签检查
        if let Some(sensitivity) = blob.labels.get("sensitivity") {
            let required_level = match sensitivity.as_str() {
                "high" => 3,
                "medium" => 2,
                "low" => 1,
                _ => 0,
            };
            if identity.level < required_level {
                return Err(Error::PermissionDenied(
                    format!("export requires level {} for sensitivity '{}', agent {} is level {}",
                        required_level, sensitivity, agent_id, identity.level)
                ));
            }
        }

        // Zone 检查
        if let Some(blob_zone) = blob.labels.get("zone") {
            if !identity.zones.iter().any(|z| z == "*")
                && !identity.zones.contains(blob_zone)
            {
                return Err(Error::PermissionDenied(
                    format!("agent {} scope {:?} does not cover zone '{}'",
                        agent_id, identity.zones, blob_zone)
                ));
            }
        }

        self.audit("export", agent_id, "success", Some(hash))?;
        Ok(blob)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use baize_core::scope::Level;

    use crate::pipeline::agent_manager::AgentRegistry;

    fn setup_baize() -> Baize {
        Baize::init_in_memory().unwrap()
    }

    fn register_agent(baize: &mut Baize, name: &str, level: u8) {
        baize.agent_register("baize-root", name, Level(level), vec!["A"], None).unwrap();
    }

    // ─── INT tests ───

    #[test]
    fn intent_write_ok() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "writer", 2);

        let content = serde_json::json!({
            "intent_id": "int-001",
            "intent_owner": "writer",
            "intent_creator": "writer",
            "intent_goal": "deploy service",
            "intent_constraints": {"budget": 100},
            "version": "1.0",
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-12-31T23:59:59Z",
        }).to_string();

        let mut labels = HashMap::new();
        labels.insert("type".to_string(), BLOB_TYPE_INTENT.to_string());
        labels.insert(LABEL_INTENT_ID.to_string(), "int-001".to_string());
        labels.insert(LABEL_INTENT_STATUS.to_string(), "active".to_string());
        labels.insert(LABEL_INTENT_EXPIRES.to_string(), "2026-12-31T23:59:59Z".to_string());

        let result = baize.pipe_blob_write("writer", &content, &labels);
        assert!(result.is_ok(), "intent write should succeed: {:?}", result);
    }

    #[test]
    fn intent_write_empty_constraints_fails() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "writer", 2);

        let content = serde_json::json!({
            "intent_id": "int-002",
            "intent_owner": "writer",
            "intent_creator": "writer",
            "intent_goal": "deploy",
            "intent_constraints": {},
            "version": "1.0",
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-12-31T23:59:59Z",
        }).to_string();

        let mut labels = HashMap::new();
        labels.insert("type".to_string(), BLOB_TYPE_INTENT.to_string());
        labels.insert(LABEL_INTENT_ID.to_string(), "int-002".to_string());

        let result = baize.pipe_blob_write("writer", &content, &labels);
        assert!(result.is_err());
        match result {
            Err(Error::Validation(msg)) => assert!(msg.contains("intent_constraints")),
            other => panic!("expected Validation, got {:?}", other),
        }
    }

    #[test]
    fn intent_write_duplicate_id_fails() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "writer", 2);

        let content = serde_json::json!({
            "intent_id": "int-dup",
            "intent_owner": "writer",
            "intent_creator": "writer",
            "intent_goal": "deploy",
            "intent_constraints": {"budget": 100},
            "version": "1.0",
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-12-31T23:59:59Z",
        }).to_string();

        let mut labels = HashMap::new();
        labels.insert("type".to_string(), BLOB_TYPE_INTENT.to_string());
        labels.insert(LABEL_INTENT_ID.to_string(), "int-dup".to_string());
        labels.insert(LABEL_INTENT_STATUS.to_string(), "active".to_string());
        labels.insert(LABEL_INTENT_EXPIRES.to_string(), "2026-12-31T23:59:59Z".to_string());

        baize.pipe_blob_write("writer", &content, &labels).unwrap();

        let content2 = serde_json::json!({
            "intent_id": "int-dup",
            "intent_owner": "writer",
            "intent_creator": "writer",
            "intent_goal": "different",
            "intent_constraints": {"budget": 200},
            "version": "1.0",
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-12-31T23:59:59Z",
        }).to_string();

        let mut labels2 = HashMap::new();
        labels2.insert("type".to_string(), BLOB_TYPE_INTENT.to_string());
        labels2.insert(LABEL_INTENT_ID.to_string(), "int-dup".to_string());
        labels2.insert(LABEL_INTENT_STATUS.to_string(), "active".to_string());
        labels2.insert(LABEL_INTENT_EXPIRES.to_string(), "2026-12-31T23:59:59Z".to_string());

        let result = baize.pipe_blob_write("writer", &content2, &labels2);
        assert!(result.is_err());
        match result {
            Err(Error::Conflict(msg)) => assert!(msg.contains("int-dup")),
            other => panic!("expected Conflict, got {:?}", other),
        }
    }

    #[test]
    fn sub_intent_write_ok() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "writer", 2);

        // 先写根意图
        let parent_content = serde_json::json!({
            "intent_id": "int-parent",
            "intent_owner": "writer",
            "intent_creator": "writer",
            "intent_goal": "deploy",
            "intent_constraints": {"budget": 200},
            "version": "1.0",
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-12-31T23:59:59Z",
        }).to_string();

        let mut parent_labels = HashMap::new();
        parent_labels.insert("type".to_string(), BLOB_TYPE_INTENT.to_string());
        parent_labels.insert(LABEL_INTENT_ID.to_string(), "int-parent".to_string());
        parent_labels.insert(LABEL_INTENT_STATUS.to_string(), "active".to_string());
        parent_labels.insert(LABEL_INTENT_EXPIRES.to_string(), "2026-12-31T23:59:59Z".to_string());
        parent_labels.insert(LABEL_DERIVATION_DEPTH.to_string(), "0".to_string());

        let parent_blob = baize.pipe_blob_write("writer", &parent_content, &parent_labels).unwrap();

        // 写子意图
        let child_content = serde_json::json!({
            "sub_intent_id": "sub-001",
            "parent_intent_digest": parent_blob.hash,
            "deriver_id": "writer",
            "subject": "deploy",
            "derivation_depth": 1,
            "intent_goal": "deploy db",
            "intent_constraints": {"budget": 100},
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-06-01T00:00:00Z",
        }).to_string();

        let mut child_labels = HashMap::new();
        child_labels.insert("type".to_string(), BLOB_TYPE_SUB_INTENT.to_string());
        child_labels.insert(LABEL_INTENT_ID.to_string(), "sub-001".to_string());
        child_labels.insert(LABEL_INTENT_STATUS.to_string(), "active".to_string());
        child_labels.insert(LABEL_INTENT_EXPIRES.to_string(), "2026-06-01T00:00:00Z".to_string());
        child_labels.insert(LABEL_PARENT_INTENT.to_string(), parent_blob.hash.clone());
        child_labels.insert(LABEL_DERIVATION_DEPTH.to_string(), "1".to_string());

        let result = baize.pipe_blob_write("writer", &child_content, &child_labels);
        assert!(result.is_ok(), "sub-intent write should succeed: {:?}", result);
    }

    #[test]
    fn sub_intent_constraint_violation_fails() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "writer", 2);

        let parent_content = serde_json::json!({
            "intent_id": "int-parent",
            "intent_owner": "writer",
            "intent_creator": "writer",
            "intent_goal": "deploy",
            "intent_constraints": {"budget": 100},
            "version": "1.0",
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-12-31T23:59:59Z",
        }).to_string();

        let mut parent_labels = HashMap::new();
        parent_labels.insert("type".to_string(), BLOB_TYPE_INTENT.to_string());
        parent_labels.insert(LABEL_INTENT_ID.to_string(), "int-parent".to_string());
        parent_labels.insert(LABEL_INTENT_STATUS.to_string(), "active".to_string());
        parent_labels.insert(LABEL_INTENT_EXPIRES.to_string(), "2026-12-31T23:59:59Z".to_string());
        parent_labels.insert(LABEL_DERIVATION_DEPTH.to_string(), "0".to_string());

        let parent_blob = baize.pipe_blob_write("writer", &parent_content, &parent_labels).unwrap();

        // 子意图超出父约束
        let child_content = serde_json::json!({
            "sub_intent_id": "sub-bad",
            "parent_intent_digest": parent_blob.hash,
            "deriver_id": "writer",
            "subject": "deploy",
            "derivation_depth": 1,
            "intent_goal": "deploy db",
            "intent_constraints": {"budget": 500},
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": "2026-06-01T00:00:00Z",
        }).to_string();

        let mut child_labels = HashMap::new();
        child_labels.insert("type".to_string(), BLOB_TYPE_SUB_INTENT.to_string());
        child_labels.insert(LABEL_INTENT_ID.to_string(), "sub-bad".to_string());
        child_labels.insert(LABEL_PARENT_INTENT.to_string(), parent_blob.hash.clone());
        child_labels.insert(LABEL_DERIVATION_DEPTH.to_string(), "1".to_string());

        let result = baize.pipe_blob_write("writer", &child_content, &child_labels);
        assert!(result.is_err());
        match result {
            Err(Error::ConstraintViolation(msg)) => assert!(msg.contains("budget")),
            other => panic!("expected ConstraintViolation, got {:?}", other),
        }
    }

    // ─── LNK tests ───

    /// 辅助：生成一个合法的 X25519 公钥 PEM 片段（用于测试）
    fn gen_ephemeral_pub() -> String {
        let (_, pub_pem) = baize_core::crypto::generate_x25519_keypair().unwrap();
        // 提取 base64 部分（中间行）
        pub_pem.lines().find(|l| !l.starts_with('-')).unwrap().to_string()
    }

    #[test]
    fn session_init_ok() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "alice", 2);
        register_agent(&mut baize, "bob", 2);

        let mut labels = HashMap::new();
        labels.insert("type".to_string(), BLOB_TYPE_SESSION_INIT.to_string());
        labels.insert(LABEL_SESSION_ID.to_string(), "sess-001".to_string());
        labels.insert(LABEL_SESSION_PEER_A.to_string(), "alice".to_string());
        labels.insert(LABEL_SESSION_PEER_B.to_string(), "bob".to_string());

        let pub_a = gen_ephemeral_pub();
        let content = format!(r#"{{"ephemeral_pub":"{}","cipher_suites":["AES-256-GCM"]}}"#, pub_a);
        let result = baize.pipe_blob_write("alice", &content, &labels);
        assert!(result.is_ok(), "session-init should succeed: {:?}", result);
    }

    #[test]
    fn session_init_unknown_peer_fails() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "alice", 2);

        let mut labels = HashMap::new();
        labels.insert("type".to_string(), BLOB_TYPE_SESSION_INIT.to_string());
        labels.insert(LABEL_SESSION_ID.to_string(), "sess-002".to_string());
        labels.insert(LABEL_SESSION_PEER_A.to_string(), "alice".to_string());
        labels.insert(LABEL_SESSION_PEER_B.to_string(), "unknown-agent".to_string());

        let pub_a = gen_ephemeral_pub();
        let content = format!(r#"{{"ephemeral_pub":"{}","cipher_suites":["AES-256-GCM"]}}"#, pub_a);
        let result = baize.pipe_blob_write("alice", &content, &labels);
        assert!(result.is_err());
    }

    #[test]
    fn session_accept_ok() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "alice", 2);
        register_agent(&mut baize, "bob", 2);

        let mut init_labels = HashMap::new();
        init_labels.insert("type".to_string(), BLOB_TYPE_SESSION_INIT.to_string());
        init_labels.insert(LABEL_SESSION_ID.to_string(), "sess-003".to_string());
        init_labels.insert(LABEL_SESSION_PEER_A.to_string(), "alice".to_string());
        init_labels.insert(LABEL_SESSION_PEER_B.to_string(), "bob".to_string());

        let pub_a = gen_ephemeral_pub();
        let init_content = format!(r#"{{"ephemeral_pub":"{}","cipher_suites":["AES-256-GCM"]}}"#, pub_a);
        let init_blob = baize.pipe_blob_write("alice", &init_content, &init_labels).unwrap();

        let mut accept_labels = HashMap::new();
        accept_labels.insert("type".to_string(), BLOB_TYPE_SESSION_ACCEPT.to_string());
        accept_labels.insert(LABEL_SESSION_ID.to_string(), "sess-003".to_string());
        accept_labels.insert("parent".to_string(), init_blob.hash);

        let pub_b = gen_ephemeral_pub();
        let accept_content = format!(r#"{{"ephemeral_pub":"{}","selected_cipher_suite":"AES-256-GCM"}}"#, pub_b);
        let result = baize.pipe_blob_write("bob", &accept_content, &accept_labels);
        assert!(result.is_ok(), "session-accept should succeed: {:?}", result);
    }

    #[test]
    fn session_message_seq_ok() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "alice", 2);
        register_agent(&mut baize, "bob", 2);

        // init
        let mut init_labels = HashMap::new();
        init_labels.insert("type".to_string(), BLOB_TYPE_SESSION_INIT.to_string());
        init_labels.insert(LABEL_SESSION_ID.to_string(), "sess-004".to_string());
        init_labels.insert(LABEL_SESSION_PEER_A.to_string(), "alice".to_string());
        init_labels.insert(LABEL_SESSION_PEER_B.to_string(), "bob".to_string());
        let pub_a = gen_ephemeral_pub();
        let init_blob = baize.pipe_blob_write("alice", &format!(r#"{{"ephemeral_pub":"{}","cipher_suites":["AES-256-GCM"]}}"#, pub_a), &init_labels).unwrap();

        // accept
        let mut accept_labels = HashMap::new();
        accept_labels.insert("type".to_string(), BLOB_TYPE_SESSION_ACCEPT.to_string());
        accept_labels.insert(LABEL_SESSION_ID.to_string(), "sess-004".to_string());
        accept_labels.insert("parent".to_string(), init_blob.hash);
        let pub_b = gen_ephemeral_pub();
        baize.pipe_blob_write("bob", &format!(r#"{{"ephemeral_pub":"{}","selected_cipher_suite":"AES-256-GCM"}}"#, pub_b), &accept_labels).unwrap();

        // message seq=1
        let mut msg_labels = HashMap::new();
        msg_labels.insert("type".to_string(), "session-message".to_string());
        msg_labels.insert(LABEL_SESSION_ID.to_string(), "sess-004".to_string());
        msg_labels.insert(LABEL_MESSAGE_SEQ.to_string(), "1".to_string());

        let result = baize.pipe_blob_write("alice", r#"{"msg":"hello"}"#, &msg_labels);
        assert!(result.is_ok(), "session message seq=1 should succeed: {:?}", result);
    }

    #[test]
    fn session_message_seq_skip_fails() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "alice", 2);
        register_agent(&mut baize, "bob", 2);

        // init + accept
        let mut init_labels = HashMap::new();
        init_labels.insert("type".to_string(), BLOB_TYPE_SESSION_INIT.to_string());
        init_labels.insert(LABEL_SESSION_ID.to_string(), "sess-005".to_string());
        init_labels.insert(LABEL_SESSION_PEER_A.to_string(), "alice".to_string());
        init_labels.insert(LABEL_SESSION_PEER_B.to_string(), "bob".to_string());
        let pub_a = gen_ephemeral_pub();
        let init_blob = baize.pipe_blob_write("alice", &format!(r#"{{"ephemeral_pub":"{}","cipher_suites":["AES-256-GCM"]}}"#, pub_a), &init_labels).unwrap();

        let mut accept_labels = HashMap::new();
        accept_labels.insert("type".to_string(), BLOB_TYPE_SESSION_ACCEPT.to_string());
        accept_labels.insert(LABEL_SESSION_ID.to_string(), "sess-005".to_string());
        accept_labels.insert("parent".to_string(), init_blob.hash);
        let pub_b = gen_ephemeral_pub();
        baize.pipe_blob_write("bob", &format!(r#"{{"ephemeral_pub":"{}","selected_cipher_suite":"AES-256-GCM"}}"#, pub_b), &accept_labels).unwrap();

        // seq=3 (should be 1)
        let mut msg_labels = HashMap::new();
        msg_labels.insert("type".to_string(), "session-message".to_string());
        msg_labels.insert(LABEL_SESSION_ID.to_string(), "sess-005".to_string());
        msg_labels.insert(LABEL_MESSAGE_SEQ.to_string(), "3".to_string());

        let result = baize.pipe_blob_write("alice", r#"{"msg":"hello"}"#, &msg_labels);
        assert!(result.is_err());
    }

    // ─── v0 regression tests ───

    #[test]
    fn plain_blob_write_still_works() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "writer", 2);

        let result = baize.pipe_blob_write("writer", "plain data", &HashMap::new());
        assert!(result.is_ok());
        assert_eq!(result.unwrap().content, "plain data");
    }

    // ─── v2 Phase 1.2: 有效期运行时检查 ───

    #[test]
    fn intent_write_already_expired_fails() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "writer", 2);

        let content = serde_json::json!({
            "intent_id": "int-exp",
            "intent_constraints": {"budget": 100},
            "created_at": "2020-01-01T00:00:00Z",
            "expires_at": "2020-12-31T23:59:59Z",
        }).to_string();

        let mut labels = HashMap::new();
        labels.insert("type".to_string(), BLOB_TYPE_INTENT.to_string());
        labels.insert(LABEL_INTENT_EXPIRES.to_string(), "2020-12-31T23:59:59Z".to_string());

        let result = baize.pipe_blob_write("writer", &content, &labels);
        assert!(result.is_err(), "expired intent should be rejected");
        match result {
            Err(Error::IntentExpired(msg)) => assert!(msg.contains("2020-12-31")),
            other => panic!("expected IntentExpired, got {:?}", other),
        }
    }

    #[test]
    fn sub_intent_expired_parent_fails() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "writer", 2);

        // 用 storage 直接写一个已过期的父意图（绕过 intent 自身过期检查）
        let mut parent_labels = HashMap::new();
        parent_labels.insert("type".to_string(), BLOB_TYPE_INTENT.to_string());
        parent_labels.insert(LABEL_INTENT_EXPIRES.to_string(), "2020-12-31T23:59:59Z".to_string());
        parent_labels.insert(LABEL_DERIVATION_DEPTH.to_string(), "0".to_string());
        let parent_blob = baize.storage.blob_write(
            "{\"intent_constraints\":{\"budget\":200}}", &parent_labels
        ).unwrap();

        // 尝试从过期父意图派生子意图
        let child_content = serde_json::json!({
            "parent_intent_digest": parent_blob.hash,
            "derivation_depth": 1,
            "intent_constraints": {"budget": 100},
            "expires_at": "2099-06-01T00:00:00Z",
        }).to_string();

        let mut child_labels = HashMap::new();
        child_labels.insert("type".to_string(), BLOB_TYPE_SUB_INTENT.to_string());
        child_labels.insert(LABEL_DERIVATION_DEPTH.to_string(), "1".to_string());

        let result = baize.pipe_blob_write("writer", &child_content, &child_labels);
        assert!(result.is_err(), "sub-intent from expired parent should be rejected");
        match result {
            Err(Error::IntentExpired(msg)) => assert!(msg.contains("parent")),
            other => panic!("expected IntentExpired, got {:?}", other),
        }
    }

    #[test]
    fn receipt_expired_authz_fails() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "writer", 2);

        // 用 storage 直接写 intent 和已过期的 authz
        let mut intent_labels = HashMap::new();
        intent_labels.insert("type".to_string(), BLOB_TYPE_INTENT.to_string());
        intent_labels.insert(LABEL_INTENT_EXPIRES.to_string(), "2099-12-31T23:59:59Z".to_string());
        let intent_blob = baize.storage.blob_write("{}", &intent_labels).unwrap();

        let authz_content = serde_json::json!({
            "exp": "2020-12-31T23:59:59Z",
            "constraints": {"budget": 100}
        }).to_string();
        let mut authz_labels = HashMap::new();
        authz_labels.insert("type".to_string(), BLOB_TYPE_AUTHORIZATION.to_string());
        authz_labels.insert(LABEL_AUTHZ_STATUS.to_string(), "valid".to_string());
        let authz_blob = baize.storage.blob_write(&authz_content, &authz_labels).unwrap();

        let receipt_content = serde_json::json!({
            "intent_digest": intent_blob.hash,
            "authorization_digest": authz_blob.hash,
            "result_status": "SUCCESS",
        }).to_string();

        let mut labels = HashMap::new();
        labels.insert("type".to_string(), BLOB_TYPE_RECEIPT.to_string());

        let result = baize.pipe_blob_write("writer", &receipt_content, &labels);
        assert!(result.is_err(), "receipt with expired authz should be rejected");
        match result {
            Err(Error::AuthorizationExpired(msg)) => assert!(msg.contains("2020-12-31")),
            other => panic!("expected AuthorizationExpired, got {:?}", other),
        }
    }

    #[test]
    fn intent_write_future_expires_ok() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "writer", 2);

        let content = serde_json::json!({
            "intent_id": "int-future",
            "intent_constraints": {"budget": 100},
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": "2099-12-31T23:59:59Z",
        }).to_string();

        let mut labels = HashMap::new();
        labels.insert("type".to_string(), BLOB_TYPE_INTENT.to_string());
        labels.insert(LABEL_INTENT_ID.to_string(), "int-future".to_string());
        labels.insert(LABEL_INTENT_STATUS.to_string(), "active".to_string());
        labels.insert(LABEL_INTENT_EXPIRES.to_string(), "2099-12-31T23:59:59Z".to_string());

        let result = baize.pipe_blob_write("writer", &content, &labels);
        assert!(result.is_ok(), "future intent should be accepted: {:?}", result);
    }

    #[test]
    fn receipt_corrupt_authz_fails() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "writer", 2);

        // 用 storage 直接写 intent
        let mut intent_labels = HashMap::new();
        intent_labels.insert("type".to_string(), BLOB_TYPE_INTENT.to_string());
        intent_labels.insert(LABEL_INTENT_EXPIRES.to_string(), "2099-12-31T23:59:59Z".to_string());
        let intent_blob = baize.storage.blob_write("{}", &intent_labels).unwrap();

        // 写一个 content 为非法 JSON 的 authz blob
        let mut authz_labels = HashMap::new();
        authz_labels.insert("type".to_string(), BLOB_TYPE_AUTHORIZATION.to_string());
        authz_labels.insert(LABEL_AUTHZ_STATUS.to_string(), "valid".to_string());
        let authz_blob = baize.storage.blob_write("not valid json!!!", &authz_labels).unwrap();

        let receipt_content = serde_json::json!({
            "intent_digest": intent_blob.hash,
            "authorization_digest": authz_blob.hash,
            "result_status": "SUCCESS",
        }).to_string();

        let mut labels = HashMap::new();
        labels.insert("type".to_string(), BLOB_TYPE_RECEIPT.to_string());

        let result = baize.pipe_blob_write("writer", &receipt_content, &labels);
        assert!(result.is_err(), "receipt with corrupt authz should be rejected");
        match result {
            Err(Error::ChainBroken(msg)) => assert!(msg.contains("invalid authorization content")),
            other => panic!("expected ChainBroken, got {:?}", other),
        }
    }

    // ─── P1: baize-asl 桥接测试 ───

    /// 辅助：构造 CNV 能通过的完整 receipt content（ASL payload 格式）
    fn make_valid_receipt_content(intent_hash: &str, authz_hash: &str) -> String {
        serde_json::json!({
            "receipt_id": "rct-cnv-001",
            "executor_id": "writer",
            "task_id": "task-001",
            "action_type": "execute",
            "intent_digest": intent_hash,
            "authorization_digest": authz_hash,
            "result_status": "SUCCEEDED",
            "started_at": "2026-01-01T00:00:00Z",
            "finished_at": "2026-01-01T00:01:00Z",
        }).to_string()
    }

    /// 辅助：构造 AZN-VER 能通过的 authorization content（ASL payload 格式）
    fn make_valid_authz_content(intent_hash: &str) -> String {
        serde_json::json!({
            "authorization_id": "authz-001",
            "issuer": "baize-root",
            "subject": "writer",
            "grant_type": "execute",
            "constraints": {"target_scope": ["zone-A"]},
            "delegatable": false,
            "source_intent_digest": intent_hash,
            "root_authorizer": "baize-root",
            "nbf": "2026-01-01T00:00:00Z",
            "exp": "2099-12-31T23:59:59Z",
            "iat": "2026-01-01T00:00:00Z",
            "jti": "jti-001",
            "version": "1.0",
        }).to_string()
    }

    #[test]
    fn receipt_write_triggers_cnv_ok() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "writer", 2);

        // 1. 写 intent（带完整 ASL labels）
        let intent_content = serde_json::json!({
            "intent_id": "int-cnv",
            "intent_owner": "writer",
            "intent_creator": "writer",
            "intent_goal": "deploy",
            "intent_constraints": {"budget": 100},
            "version": "1.0",
            "created_at": "2026-01-01T00:00:00Z",
            "expires_at": "2099-12-31T23:59:59Z",
        }).to_string();
        let mut intent_labels = HashMap::new();
        intent_labels.insert("type".to_string(), BLOB_TYPE_INTENT.to_string());
        intent_labels.insert(LABEL_INTENT_ID.to_string(), "int-cnv".to_string());
        intent_labels.insert(LABEL_INTENT_STATUS.to_string(), "active".to_string());
        intent_labels.insert(LABEL_INTENT_EXPIRES.to_string(), "2099-12-31T23:59:59Z".to_string());
        let intent_blob = baize.pipe_blob_write("writer", &intent_content, &intent_labels).unwrap();

        // 2. 写 authorization（带完整 ASL labels）
        let authz_content = make_valid_authz_content(&intent_blob.hash);
        let mut authz_labels = HashMap::new();
        authz_labels.insert("type".to_string(), BLOB_TYPE_AUTHORIZATION.to_string());
        authz_labels.insert(LABEL_AUTHZ_STATUS.to_string(), "valid".to_string());
        authz_labels.insert(LABEL_SOURCE_INTENT.to_string(), intent_blob.hash.clone());
        let authz_blob = baize.storage.blob_write(&authz_content, &authz_labels).unwrap();

        // 3. 写 receipt → 触发 CNV 自动校验
        let receipt_content = make_valid_receipt_content(&intent_blob.hash, &authz_blob.hash);
        let mut receipt_labels = HashMap::new();
        receipt_labels.insert("type".to_string(), BLOB_TYPE_RECEIPT.to_string());
        receipt_labels.insert(LABEL_RECEIPT_INTENT.to_string(), intent_blob.hash.clone());
        receipt_labels.insert(LABEL_RECEIPT_AUTHZ.to_string(), authz_blob.hash.clone());

        let result = baize.pipe_blob_write("writer", &receipt_content, &receipt_labels);
        assert!(result.is_ok(), "receipt with valid CNV chain should succeed: {:?}", result);
    }

    #[test]
    fn receipt_write_cnv_source_intent_mismatch_fails() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "writer", 2);

        // 写一个 intent
        let mut intent_labels = HashMap::new();
        intent_labels.insert("type".to_string(), BLOB_TYPE_INTENT.to_string());
        intent_labels.insert(LABEL_INTENT_ID.to_string(), "int-mismatch".to_string());
        intent_labels.insert(LABEL_INTENT_STATUS.to_string(), "active".to_string());
        intent_labels.insert(LABEL_INTENT_EXPIRES.to_string(), "2099-12-31T23:59:59Z".to_string());
        let intent_blob = baize.storage.blob_write(
            &serde_json::json!({
                "intent_id": "int-mismatch",
                "intent_constraints": {"budget": 100},
                "created_at": "2026-01-01T00:00:00Z",
                "expires_at": "2099-12-31T23:59:59Z",
            }).to_string(),
            &intent_labels,
        ).unwrap();

        // 写另一个无关的 intent（用作 authz 的错误 source）
        let mut other_intent_labels = HashMap::new();
        other_intent_labels.insert("type".to_string(), BLOB_TYPE_INTENT.to_string());
        other_intent_labels.insert(LABEL_INTENT_ID.to_string(), "int-other".to_string());
        other_intent_labels.insert(LABEL_INTENT_STATUS.to_string(), "active".to_string());
        other_intent_labels.insert(LABEL_INTENT_EXPIRES.to_string(), "2099-12-31T23:59:59Z".to_string());
        let other_intent_blob = baize.storage.blob_write(
            &serde_json::json!({"intent_id": "int-other", "intent_constraints": {"budget": 50}}).to_string(),
            &other_intent_labels,
        ).unwrap();

        // 写 authorization，source 指向另一个 intent（不匹配 receipt 的 intent）
        let authz_content = make_valid_authz_content(&other_intent_blob.hash);
        let mut authz_labels = HashMap::new();
        authz_labels.insert("type".to_string(), BLOB_TYPE_AUTHORIZATION.to_string());
        authz_labels.insert(LABEL_AUTHZ_STATUS.to_string(), "valid".to_string());
        authz_labels.insert(LABEL_SOURCE_INTENT.to_string(), other_intent_blob.hash.clone());
        let authz_blob = baize.storage.blob_write(&authz_content, &authz_labels).unwrap();

        // 写 receipt → CNV 校验发现 source_intent_digest 不在 intent chain 中
        let receipt_content = make_valid_receipt_content(&intent_blob.hash, &authz_blob.hash);
        let mut receipt_labels = HashMap::new();
        receipt_labels.insert("type".to_string(), BLOB_TYPE_RECEIPT.to_string());
        receipt_labels.insert(LABEL_RECEIPT_INTENT.to_string(), intent_blob.hash.clone());
        receipt_labels.insert(LABEL_RECEIPT_AUTHZ.to_string(), authz_blob.hash.clone());

        let result = baize.pipe_blob_write("writer", &receipt_content, &receipt_labels);
        assert!(result.is_err(), "receipt with CNV source_intent mismatch should fail");
        match result {
            Err(Error::ConstraintViolation(msg)) => assert!(msg.contains("source_intent_digest"), "expected CNV error, got: {}", msg),
            other => panic!("expected ConstraintViolation, got {:?}", other),
        }
    }

    #[test]
    fn authz_write_triggers_azn_ver_ok() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "writer", 2);

        // 写 intent
        let mut intent_labels = HashMap::new();
        intent_labels.insert("type".to_string(), BLOB_TYPE_INTENT.to_string());
        intent_labels.insert(LABEL_INTENT_ID.to_string(), "int-azn".to_string());
        intent_labels.insert(LABEL_INTENT_STATUS.to_string(), "active".to_string());
        intent_labels.insert(LABEL_INTENT_EXPIRES.to_string(), "2099-12-31T23:59:59Z".to_string());
        let intent_blob = baize.storage.blob_write(
            &serde_json::json!({
                "intent_id": "int-azn",
                "intent_constraints": {"budget": 100},
                "created_at": "2026-01-01T00:00:00Z",
                "expires_at": "2099-12-31T23:59:59Z",
            }).to_string(),
            &intent_labels,
        ).unwrap();

        // 写 authorization → 触发 AZN-VER 自动校验
        let authz_content = make_valid_authz_content(&intent_blob.hash);
        let mut authz_labels = HashMap::new();
        authz_labels.insert("type".to_string(), BLOB_TYPE_AUTHORIZATION.to_string());
        authz_labels.insert(LABEL_AUTHZ_STATUS.to_string(), "valid".to_string());
        authz_labels.insert(LABEL_SOURCE_INTENT.to_string(), intent_blob.hash.clone());

        let result = baize.pipe_blob_write("writer", &authz_content, &authz_labels);
        assert!(result.is_ok(), "authz with valid AZN-VER should succeed: {:?}", result);
    }

    #[test]
    fn authz_write_azn_ver_expired_fails() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "writer", 2);

        // 写 intent
        let mut intent_labels = HashMap::new();
        intent_labels.insert("type".to_string(), BLOB_TYPE_INTENT.to_string());
        intent_labels.insert(LABEL_INTENT_ID.to_string(), "int-exp-azn".to_string());
        intent_labels.insert(LABEL_INTENT_STATUS.to_string(), "active".to_string());
        intent_labels.insert(LABEL_INTENT_EXPIRES.to_string(), "2099-12-31T23:59:59Z".to_string());
        let intent_blob = baize.storage.blob_write(
            &serde_json::json!({
                "intent_id": "int-exp-azn",
                "intent_constraints": {"budget": 100},
            }).to_string(),
            &intent_labels,
        ).unwrap();

        // 写已过期的 authorization → AZN-VER 校验二失败
        let expired_authz_content = serde_json::json!({
            "authorization_id": "authz-exp",
            "issuer": "baize-root",
            "subject": "writer",
            "grant_type": "execute",
            "constraints": {"target_scope": ["zone-A"]},
            "delegatable": false,
            "source_intent_digest": intent_blob.hash,
            "root_authorizer": "baize-root",
            "nbf": "2020-01-01T00:00:00Z",
            "exp": "2020-12-31T23:59:59Z",
            "iat": "2020-01-01T00:00:00Z",
            "jti": "jti-exp",
            "version": "1.0",
        }).to_string();
        let mut authz_labels = HashMap::new();
        authz_labels.insert("type".to_string(), BLOB_TYPE_AUTHORIZATION.to_string());
        authz_labels.insert(LABEL_AUTHZ_STATUS.to_string(), "valid".to_string());
        authz_labels.insert(LABEL_SOURCE_INTENT.to_string(), intent_blob.hash.clone());

        let result = baize.pipe_blob_write("writer", &expired_authz_content, &authz_labels);
        assert!(result.is_err(), "expired authz should fail AZN-VER");
        match result {
            Err(Error::ConstraintViolation(msg)) => assert!(msg.contains("expired") || msg.contains("AZN-VER"), "expected AZN-VER expiry error, got: {}", msg),
            other => panic!("expected ConstraintViolation, got {:?}", other),
        }
    }

    // ─── Phase 3: session 校验增强测试 ───

    #[test]
    fn session_init_requires_ephemeral_pub() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "alice", 2);
        register_agent(&mut baize, "bob", 2);

        let mut labels = HashMap::new();
        labels.insert("type".to_string(), BLOB_TYPE_SESSION_INIT.to_string());
        labels.insert(LABEL_SESSION_ID.to_string(), "sess-no-eph".to_string());
        labels.insert(LABEL_SESSION_PEER_A.to_string(), "alice".to_string());
        labels.insert(LABEL_SESSION_PEER_B.to_string(), "bob".to_string());

        // 缺少 ephemeral_pub
        let result = baize.pipe_blob_write("alice", r#"{"cipher_suites":["AES-256-GCM"]}"#, &labels);
        assert!(result.is_err());
        match result {
            Err(Error::Validation(msg)) => assert!(msg.contains("ephemeral_pub"), "got: {}", msg),
            other => panic!("expected Validation, got {:?}", other),
        }
    }

    #[test]
    fn session_init_requires_aes_256_gcm_cipher_suite() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "alice", 2);
        register_agent(&mut baize, "bob", 2);

        let mut labels = HashMap::new();
        labels.insert("type".to_string(), BLOB_TYPE_SESSION_INIT.to_string());
        labels.insert(LABEL_SESSION_ID.to_string(), "sess-no-cipher".to_string());
        labels.insert(LABEL_SESSION_PEER_A.to_string(), "alice".to_string());
        labels.insert(LABEL_SESSION_PEER_B.to_string(), "bob".to_string());

        // cipher_suites 不包含 AES-256-GCM（ephemeral_pub 需要合法格式）
        let pub_a = gen_ephemeral_pub();
        let result = baize.pipe_blob_write("alice", &format!(r#"{{"ephemeral_pub":"{}","cipher_suites":["ChaCha20-Poly1305"]}}"#, pub_a), &labels);
        assert!(result.is_err());
        match result {
            Err(Error::Validation(msg)) => assert!(msg.contains("AES-256-GCM"), "got: {}", msg),
            other => panic!("expected Validation, got {:?}", other),
        }
    }

    #[test]
    fn session_accept_requires_ephemeral_pub() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "alice", 2);
        register_agent(&mut baize, "bob", 2);

        // init
        let mut init_labels = HashMap::new();
        init_labels.insert("type".to_string(), BLOB_TYPE_SESSION_INIT.to_string());
        init_labels.insert(LABEL_SESSION_ID.to_string(), "sess-accept-no-eph".to_string());
        init_labels.insert(LABEL_SESSION_PEER_A.to_string(), "alice".to_string());
        init_labels.insert(LABEL_SESSION_PEER_B.to_string(), "bob".to_string());
        let pub_a = gen_ephemeral_pub();
        let init_blob = baize.pipe_blob_write("alice", &format!(r#"{{"ephemeral_pub":"{}","cipher_suites":["AES-256-GCM"]}}"#, pub_a), &init_labels).unwrap();

        let mut accept_labels = HashMap::new();
        accept_labels.insert("type".to_string(), BLOB_TYPE_SESSION_ACCEPT.to_string());
        accept_labels.insert(LABEL_SESSION_ID.to_string(), "sess-accept-no-eph".to_string());
        accept_labels.insert("parent".to_string(), init_blob.hash);

        // 缺少 ephemeral_pub
        let result = baize.pipe_blob_write("bob", r#"{"selected_cipher_suite":"AES-256-GCM"}"#, &accept_labels);
        assert!(result.is_err());
        match result {
            Err(Error::Validation(msg)) => assert!(msg.contains("ephemeral_pub"), "got: {}", msg),
            other => panic!("expected Validation, got {:?}", other),
        }
    }

    #[test]
    fn session_accept_cipher_suite_mismatch_fails() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "alice", 2);
        register_agent(&mut baize, "bob", 2);

        // init
        let mut init_labels = HashMap::new();
        init_labels.insert("type".to_string(), BLOB_TYPE_SESSION_INIT.to_string());
        init_labels.insert(LABEL_SESSION_ID.to_string(), "sess-cipher-mismatch".to_string());
        init_labels.insert(LABEL_SESSION_PEER_A.to_string(), "alice".to_string());
        init_labels.insert(LABEL_SESSION_PEER_B.to_string(), "bob".to_string());
        let pub_a = gen_ephemeral_pub();
        let init_blob = baize.pipe_blob_write("alice", &format!(r#"{{"ephemeral_pub":"{}","cipher_suites":["AES-256-GCM"]}}"#, pub_a), &init_labels).unwrap();

        let mut accept_labels = HashMap::new();
        accept_labels.insert("type".to_string(), BLOB_TYPE_SESSION_ACCEPT.to_string());
        accept_labels.insert(LABEL_SESSION_ID.to_string(), "sess-cipher-mismatch".to_string());
        accept_labels.insert("parent".to_string(), init_blob.hash);

        // selected_cipher_suite 不在 init 的 cipher_suites 中（ephemeral_pub 需合法）
        let pub_b = gen_ephemeral_pub();
        let result = baize.pipe_blob_write("bob", &format!(r#"{{"ephemeral_pub":"{}","selected_cipher_suite":"ChaCha20-Poly1305"}}"#, pub_b), &accept_labels);
        assert!(result.is_err());
        match result {
            Err(Error::Validation(msg)) => assert!(msg.contains("selected_cipher_suite"), "got: {}", msg),
            other => panic!("expected Validation, got {:?}", other),
        }
    }

    #[test]
    fn session_message_after_close_rejected() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "alice", 2);
        register_agent(&mut baize, "bob", 2);

        // init
        let mut init_labels = HashMap::new();
        init_labels.insert("type".to_string(), BLOB_TYPE_SESSION_INIT.to_string());
        init_labels.insert(LABEL_SESSION_ID.to_string(), "sess-close-msg".to_string());
        init_labels.insert(LABEL_SESSION_PEER_A.to_string(), "alice".to_string());
        init_labels.insert(LABEL_SESSION_PEER_B.to_string(), "bob".to_string());
        let pub_a = gen_ephemeral_pub();
        let init_blob = baize.pipe_blob_write("alice", &format!(r#"{{"ephemeral_pub":"{}","cipher_suites":["AES-256-GCM"]}}"#, pub_a), &init_labels).unwrap();

        // accept
        let mut accept_labels = HashMap::new();
        accept_labels.insert("type".to_string(), BLOB_TYPE_SESSION_ACCEPT.to_string());
        accept_labels.insert(LABEL_SESSION_ID.to_string(), "sess-close-msg".to_string());
        accept_labels.insert("parent".to_string(), init_blob.hash);
        let pub_b = gen_ephemeral_pub();
        baize.pipe_blob_write("bob", &format!(r#"{{"ephemeral_pub":"{}","selected_cipher_suite":"AES-256-GCM"}}"#, pub_b), &accept_labels).unwrap();

        // close session（直接写 session-close blob）
        let close_content = serde_json::json!({
            "session_id": "sess-close-msg",
            "action": "close",
            "closed_by": "alice",
        }).to_string();
        let mut close_labels = HashMap::new();
        close_labels.insert("type".to_string(), "session-close".to_string());
        close_labels.insert(LABEL_SESSION_ID.to_string(), "sess-close-msg".to_string());
        close_labels.insert(LABEL_SESSION_STATUS.to_string(), "closed".to_string());
        baize.storage.blob_write(&close_content, &close_labels).unwrap();

        // 尝试在关闭后发 message → 应被拒绝
        let mut msg_labels = HashMap::new();
        msg_labels.insert("type".to_string(), "session-message".to_string());
        msg_labels.insert(LABEL_SESSION_ID.to_string(), "sess-close-msg".to_string());
        msg_labels.insert(LABEL_MESSAGE_SEQ.to_string(), "1".to_string());

        let result = baize.pipe_blob_write("alice", r#"{"msg":"after close"}"#, &msg_labels);
        assert!(result.is_err(), "message after session close should be rejected");
        match result {
            Err(Error::Validation(msg)) => assert!(msg.contains("closed"), "got: {}", msg),
            other => panic!("expected Validation, got {:?}", other),
        }
    }

    #[test]
    fn session_message_expired_session_rejected() {
        let mut baize = setup_baize();
        register_agent(&mut baize, "alice", 2);
        register_agent(&mut baize, "bob", 2);

        // init with past expires_at（直接写入 storage 绕过管道创建已过期的 session）
        let mut init_labels = HashMap::new();
        init_labels.insert("type".to_string(), BLOB_TYPE_SESSION_INIT.to_string());
        init_labels.insert(LABEL_SESSION_ID.to_string(), "sess-expired".to_string());
        init_labels.insert(LABEL_SESSION_PEER_A.to_string(), "alice".to_string());
        init_labels.insert(LABEL_SESSION_PEER_B.to_string(), "bob".to_string());
        let pub_a = gen_ephemeral_pub();
        let past = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
        let init_content = format!(
            r#"{{"ephemeral_pub":"{}","cipher_suites":["AES-256-GCM"],"expires_at":"{}"}}"#,
            pub_a, past
        );
        baize.storage.blob_write(&init_content, &init_labels).unwrap();

        // accept（直接写入 storage）
        let mut accept_labels = HashMap::new();
        accept_labels.insert("type".to_string(), BLOB_TYPE_SESSION_ACCEPT.to_string());
        accept_labels.insert(LABEL_SESSION_ID.to_string(), "sess-expired".to_string());
        let pub_b = gen_ephemeral_pub();
        baize.storage.blob_write(
            &format!(r#"{{"ephemeral_pub":"{}","selected_cipher_suite":"AES-256-GCM"}}"#, pub_b),
            &accept_labels,
        ).unwrap();

        // 尝试在过期 session 发 message → 应被拒绝
        let mut msg_labels = HashMap::new();
        msg_labels.insert("type".to_string(), "session-message".to_string());
        msg_labels.insert(LABEL_SESSION_ID.to_string(), "sess-expired".to_string());
        msg_labels.insert(LABEL_MESSAGE_SEQ.to_string(), "1".to_string());

        let result = baize.pipe_blob_write("alice", r#"{"msg":"after expire"}"#, &msg_labels);
        assert!(result.is_err(), "message to expired session should be rejected");
        match result {
            Err(Error::Validation(msg)) => assert!(msg.contains("expired"), "got: {}", msg),
            other => panic!("expected Validation, got {:?}", other),
        }
    }

    // ─── Phase 2: 自定义 handler 集成测试 ───

    #[test]
    fn custom_handler_validates_and_writes_via_pipe_blob_write() {
        use crate::pipeline::protocol::{BlobTypeHandler, ValidationContext};

        struct NoteHandler;
        impl BlobTypeHandler for NoteHandler {
            fn blob_type(&self) -> &str { "note" }
            fn validate(
                &self,
                _ctx: &ValidationContext,
                content: &str,
                _labels: &HashMap<String, String>,
            ) -> Result<(), Error> {
                let _: serde_json::Value = serde_json::from_str(content)
                    .map_err(|e| Error::Validation(format!("note must be valid JSON: {}", e)))?;
                Ok(())
            }
        }

        let mut baize = setup_baize();
        baize.register_handler(Box::new(NoteHandler));
        register_agent(&mut baize, "alice", 2);

        // 有效 JSON 应通过自定义 handler 校验并写入
        let mut labels = HashMap::new();
        labels.insert("type".to_string(), "note".to_string());
        let blob = baize.pipe_blob_write("alice", r#"{"text":"hello"}"#, &labels).unwrap();
        assert_eq!(blob.labels.get("type").unwrap(), "note");
        assert_eq!(blob.labels.get("agent").unwrap(), "alice");

        // 无效 JSON 应被自定义 handler 拒绝
        let result = baize.pipe_blob_write("alice", "not json", &labels);
        assert!(result.is_err());
        match result {
            Err(Error::Validation(msg)) => assert!(msg.contains("note must be valid JSON"), "got: {}", msg),
            other => panic!("expected Validation, got {:?}", other),
        }
    }

    #[test]
    fn override_default_handler_with_custom() {
        use crate::pipeline::protocol::{BlobTypeHandler, ValidationContext};

        // 自定义 intent handler：总是通过（跳过所有校验）
        struct FastIntentHandler;
        impl BlobTypeHandler for FastIntentHandler {
            fn blob_type(&self) -> &str { "intent" }
            fn validate(
                &self,
                _ctx: &ValidationContext,
                _content: &str,
                _labels: &HashMap<String, String>,
            ) -> Result<(), Error> {
                Ok(())
            }
        }

        let mut baize = setup_baize();
        baize.register_handler(Box::new(FastIntentHandler));
        register_agent(&mut baize, "alice", 2);

        // 空 content 应被默认 IntentHandler 拒绝，但自定义 handler 放行
        let mut labels = HashMap::new();
        labels.insert("type".to_string(), "intent".to_string());
        let result = baize.pipe_blob_write("alice", "", &labels);
        assert!(result.is_ok(), "custom handler should override default validation");
    }
}
