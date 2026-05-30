//! 协议处理器注册表 — 可扩展的 blob type 校验与副作用管理
//!
//! V3 Phase 2：将 pipe_blob_write 中的硬编码 match 分支替换为可注册的 Handler 注册表，
//! 允许二次开发者添加新的协议域（如 task、payment）。

use std::collections::HashMap;

use baize_core::error::Error;
use baize_core::identity::IdentityProvider;
use baize_core::labels::*;
use baize_core::storage::{Blob, BlobStore};

use super::data_ops::authz_ops::validate_authorization_blob;
use super::data_ops::intent_ops::{
    validate_intent_blob, validate_receipt_blob, validate_sub_intent_blob,
};
use super::data_ops::session_ops::{
    validate_session_accept_blob, validate_session_init_blob, validate_session_message_blob,
};

// ─── 校验上下文 ───

/// 校验上下文 — handler 校验时可能需要的管道状态
pub struct ValidationContext<'a> {
    pub storage: &'a dyn BlobStore,
    pub identity: &'a dyn IdentityProvider,
    pub agent_id: &'a str,
}

// ─── BlobTypeHandler trait ───

/// 协议处理器 — 每个 blob type 对应一个 handler
///
/// 二次开发者实现此 trait 并注册到 `ProtocolRegistry`，即可扩展新的协议域。
/// 写入前走 `validate`，写入后走 `post_write`（含副作用）。
pub trait BlobTypeHandler: Send + Sync {
    /// 处理的 blob type 名称（如 "intent"、"authorization"）
    fn blob_type(&self) -> &str;

    /// 写入前校验，返回 Err 则拒绝写入
    fn validate(
        &self,
        ctx: &ValidationContext,
        content: &str,
        labels: &HashMap<String, String>,
    ) -> Result<(), Error>;

    /// 写入后副作用（如触发 CNV、AZN-VER），失败则回滚删除 blob
    /// 返回 Err 时调用方负责 blob_delete
    fn post_write(&self, _storage: &dyn BlobStore, _blob: &Blob) -> Result<(), Error> {
        Ok(())
    }

    /// Level 3+ 是否对此类型强制 proof
    fn requires_proof(&self) -> bool {
        false
    }
}

// ─── ProtocolRegistry ───

/// 协议处理器注册表
pub struct ProtocolRegistry {
    handlers: HashMap<String, Box<dyn BlobTypeHandler>>,
    /// 不走 handler 但视为 ASL 类型的系统 type（agent-cert/key/root-ca 等）
    system_types: Vec<String>,
}

impl ProtocolRegistry {
    /// 创建空注册表
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
            system_types: Vec::new(),
        }
    }

    /// 注册 handler（覆盖同名）
    pub fn register(&mut self, handler: Box<dyn BlobTypeHandler>) {
        self.handlers
            .insert(handler.blob_type().to_string(), handler);
    }

    /// 查找 handler
    pub fn get(&self, blob_type: &str) -> Option<&dyn BlobTypeHandler> {
        self.handlers.get(blob_type).map(|h| h.as_ref())
    }

    /// 是否为已知类型（handler 或 system_type）
    pub fn is_known_type(&self, blob_type: &str) -> bool {
        self.handlers.contains_key(blob_type)
            || self.system_types.iter().any(|t| t == blob_type)
    }

    /// 所有已注册的 handler type 名称
    pub fn registered_types(&self) -> Vec<&str> {
        self.handlers.values().map(|h| h.blob_type()).collect()
    }
}

impl std::fmt::Debug for ProtocolRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProtocolRegistry")
            .field("handlers", &self.registered_types())
            .field("system_types", &self.system_types)
            .finish()
    }
}

impl Default for ProtocolRegistry {
    fn default() -> Self {
        let mut registry = Self::new();

        // 注册 7 个 ASL handler
        registry.register(Box::new(IntentHandler));
        registry.register(Box::new(SubIntentHandler));
        registry.register(Box::new(ReceiptHandler));
        registry.register(Box::new(AuthorizationHandler));
        registry.register(Box::new(SessionInitHandler));
        registry.register(Box::new(SessionAcceptHandler));
        registry.register(Box::new(SessionMessageHandler));

        // 系统类型（不走 handler，但视为已知 ASL 类型，用于 session 消息分流）
        registry.system_types = vec![
            BLOB_TYPE_AGENT_CERT.to_string(),
            BLOB_TYPE_AGENT_KEY.to_string(),
            BLOB_TYPE_ROOT_CA.to_string(),
            "session-close".to_string(),
            "runtime-proof".to_string(),
        ];

        registry
    }
}

// ─── 6 个默认 Handler ───

/// INT-GIR：通用意图
struct IntentHandler;

impl BlobTypeHandler for IntentHandler {
    fn blob_type(&self) -> &str {
        BLOB_TYPE_INTENT
    }

    fn validate(
        &self,
        ctx: &ValidationContext,
        content: &str,
        labels: &HashMap<String, String>,
    ) -> Result<(), Error> {
        validate_intent_blob(ctx.storage, content, labels)
    }
}

/// INT-DER：子意图派生
struct SubIntentHandler;

impl BlobTypeHandler for SubIntentHandler {
    fn blob_type(&self) -> &str {
        BLOB_TYPE_SUB_INTENT
    }

    fn validate(
        &self,
        ctx: &ValidationContext,
        content: &str,
        labels: &HashMap<String, String>,
    ) -> Result<(), Error> {
        validate_sub_intent_blob(ctx.storage, content, labels)
    }
}

/// INT-RCT：执行回执
struct ReceiptHandler;

impl BlobTypeHandler for ReceiptHandler {
    fn blob_type(&self) -> &str {
        BLOB_TYPE_RECEIPT
    }

    fn validate(
        &self,
        ctx: &ValidationContext,
        content: &str,
        labels: &HashMap<String, String>,
    ) -> Result<(), Error> {
        validate_receipt_blob(ctx.storage, content, labels)
    }

    /// 写入后自动 CNV 全链路校验（失败由调用方回滚删除 blob）
    fn post_write(&self, storage: &dyn BlobStore, blob: &Blob) -> Result<(), Error> {
        let cnv_result = baize_asl::verify::cnv_verify(storage, &blob.hash);
        match cnv_result {
            Ok(result) if !result.valid => {
                return Err(Error::ConstraintViolation(format!(
                    "CNV verification failed: {}",
                    result.errors.join("; ")
                )));
            }
            Err(e) => {
                return Err(e);
            }
            _ => {}
        }
        Ok(())
    }

    fn requires_proof(&self) -> bool {
        true
    }
}

/// AZN-APR/AZN-ISS：授权签发
struct AuthorizationHandler;

impl BlobTypeHandler for AuthorizationHandler {
    fn blob_type(&self) -> &str {
        BLOB_TYPE_AUTHORIZATION
    }

    fn validate(
        &self,
        ctx: &ValidationContext,
        content: &str,
        labels: &HashMap<String, String>,
    ) -> Result<(), Error> {
        validate_authorization_blob(ctx.storage, content, labels)
    }

    /// 写入后自动 AZN-VER 校验（失败由调用方回滚删除 blob）
    fn post_write(&self, storage: &dyn BlobStore, blob: &Blob) -> Result<(), Error> {
        let action_type = serde_json::from_str::<serde_json::Value>(&blob.content)
            .ok()
            .and_then(|v| {
                v.get("grant_type")
                    .and_then(|g| g.as_str())
                    .map(String::from)
            })
            .unwrap_or_else(|| "execute".to_string());

        let authz_result = baize_asl::verify::verify_authorization(
            storage,
            &blob.hash,
            &action_type,
            &baize_asl::verify::ExecutionContext::default(),
        );
        match authz_result {
            Ok(result) if !result.valid => {
                return Err(Error::ConstraintViolation(format!(
                    "AZN-VER failed: {}",
                    result.errors.join("; ")
                )));
            }
            Err(e) => {
                return Err(e);
            }
            _ => {}
        }
        Ok(())
    }

    fn requires_proof(&self) -> bool {
        true
    }
}

/// LNK-SES：会话建立
struct SessionInitHandler;

impl BlobTypeHandler for SessionInitHandler {
    fn blob_type(&self) -> &str {
        BLOB_TYPE_SESSION_INIT
    }

    fn validate(
        &self,
        ctx: &ValidationContext,
        content: &str,
        labels: &HashMap<String, String>,
    ) -> Result<(), Error> {
        validate_session_init_blob(ctx.storage, ctx.identity, content, labels)
    }

    fn requires_proof(&self) -> bool {
        true
    }
}

/// LNK-SES：会话接受
struct SessionAcceptHandler;

impl BlobTypeHandler for SessionAcceptHandler {
    fn blob_type(&self) -> &str {
        BLOB_TYPE_SESSION_ACCEPT
    }

    fn validate(
        &self,
        ctx: &ValidationContext,
        content: &str,
        labels: &HashMap<String, String>,
    ) -> Result<(), Error> {
        validate_session_accept_blob(ctx.storage, content, labels, ctx.agent_id)
    }

    fn requires_proof(&self) -> bool {
        true
    }
}

/// LNK-DTX：session 内加密消息
struct SessionMessageHandler;

impl BlobTypeHandler for SessionMessageHandler {
    fn blob_type(&self) -> &str {
        BLOB_TYPE_SESSION_MESSAGE
    }

    fn validate(
        &self,
        ctx: &ValidationContext,
        _content: &str,
        labels: &HashMap<String, String>,
    ) -> Result<(), Error> {
        validate_session_message_blob(ctx.storage, labels, ctx.agent_id)
    }

    fn requires_proof(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_default_has_all_asl_handlers() {
        let registry = ProtocolRegistry::default();
        assert!(registry.get(BLOB_TYPE_INTENT).is_some());
        assert!(registry.get(BLOB_TYPE_SUB_INTENT).is_some());
        assert!(registry.get(BLOB_TYPE_RECEIPT).is_some());
        assert!(registry.get(BLOB_TYPE_AUTHORIZATION).is_some());
        assert!(registry.get(BLOB_TYPE_SESSION_INIT).is_some());
        assert!(registry.get(BLOB_TYPE_SESSION_ACCEPT).is_some());
        assert!(registry.get(BLOB_TYPE_SESSION_MESSAGE).is_some());
        assert_eq!(registry.registered_types().len(), 7);
    }

    #[test]
    fn registry_system_types_recognized() {
        let registry = ProtocolRegistry::default();
        assert!(registry.is_known_type(BLOB_TYPE_AGENT_CERT));
        assert!(registry.is_known_type(BLOB_TYPE_AGENT_KEY));
        assert!(registry.is_known_type(BLOB_TYPE_ROOT_CA));
        assert!(registry.is_known_type("session-close"));
        assert!(registry.is_known_type("runtime-proof"));
        assert!(!registry.is_known_type("unknown-type"));
    }

    #[test]
    fn custom_handler_registration() {
        struct TaskHandler;
        impl BlobTypeHandler for TaskHandler {
            fn blob_type(&self) -> &str {
                "task"
            }
            fn validate(
                &self,
                _ctx: &ValidationContext,
                content: &str,
                _labels: &HashMap<String, String>,
            ) -> Result<(), Error> {
                let _: serde_json::Value = serde_json::from_str(content)
                    .map_err(|e| Error::Validation(format!("invalid JSON: {}", e)))?;
                Ok(())
            }
        }

        let mut registry = ProtocolRegistry::default();
        registry.register(Box::new(TaskHandler));
        assert!(registry.get("task").is_some());
        assert_eq!(registry.get("task").unwrap().blob_type(), "task");
    }

    #[test]
    fn handler_override_replaces_default() {
        struct FastIntentHandler;
        impl BlobTypeHandler for FastIntentHandler {
            fn blob_type(&self) -> &str {
                BLOB_TYPE_INTENT
            }
            fn validate(
                &self,
                _ctx: &ValidationContext,
                _content: &str,
                _labels: &HashMap<String, String>,
            ) -> Result<(), Error> {
                Ok(()) // 总是通过
            }
        }

        let mut registry = ProtocolRegistry::default();
        registry.register(Box::new(FastIntentHandler));
        // 覆盖后应返回新 handler
        assert!(registry.get(BLOB_TYPE_INTENT).is_some());
    }
}
