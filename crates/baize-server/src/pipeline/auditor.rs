use std::collections::HashMap;

use baize_core::error::Error;

use super::Baize;

/// 审计接口：所有写操作通过此接口留痕
pub trait Auditor {
    /// 写入审计记录
    /// target: 操作对象标识（如 blob hash、agent id、file path），可为空
    fn audit(&self, audit_type: &str, agent_id: &str, result: &str, target: Option<&str>) -> Result<(), Error>;
}

impl Auditor for Baize {
    fn audit(&self, audit_type: &str, agent_id: &str, result: &str, target: Option<&str>) -> Result<(), Error> {
        let seq = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        let mut labels = HashMap::from([
            ("type".to_string(), "audit".to_string()),
            ("x-audit".to_string(), "true".to_string()),
            ("x-audit-type".to_string(), audit_type.to_string()),
            ("x-audit-agent".to_string(), agent_id.to_string()),
            ("x-audit-result".to_string(), result.to_string()),
            ("x-audit-time".to_string(), chrono::Utc::now().to_rfc3339()),
            ("x-audit-seq".to_string(), seq.to_string()),
        ]);
        if let Some(t) = target {
            labels.insert("x-audit-target".to_string(), t.to_string());
        }

        let mut content = serde_json::json!({
            "type": audit_type,
            "agent": agent_id,
            "result": result,
            "seq": seq,
        });
        if let Some(t) = target {
            content["target"] = serde_json::Value::String(t.to_string());
        }

        self.storage.blob_write(&content.to_string(), &labels)?;
        Ok(())
    }
}
