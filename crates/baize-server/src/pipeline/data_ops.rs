use std::collections::HashMap;

use baize_core::error::Error;

use super::Baize;
use super::auditor::Auditor;
use super::agent_manager::PermissionGuard;

/// 数据操作接口：blob 写入、label 追加、导入、导出
pub trait DataOps {
    /// 管道：blob 写入
    fn pipe_blob_write(
        &self,
        agent_id: &str,
        content: &str,
        labels: &HashMap<String, String>,
    ) -> Result<baize_core::storage::Blob, Error>;

    /// 管道：label 追加
    fn pipe_label_add(
        &self,
        agent_id: &str,
        entity_hash: &str,
        key: &str,
        value: &str,
    ) -> Result<(), Error>;

    /// 管道：数据导入
    fn pipe_import(
        &self,
        agent_id: &str,
        content: &str,
        source: &str,
        trust_level: u8,
        extra_labels: Option<HashMap<String, String>>,
    ) -> Result<baize_core::storage::Blob, Error>;

    /// 管道：数据导出
    fn pipe_export(
        &self,
        agent_id: &str,
        hash: &str,
    ) -> Result<baize_core::storage::Blob, Error>;
}

impl DataOps for Baize {
    fn pipe_blob_write(
        &self,
        agent_id: &str,
        content: &str,
        labels: &HashMap<String, String>,
    ) -> Result<baize_core::storage::Blob, Error> {
        self.verify_write_agent(agent_id)?;
        let blob = self.storage.blob_write(content, labels)?;
        self.audit("blob_write", agent_id, "success", Some(&blob.hash))?;
        Ok(blob)
    }

    fn pipe_label_add(
        &self,
        agent_id: &str,
        entity_hash: &str,
        key: &str,
        value: &str,
    ) -> Result<(), Error> {
        self.verify_write_agent(agent_id)?;
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
        self.verify_write_agent(agent_id)?;

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
