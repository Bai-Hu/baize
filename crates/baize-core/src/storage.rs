use std::collections::HashMap;
use std::sync::Mutex;

use crate::error::{Error, Result};
use chrono::Utc;
use rusqlite::params;
use sha2::{Digest, Sha256};

// ─── 数据类型 ───

#[derive(Debug, Clone)]
pub struct Blob {
    pub hash: String,
    pub content: String,
    pub labels: HashMap<String, String>,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct Label {
    pub entity_hash: String,
    pub key: String,
    pub value: String,
}

// ─── BlobStore trait ───

/// Blob 存储抽象 — 所有存储后端必须实现此 trait
///
/// 写操作使用 &self，实现者需自行处理内部可变性（如 Mutex）。
/// 理由：&self 使 trait 可在 Arc 中共享，避免 &mut self 导致 Arc<Mutex> 嵌套。
pub trait BlobStore: Send + Sync {
    /// 写入 blob（幂等：相同 content 返回已有记录，合并不冲突的 labels）
    fn blob_write(&self, content: &str, labels: &HashMap<String, String>) -> Result<Blob>;

    /// 读取 blob
    fn blob_read(&self, hash: &str) -> Result<Blob>;

    /// 按 labels 查询 blob（AND 语义）
    fn blob_query(&self, filter: &HashMap<String, String>) -> Result<Vec<Blob>>;

    /// 按 labels 查询 blob（支持分页）
    fn blob_query_paginated(
        &self,
        filter: &HashMap<String, String>,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> Result<Vec<Blob>>;

    /// blob 总数
    fn blob_count(&self) -> Result<i64>;

    /// 只查询 hash + labels（不加载 content）
    fn blob_query_metadata(
        &self,
        filter: &HashMap<String, String>,
    ) -> Result<Vec<(String, HashMap<String, String>)>>;

    /// 删除 blob 及其所有 labels
    ///
    /// 默认返回 Unsupported 错误 — append-only 后端无需实现。
    /// 仅用于管道内部回滚（CNV/AZN-VER 校验失败时撤回刚写入的 blob）。
    fn blob_delete(&self, _hash: &str) -> Result<()> {
        Err(Error::Unsupported("blob_delete not supported by this backend".into()))
    }

    /// 添加 label（key 冲突时报错）
    fn label_add(&self, entity_hash: &str, key: &str, value: &str) -> Result<()>;

    /// 设置 label（upsert：存在则替换，不存在则创建）
    fn label_set(&self, entity_hash: &str, key: &str, value: &str) -> Result<()>;

    /// 按 key/value 查询 labels
    fn label_query(&self, key: &str, value: Option<&str>) -> Result<Vec<Label>>;

    /// 查询指定 entity 的所有 labels
    fn label_query_for_entity(&self, entity_hash: &str) -> Result<Vec<Label>>;
}

// ─── SQLite 实现 ───

/// SQLite blob 存储引擎（默认实现）
///
/// `Connection` 用 `Mutex` 包装以满足 `Send + Sync`。
/// 由于 `Baize` 已在 `Arc<tokio::sync::Mutex>` 后面，内部 Mutex 无实际竞争。
pub struct SqliteBlobStore {
    db: Mutex<rusqlite::Connection>,
}

/// 向后兼容类型别名
pub type Storage = SqliteBlobStore;

impl SqliteBlobStore {
    pub fn open(path: &str) -> Result<Self> {
        let conn = if path == ":memory:" {
            rusqlite::Connection::open_in_memory()?
        } else {
            rusqlite::Connection::open(path)?
        };
        let store = Self {
            db: Mutex::new(conn),
        };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> Result<()> {
        self.db.lock().unwrap().execute_batch(
            "
            CREATE TABLE IF NOT EXISTS blobs (
                hash       TEXT PRIMARY KEY,
                content    TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS labels (
                entity_hash TEXT NOT NULL,
                key         TEXT NOT NULL,
                value       TEXT NOT NULL,
                PRIMARY KEY (entity_hash, key, value)
            );
            CREATE INDEX IF NOT EXISTS idx_labels_kv ON labels(key, value);
            CREATE INDEX IF NOT EXISTS idx_labels_hash ON labels(entity_hash);
            ",
        )?;
        Ok(())
    }

    // ─── Blob 操作 ───

    pub fn blob_write(&self, content: &str, labels: &HashMap<String, String>) -> Result<Blob> {
        let hash = Self::hash_content(content);
        let created_at = Utc::now().to_rfc3339();

        // 幂等：已存在则合并不冲突的 labels 后返回
        if self.blob_exists(&hash)? {
            {
                let db = self.db.lock().unwrap();
                let tx = db.unchecked_transaction()?;
                for (k, v) in labels {
                    let exists: bool = tx.query_row(
                        "SELECT EXISTS(SELECT 1 FROM labels WHERE entity_hash = ?1 AND key = ?2)",
                        params![hash, k],
                        |row| row.get(0),
                    )?;
                    if !exists {
                        tx.execute(
                            "INSERT INTO labels (entity_hash, key, value) VALUES (?1, ?2, ?3)",
                            params![hash, k, v],
                        )?;
                    }
                }
                tx.commit()?;
            }
            return self.blob_read(&hash);
        }

        {
            let db = self.db.lock().unwrap();
            let tx = db.unchecked_transaction()?;

            tx.execute(
                "INSERT INTO blobs (hash, content, created_at) VALUES (?1, ?2, ?3)",
                params![hash, content, created_at],
            )?;

            for (k, v) in labels {
                tx.execute(
                    "INSERT INTO labels (entity_hash, key, value) VALUES (?1, ?2, ?3)",
                    params![hash, k, v],
                )?;
            }

            tx.commit()?;
        }

        Ok(Blob {
            hash,
            content: content.to_string(),
            labels: labels.clone(),
            created_at,
        })
    }

    pub fn blob_read(&self, hash: &str) -> Result<Blob> {
        let (content, created_at) = self
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT content, created_at FROM blobs WHERE hash = ?1",
                params![hash],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| Error::NotFound(format!("blob {}", hash)))?;

        let labels = self.load_entity_labels(hash)?;
        Ok(Blob {
            hash: hash.to_string(),
            content,
            labels,
            created_at,
        })
    }

    /// 批量加载 blob（单次查询 + 单次 label 批量查询，避免 N+1）
    fn load_blobs_batch(&self, hashes: &[String]) -> Result<Vec<Blob>> {
        if hashes.is_empty() {
            return Ok(vec![]);
        }

        let db = self.db.lock().unwrap();

        // 构建 IN 子句参数
        let placeholders: Vec<String> = hashes
            .iter()
            .enumerate()
            .map(|(i, _)| format!("?{}", i + 1))
            .collect();
        let sql = format!(
            "SELECT hash, content, created_at FROM blobs WHERE hash IN ({})",
            placeholders.join(", ")
        );

        let mut stmt = db.prepare(&sql)?;
        let param_refs: Vec<Box<dyn rusqlite::types::ToSql>> = hashes
            .iter()
            .map(|h| Box::new(h.as_str()) as Box<dyn rusqlite::types::ToSql>)
            .collect();
        let param_slice: Vec<&dyn rusqlite::types::ToSql> =
            param_refs.iter().map(|p| p.as_ref()).collect();

        let blobs: Vec<Blob> = stmt
            .query_map(param_slice.as_slice(), |row| {
                Ok(Blob {
                    hash: row.get(0)?,
                    content: row.get(1)?,
                    labels: HashMap::new(), // 稍后填充
                    created_at: row.get(2)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();
        drop(stmt);

        // 批量加载所有 blob 的 labels
        let label_placeholders: Vec<String> = hashes
            .iter()
            .enumerate()
            .map(|(i, _)| format!("?{}", i + 1))
            .collect();
        let label_sql = format!(
            "SELECT entity_hash, key, value FROM labels WHERE entity_hash IN ({})",
            label_placeholders.join(", ")
        );

        let mut label_stmt = db.prepare(&label_sql)?;
        let label_params: Vec<Box<dyn rusqlite::types::ToSql>> = hashes
            .iter()
            .map(|h| Box::new(h.as_str()) as Box<dyn rusqlite::types::ToSql>)
            .collect();
        let label_slice: Vec<&dyn rusqlite::types::ToSql> =
            label_params.iter().map(|p| p.as_ref()).collect();

        let mut label_map: HashMap<String, HashMap<String, String>> = HashMap::new();
        let rows = label_stmt.query_map(label_slice.as_slice(), |row| {
            Ok::<(String, String, String), rusqlite::Error>((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?;
        for row in rows.flatten() {
            label_map.entry(row.0).or_default().insert(row.1, row.2);
        }
        drop(label_stmt);
        drop(db);

        // 组装结果
        let result: Vec<Blob> = blobs
            .into_iter()
            .map(|mut b| {
                if let Some(labels) = label_map.remove(&b.hash) {
                    b.labels = labels;
                }
                b
            })
            .collect();

        Ok(result)
    }

    pub fn blob_query(&self, filter: &HashMap<String, String>) -> Result<Vec<Blob>> {
        self.blob_query_paginated(filter, None, None)
    }

    /// 按 labels 查询 blob（支持分页）
    pub fn blob_query_paginated(
        &self,
        filter: &HashMap<String, String>,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> Result<Vec<Blob>> {
        let hashes = self.query_hashes_by_labels(filter, limit, offset)?;
        self.load_blobs_batch(&hashes)
    }

    /// 根据 label filter 查询匹配的 entity hash 列表
    /// AND 语义：所有 filter 条件必须同时满足
    fn query_hashes_by_labels(
        &self,
        filter: &HashMap<String, String>,
        limit: Option<usize>,
        offset: Option<usize>,
    ) -> Result<Vec<String>> {
        let db = self.db.lock().unwrap();

        if filter.is_empty() {
            let mut sql = "SELECT hash FROM blobs ORDER BY created_at DESC".to_string();
            if let Some(lim) = limit {
                sql.push_str(&format!(" LIMIT {}", lim));
            }
            if let Some(off) = offset {
                sql.push_str(&format!(" OFFSET {}", off));
            }
            let mut stmt = db.prepare(&sql)?;
            let hashes: Vec<String> = stmt
                .query_map([], |row| row.get::<_, String>(0))?
                .filter_map(|r| r.ok())
                .collect();
            return Ok(hashes);
        }

        let filter_vec: Vec<(&String, &String)> = filter.iter().collect();
        let conditions: Vec<String> = filter_vec
            .iter()
            .enumerate()
            .map(|(i, _)| format!("(key = ?{} AND value = ?{})", i * 2 + 1, i * 2 + 2))
            .collect();
        let mut sql = format!(
            "SELECT entity_hash FROM labels WHERE {} GROUP BY entity_hash HAVING COUNT(DISTINCT key) = {}",
            conditions.join(" OR "),
            filter.len()
        );
        if let Some(lim) = limit {
            sql.push_str(&format!(" LIMIT {}", lim));
            if let Some(off) = offset {
                sql.push_str(&format!(" OFFSET {}", off));
            }
        }
        let mut stmt = db.prepare(&sql)?;
        let mut sql_params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        for (k, v) in &filter_vec {
            sql_params.push(Box::new(k.as_str()));
            sql_params.push(Box::new(v.as_str()));
        }
        let param_refs: Vec<&dyn rusqlite::types::ToSql> =
            sql_params.iter().map(|p| p.as_ref()).collect();
        let hashes: Vec<String> = stmt
            .query_map(param_refs.as_slice(), |row| row.get::<_, String>(0))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(hashes)
    }

    pub fn blob_count(&self) -> Result<i64> {
        let count: i64 = self.db.lock().unwrap().query_row(
            "SELECT COUNT(*) FROM blobs",
            [],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    /// 删除 blob 及其所有 labels
    ///
    /// 仅用于管道内部回滚（CNV/AZN-VER 校验失败时撤回刚写入的 blob）。
    /// 调用方已在管道层完成鉴权，此函数不做权限检查。不得用于响应外部删除请求。
    pub fn blob_delete(&self, hash: &str) -> Result<()> {
        let db = self.db.lock().unwrap();
        let tx = db.unchecked_transaction()?;
        tx.execute("DELETE FROM labels WHERE entity_hash = ?1", params![hash])?;
        let rows = tx.execute("DELETE FROM blobs WHERE hash = ?1", params![hash])?;
        tx.commit()?;
        if rows == 0 {
            return Err(Error::NotFound(format!("blob {}", hash)));
        }
        Ok(())
    }

    fn blob_exists(&self, hash: &str) -> Result<bool> {
        let count: i64 = self.db.lock().unwrap().query_row(
            "SELECT COUNT(*) FROM blobs WHERE hash = ?1",
            params![hash],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    fn load_entity_labels(&self, hash: &str) -> Result<HashMap<String, String>> {
        let db = self.db.lock().unwrap();
        let mut stmt = db.prepare("SELECT key, value FROM labels WHERE entity_hash = ?1")?;
        let labels: HashMap<String, String> = stmt
            .query_map(params![hash], |row| Ok((row.get(0)?, row.get(1)?)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(labels)
    }

    /// 只查询 hash + labels（不加载 blob content），用于审计等只需要元数据的场景
    pub fn blob_query_metadata(
        &self,
        filter: &HashMap<String, String>,
    ) -> Result<Vec<(String, HashMap<String, String>)>> {
        let hashes = self.query_hashes_by_labels(filter, None, None)?;
        let mut results = Vec::new();
        for hash in hashes {
            let labels = self.load_entity_labels(&hash)?;
            results.push((hash, labels));
        }
        Ok(results)
    }

    // ─── Label 操作（挂在 blob 上） ───

    pub fn label_add(&self, entity_hash: &str, key: &str, value: &str) -> Result<()> {
        let db = self.db.lock().unwrap();
        // 事务内完成检查+插入，防止并发竞态
        let tx = db.unchecked_transaction()?;

        // 检查 blob 是否存在
        let blob_count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM blobs WHERE hash = ?1",
            params![entity_hash],
            |row| row.get(0),
        )?;
        if blob_count == 0 {
            return Err(Error::NotFound(format!("blob {}", entity_hash)));
        }

        // 检查 key 是否已存在（LABEL_CONFLICT）
        let existing: i64 = tx.query_row(
            "SELECT COUNT(*) FROM labels WHERE entity_hash = ?1 AND key = ?2",
            params![entity_hash, key],
            |row| row.get(0),
        )?;
        if existing > 0 {
            return Err(Error::Conflict(format!(
                "label key '{}' already exists on {}",
                key, entity_hash
            )));
        }

        tx.execute(
            "INSERT INTO labels (entity_hash, key, value) VALUES (?1, ?2, ?3)",
            params![entity_hash, key, value],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// 设置 label（upsert：存在则替换，不存在则创建）
    pub fn label_set(&self, entity_hash: &str, key: &str, value: &str) -> Result<()> {
        if !self.blob_exists(entity_hash)? {
            return Err(Error::NotFound(format!("blob {}", entity_hash)));
        }
        let db = self.db.lock().unwrap();
        let tx = db.unchecked_transaction()?;
        // 主键包含 value，必须先删除旧值再插入新值
        tx.execute(
            "DELETE FROM labels WHERE entity_hash = ?1 AND key = ?2",
            params![entity_hash, key],
        )?;
        tx.execute(
            "INSERT INTO labels (entity_hash, key, value) VALUES (?1, ?2, ?3)",
            params![entity_hash, key, value],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn label_query(&self, key: &str, value: Option<&str>) -> Result<Vec<Label>> {
        let db = self.db.lock().unwrap();
        let labels = if let Some(v) = value {
            let mut stmt = db.prepare(
                "SELECT entity_hash, key, value FROM labels WHERE key = ?1 AND value = ?2",
            )?;
            let result: Vec<Label> = stmt
                .query_map(params![key, v], |row| {
                    Ok(Label {
                        entity_hash: row.get(0)?,
                        key: row.get(1)?,
                        value: row.get(2)?,
                    })
                })?
                .filter_map(|r| r.ok())
                .collect();
            drop(stmt);
            result
        } else {
            let mut stmt =
                db.prepare("SELECT entity_hash, key, value FROM labels WHERE key = ?1")?;
            let result: Vec<Label> = stmt
                .query_map(params![key], |row| {
                    Ok(Label {
                        entity_hash: row.get(0)?,
                        key: row.get(1)?,
                        value: row.get(2)?,
                    })
                })?
                .filter_map(|r| r.ok())
                .collect();
            drop(stmt);
            result
        };
        Ok(labels)
    }

    /// 查询指定 entity 的所有 labels
    pub fn label_query_for_entity(&self, entity_hash: &str) -> Result<Vec<Label>> {
        let db = self.db.lock().unwrap();
        let mut stmt =
            db.prepare("SELECT entity_hash, key, value FROM labels WHERE entity_hash = ?1")?;
        let result: Vec<Label> = stmt
            .query_map(params![entity_hash], |row| {
                Ok(Label {
                    entity_hash: row.get(0)?,
                    key: row.get(1)?,
                    value: row.get(2)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(result)
    }

    // ─── 工具函数 ───

    pub fn hash_content(content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

// ─── BlobStore trait 实现 ───

/// 将 SqliteBlobStore 固有方法转发为 BlobStore trait 实现
macro_rules! delegate_blob_store {
    ($($method:ident($($arg:ident: $ty:ty),*) -> $ret:ty),* $(,)?) => {
        impl BlobStore for SqliteBlobStore {
            $(fn $method(&self, $($arg: $ty),*) -> $ret {
                SqliteBlobStore::$method(self, $($arg),*)
            })*
        }
    }
}

delegate_blob_store! {
    blob_write(content: &str, labels: &HashMap<String, String>) -> Result<Blob>,
    blob_read(hash: &str) -> Result<Blob>,
    blob_query(filter: &HashMap<String, String>) -> Result<Vec<Blob>>,
    blob_query_paginated(filter: &HashMap<String, String>, limit: Option<usize>, offset: Option<usize>) -> Result<Vec<Blob>>,
    blob_count() -> Result<i64>,
    blob_query_metadata(filter: &HashMap<String, String>) -> Result<Vec<(String, HashMap<String, String>)>>,
    blob_delete(hash: &str) -> Result<()>,
    label_add(entity_hash: &str, key: &str, value: &str) -> Result<()>,
    label_set(entity_hash: &str, key: &str, value: &str) -> Result<()>,
    label_query(key: &str, value: Option<&str>) -> Result<Vec<Label>>,
    label_query_for_entity(entity_hash: &str) -> Result<Vec<Label>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn open_db() -> Storage {
        Storage::open(":memory:").unwrap()
    }

    // ─── Blob ───

    #[test]
    fn blob_write_and_read() {
        let db = open_db();
        let mut labels = HashMap::new();
        labels.insert("type".to_string(), "test".to_string());
        let blob = db.blob_write("hello world", &labels).unwrap();
        assert!(!blob.hash.is_empty());
        assert_eq!(blob.content, "hello world");
        assert_eq!(blob.labels["type"], "test");

        let read = db.blob_read(&blob.hash).unwrap();
        assert_eq!(read.content, "hello world");
        assert_eq!(read.hash, blob.hash);
    }

    #[test]
    fn blob_write_idempotent() {
        let db = open_db();
        let labels = HashMap::new();
        let b1 = db.blob_write("same content", &labels).unwrap();
        let b2 = db.blob_write("same content", &labels).unwrap();
        assert_eq!(b1.hash, b2.hash);
    }

    #[test]
    fn blob_write_idempotent_merges_new_labels() {
        let db = open_db();
        let mut l1 = HashMap::new();
        l1.insert("a".to_string(), "1".to_string());
        let b1 = db.blob_write("same content", &l1).unwrap();

        let mut l2 = HashMap::new();
        l2.insert("a".to_string(), "1".to_string()); // 已存在，跳过
        l2.insert("b".to_string(), "2".to_string()); // 新增
        let b2 = db.blob_write("same content", &l2).unwrap();

        assert_eq!(b1.hash, b2.hash);
        assert_eq!(b2.labels["a"], "1");
        assert_eq!(b2.labels["b"], "2");
    }

    #[test]
    fn blob_write_idempotent_skips_conflicting_labels() {
        let db = open_db();
        let mut l1 = HashMap::new();
        l1.insert("a".to_string(), "1".to_string());
        db.blob_write("content x", &l1).unwrap();

        let mut l2 = HashMap::new();
        l2.insert("a".to_string(), "999".to_string()); // key 冲突，跳过
        let b2 = db.blob_write("content x", &l2).unwrap();

        assert_eq!(b2.labels["a"], "1"); // 原值不变
    }

    #[test]
    fn blob_write_idempotent_no_new_labels() {
        let db = open_db();
        let mut l1 = HashMap::new();
        l1.insert("a".to_string(), "1".to_string());
        let b1 = db.blob_write("content y", &l1).unwrap();

        let b2 = db.blob_write("content y", &HashMap::new()).unwrap();
        assert_eq!(b1.hash, b2.hash);
        assert_eq!(b2.labels["a"], "1"); // 原有 label 保留
    }

    #[test]
    fn blob_read_nonexistent() {
        let db = open_db();
        let result = db.blob_read("0000deadbeef");
        assert!(result.is_err());
    }

    #[test]
    fn blob_query_empty_filter() {
        let db = open_db();
        db.blob_write("a", &HashMap::new()).unwrap();
        db.blob_write("b", &HashMap::new()).unwrap();
        let blobs = db.blob_query(&HashMap::new()).unwrap();
        assert_eq!(blobs.len(), 2);
    }

    #[test]
    fn blob_query_by_labels() {
        let db = open_db();
        let mut l1 = HashMap::new();
        l1.insert("kind".to_string(), "alpha".to_string());
        let mut l2 = HashMap::new();
        l2.insert("kind".to_string(), "beta".to_string());
        db.blob_write("alpha content", &l1).unwrap();
        db.blob_write("beta content", &l2).unwrap();

        let mut filter = HashMap::new();
        filter.insert("kind".to_string(), "alpha".to_string());
        let results = db.blob_query(&filter).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].content, "alpha content");
    }

    #[test]
    fn blob_query_no_match() {
        let db = open_db();
        let mut filter = HashMap::new();
        filter.insert("missing".to_string(), "nope".to_string());
        let results = db.blob_query(&filter).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn blob_query_multi_label_and() {
        let db = open_db();
        let mut labels = HashMap::new();
        labels.insert("a".to_string(), "1".to_string());
        labels.insert("b".to_string(), "2".to_string());
        db.blob_write("both", &labels).unwrap();

        let mut l3 = HashMap::new();
        l3.insert("a".to_string(), "1".to_string());
        db.blob_write("only a", &l3).unwrap();

        // 两个条件都满足
        let mut filter = HashMap::new();
        filter.insert("a".to_string(), "1".to_string());
        filter.insert("b".to_string(), "2".to_string());
        let results = db.blob_query(&filter).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].content, "both");
    }

    // ─── Label ───

    #[test]
    fn label_add_and_query() {
        let db = open_db();
        let blob = db.blob_write("data", &HashMap::new()).unwrap();
        db.label_add(&blob.hash, "env", "prod").unwrap();

        let labels = db.label_query("env", Some("prod")).unwrap();
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0].entity_hash, blob.hash);
        assert_eq!(labels[0].value, "prod");
    }

    #[test]
    fn label_add_conflict() {
        let db = open_db();
        let blob = db.blob_write("data", &HashMap::new()).unwrap();
        db.label_add(&blob.hash, "env", "prod").unwrap();
        let result = db.label_add(&blob.hash, "env", "staging");
        assert!(result.is_err());
    }

    #[test]
    fn label_add_nonexistent_entity() {
        let db = open_db();
        let result = db.label_add("deadbeef", "key", "val");
        assert!(result.is_err());
    }

    #[test]
    fn label_set_creates_new() {
        let db = open_db();
        let blob = db.blob_write("data", &HashMap::new()).unwrap();
        db.label_set(&blob.hash, "status", "active").unwrap();

        let labels = db.label_query("status", Some("active")).unwrap();
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0].entity_hash, blob.hash);
    }

    #[test]
    fn label_set_replaces_existing() {
        let db = open_db();
        let blob = db.blob_write("data", &HashMap::new()).unwrap();
        db.label_add(&blob.hash, "status", "active").unwrap();

        db.label_set(&blob.hash, "status", "revoked").unwrap();

        // 旧值不应存在
        let old = db.label_query("status", Some("active")).unwrap();
        assert_eq!(old.len(), 0, "old value should be gone");
        // 新值应存在
        let new = db.label_query("status", Some("revoked")).unwrap();
        assert_eq!(new.len(), 1);
        assert_eq!(new[0].entity_hash, blob.hash);
    }

    #[test]
    fn label_set_nonexistent_entity() {
        let db = open_db();
        let result = db.label_set("deadbeef", "key", "val");
        assert!(result.is_err());
    }

    #[test]
    fn label_query_key_only() {
        let db = open_db();
        let blob = db.blob_write("data", &HashMap::new()).unwrap();
        db.label_add(&blob.hash, "env", "prod").unwrap();

        let labels = db.label_query("env", None).unwrap();
        assert_eq!(labels.len(), 1);
    }

    #[test]
    fn hash_content_deterministic() {
        let h1 = Storage::hash_content("hello");
        let h2 = Storage::hash_content("hello");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 hex
    }

    // ─── BlobStore trait 测试 ───

    #[test]
    fn blob_store_trait_sqlite_implementation() {
        let store: Arc<dyn BlobStore> = Arc::new(Storage::open(":memory:").unwrap());
        let mut labels = HashMap::new();
        labels.insert("type".to_string(), "test".to_string());
        let blob = store.blob_write("hello", &labels).unwrap();
        let read = store.blob_read(&blob.hash).unwrap();
        assert_eq!(read.content, "hello");

        // Arc<dyn BlobStore> 的 Deref 调用也正常工作
        let blobs = store.blob_query(&labels).unwrap();
        assert_eq!(blobs.len(), 1);
        assert_eq!(store.blob_count().unwrap(), 1);
    }

    #[test]
    fn blob_store_trait_is_pluggable() {
        /// HashMap mock 实现，验证 trait 可替换
        struct HashMapBlobStore {
            blobs: Mutex<HashMap<String, (String, HashMap<String, String>)>>,
        }

        impl BlobStore for HashMapBlobStore {
            fn blob_write(&self, content: &str, labels: &HashMap<String, String>) -> Result<Blob> {
                let hash = Storage::hash_content(content);
                let mut map = self.blobs.lock().unwrap();
                map.entry(hash.clone())
                    .or_insert_with(|| (content.to_string(), labels.clone()));
                let (c, l) = map.get(&hash).unwrap();
                Ok(Blob {
                    hash,
                    content: c.clone(),
                    labels: l.clone(),
                    created_at: "now".into(),
                })
            }

            fn blob_read(&self, hash: &str) -> Result<Blob> {
                self.blobs
                    .lock()
                    .unwrap()
                    .get(hash)
                    .map(|(c, l)| Blob {
                        hash: hash.into(),
                        content: c.clone(),
                        labels: l.clone(),
                        created_at: "now".into(),
                    })
                    .ok_or_else(|| Error::NotFound(format!("blob {}", hash)))
            }

            fn blob_query(&self, _filter: &HashMap<String, String>) -> Result<Vec<Blob>> {
                Ok(vec![])
            }

            fn blob_query_paginated(
                &self,
                _filter: &HashMap<String, String>,
                _limit: Option<usize>,
                _offset: Option<usize>,
            ) -> Result<Vec<Blob>> {
                Ok(vec![])
            }

            fn blob_count(&self) -> Result<i64> {
                Ok(self.blobs.lock().unwrap().len() as i64)
            }

            fn blob_query_metadata(
                &self,
                _filter: &HashMap<String, String>,
            ) -> Result<Vec<(String, HashMap<String, String>)>> {
                Ok(vec![])
            }

            fn blob_delete(&self, hash: &str) -> Result<()> {
                let mut map = self.blobs.lock().unwrap();
                if map.remove(hash).is_some() {
                    Ok(())
                } else {
                    Err(Error::NotFound(format!("blob {}", hash)))
                }
            }

            fn label_add(&self, _entity_hash: &str, _key: &str, _value: &str) -> Result<()> {
                Ok(())
            }

            fn label_set(&self, _entity_hash: &str, _key: &str, _value: &str) -> Result<()> {
                Ok(())
            }

            fn label_query(&self, _key: &str, _value: Option<&str>) -> Result<Vec<Label>> {
                Ok(vec![])
            }

            fn label_query_for_entity(&self, _entity_hash: &str) -> Result<Vec<Label>> {
                Ok(vec![])
            }
        }

        let store: Arc<dyn BlobStore> = Arc::new(HashMapBlobStore {
            blobs: Mutex::new(HashMap::new()),
        });
        let blob = store.blob_write("test", &HashMap::new()).unwrap();
        assert_eq!(blob.content, "test");
        let read = store.blob_read(&blob.hash).unwrap();
        assert_eq!(read.content, "test");
        assert_eq!(store.blob_count().unwrap(), 1);

        // blob_delete 在 mock 实现中正常工作
        store.blob_delete(&blob.hash).unwrap();
        assert_eq!(store.blob_count().unwrap(), 0);
    }
}
