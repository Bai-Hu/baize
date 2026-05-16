use std::collections::HashMap;

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
pub struct Commit {
    pub hash: String,
    pub message: String,
    pub author: Option<String>,
    pub parent_hash: Option<String>,
    pub blob_hashes: Vec<String>,
    pub labels: HashMap<String, String>,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct Ref {
    pub name: String,
    pub commit_hash: String,
}

#[derive(Debug, Clone)]
pub struct Label {
    pub entity_hash: String,
    pub key: String,
    pub value: String,
}

// ─── 存储引擎 ───

pub struct Storage {
    db: rusqlite::Connection,
}

impl Storage {
    pub fn open(path: &str) -> Result<Self> {
        let db = if path == ":memory:" {
            rusqlite::Connection::open_in_memory()?
        } else {
            rusqlite::Connection::open(path)?
        };
        let storage = Self { db };
        storage.init_schema()?;
        Ok(storage)
    }

    fn init_schema(&self) -> Result<()> {
        self.db.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS blobs (
                hash       TEXT PRIMARY KEY,
                content    TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS commits (
                hash        TEXT PRIMARY KEY,
                message     TEXT NOT NULL,
                author      TEXT,
                parent_hash TEXT,
                created_at  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS commit_blobs (
                commit_hash TEXT NOT NULL,
                blob_hash   TEXT NOT NULL,
                PRIMARY KEY (commit_hash, blob_hash)
            );

            CREATE TABLE IF NOT EXISTS refs (
                name        TEXT PRIMARY KEY,
                commit_hash TEXT NOT NULL
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
            let tx = self.db.unchecked_transaction()?;
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
            return self.blob_read(&hash);
        }

        let tx = self.db.unchecked_transaction()?;

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

        Ok(Blob {
            hash,
            content: content.to_string(),
            labels: labels.clone(),
            created_at,
        })
    }

    pub fn blob_read(&self, hash: &str) -> Result<Blob> {
        let (content, created_at) = self.db.query_row(
            "SELECT content, created_at FROM blobs WHERE hash = ?1",
            params![hash],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).map_err(|_| Error::NotFound(format!("blob {}", hash)))?;

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

        // 构建 IN 子句参数
        let placeholders: Vec<String> = hashes.iter().enumerate()
            .map(|(i, _)| format!("?{}", i + 1))
            .collect();
        let sql = format!(
            "SELECT hash, content, created_at FROM blobs WHERE hash IN ({})",
            placeholders.join(", ")
        );

        let mut stmt = self.db.prepare(&sql)?;
        let param_refs: Vec<Box<dyn rusqlite::types::ToSql>> = hashes.iter()
            .map(|h| Box::new(h.as_str()) as Box<dyn rusqlite::types::ToSql>)
            .collect();
        let param_slice: Vec<&dyn rusqlite::types::ToSql> = param_refs.iter().map(|p| p.as_ref()).collect();

        let blobs: Vec<Blob> = stmt.query_map(param_slice.as_slice(), |row| {
            Ok(Blob {
                hash: row.get(0)?,
                content: row.get(1)?,
                labels: HashMap::new(), // 稍后填充
                created_at: row.get(2)?,
            })
        })?.filter_map(|r| r.ok()).collect();
        drop(stmt);

        // 批量加载所有 blob 的 labels
        let label_placeholders: Vec<String> = hashes.iter().enumerate()
            .map(|(i, _)| format!("?{}", i + 1))
            .collect();
        let label_sql = format!(
            "SELECT entity_hash, key, value FROM labels WHERE entity_hash IN ({})",
            label_placeholders.join(", ")
        );

        let mut label_stmt = self.db.prepare(&label_sql)?;
        let label_params: Vec<Box<dyn rusqlite::types::ToSql>> = hashes.iter()
            .map(|h| Box::new(h.as_str()) as Box<dyn rusqlite::types::ToSql>)
            .collect();
        let label_slice: Vec<&dyn rusqlite::types::ToSql> = label_params.iter().map(|p| p.as_ref()).collect();

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

        // 组装结果
        let result: Vec<Blob> = blobs.into_iter().map(|mut b| {
            if let Some(labels) = label_map.remove(&b.hash) {
                b.labels = labels;
            }
            b
        }).collect();

        Ok(result)
    }

    pub fn blob_query(&self, filter: &HashMap<String, String>) -> Result<Vec<Blob>> {
        let hashes = self.query_hashes_by_labels(filter)?;
        self.load_blobs_batch(&hashes)
    }

    /// 根据 label filter 查询匹配的 entity hash 列表
    /// AND 语义：所有 filter 条件必须同时满足
    fn query_hashes_by_labels(&self, filter: &HashMap<String, String>) -> Result<Vec<String>> {
        if filter.is_empty() {
            let mut stmt = self.db.prepare("SELECT hash FROM blobs ORDER BY created_at DESC")?;
            let hashes: Vec<String> = stmt.query_map([], |row| row.get::<_, String>(0))?.filter_map(|r| r.ok()).collect();
            return Ok(hashes);
        }

        let filter_vec: Vec<(&String, &String)> = filter.iter().collect();
        let conditions: Vec<String> = filter_vec
            .iter()
            .enumerate()
            .map(|(i, _)| format!("(key = ?{} AND value = ?{})", i * 2 + 1, i * 2 + 2))
            .collect();
        let sql = format!(
            "SELECT entity_hash FROM labels WHERE {} GROUP BY entity_hash HAVING COUNT(DISTINCT key) = {}",
            conditions.join(" OR "),
            filter.len()
        );
        let mut stmt = self.db.prepare(&sql)?;
        let mut sql_params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        for (k, v) in &filter_vec {
            sql_params.push(Box::new(k.as_str()));
            sql_params.push(Box::new(v.as_str()));
        }
        let param_refs: Vec<&dyn rusqlite::types::ToSql> = sql_params.iter().map(|p| p.as_ref()).collect();
        let hashes: Vec<String> = stmt.query_map(param_refs.as_slice(), |row| row.get::<_, String>(0))?.filter_map(|r| r.ok()).collect();
        Ok(hashes)
    }

    fn blob_exists(&self, hash: &str) -> Result<bool> {
        let count: i64 = self.db.query_row(
            "SELECT COUNT(*) FROM blobs WHERE hash = ?1",
            params![hash],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    fn load_entity_labels(&self, hash: &str) -> Result<HashMap<String, String>> {
        let mut stmt = self.db.prepare(
            "SELECT key, value FROM labels WHERE entity_hash = ?1",
        )?;
        let labels: HashMap<String, String> = stmt
            .query_map(params![hash], |row| Ok((row.get(0)?, row.get(1)?)))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(labels)
    }

    /// 只查询 hash + labels（不加载 blob content），用于审计等只需要元数据的场景
    pub fn blob_query_metadata(&self, filter: &HashMap<String, String>) -> Result<Vec<(String, HashMap<String, String>)>> {
        let hashes = self.query_hashes_by_labels(filter)?;
        let mut results = Vec::new();
        for hash in hashes {
            let labels = self.load_entity_labels(&hash)?;
            results.push((hash, labels));
        }
        Ok(results)
    }

    // ─── Commit 操作 ───

    pub fn commit_create(&self, blob_hashes: &[String], message: &str, parent_hash: Option<&str>, author: Option<&str>, labels: &HashMap<String, String>) -> Result<Commit> {
        if blob_hashes.is_empty() {
            return Err(Error::Validation("commit must contain at least one blob".into()));
        }

        // 验证所有 blob 存在
        for bh in blob_hashes {
            if !self.blob_exists(bh)? {
                return Err(Error::NotFound(format!("blob {}", bh)));
            }
        }

        // 验证 parent 存在（如果指定）
        if let Some(ph) = parent_hash {
            if !self.commit_exists(ph)? {
                return Err(Error::NotFound(format!("commit (parent) {}", ph)));
            }
        }

        // commit hash = SHA-256(排序后的 blob hashes + parent + message + author)
        let mut hasher = Sha256::new();
        let mut sorted = blob_hashes.to_vec();
        sorted.sort();
        for bh in &sorted {
            hasher.update(bh.as_bytes());
        }
        if let Some(ph) = parent_hash {
            hasher.update(ph.as_bytes());
        }
        hasher.update(message.as_bytes());
        if let Some(a) = author {
            hasher.update(a.as_bytes());
        }
        let hash = format!("{:x}", hasher.finalize());

        let created_at = Utc::now().to_rfc3339();

        let tx = self.db.unchecked_transaction()?;

        tx.execute(
            "INSERT INTO commits (hash, message, author, parent_hash, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![hash, message, author, parent_hash, created_at],
        )?;

        for bh in &sorted {
            tx.execute(
                "INSERT INTO commit_blobs (commit_hash, blob_hash) VALUES (?1, ?2)",
                params![hash, bh],
            )?;
        }

        for (k, v) in labels {
            tx.execute(
                "INSERT INTO labels (entity_hash, key, value) VALUES (?1, ?2, ?3)",
                params![hash, k, v],
            )?;
        }

        // 同一事务内更新 HEAD
        tx.execute(
            "INSERT OR REPLACE INTO refs (name, commit_hash) VALUES ('HEAD', ?1)",
            params![hash],
        )?;

        tx.commit()?;

        Ok(Commit {
            hash,
            message: message.to_string(),
            author: author.map(String::from),
            parent_hash: parent_hash.map(String::from),
            blob_hashes: sorted,
            labels: labels.clone(),
            created_at,
        })
    }

    pub fn commit_log(&self, from_hash: Option<&str>) -> Result<Vec<Commit>> {
        let start = match from_hash {
            Some(h) => h.to_string(),
            None => {
                // 从 HEAD 开始
                match self.ref_get("HEAD") {
                    Ok(r) => r.commit_hash,
                    Err(_) => return Ok(vec![]),
                }
            }
        };

        let mut commits = Vec::new();
        let mut current = Some(start);

        while let Some(hash) = current {
            let commit = self.commit_read(&hash)?;
            current = commit.parent_hash.clone();
            commits.push(commit);
        }

        Ok(commits)
    }

    pub fn commit_read(&self, hash: &str) -> Result<Commit> {
        let (message, author, parent_hash, created_at) = self.db.query_row(
            "SELECT message, author, parent_hash, created_at FROM commits WHERE hash = ?1",
            params![hash],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ).map_err(|_| Error::NotFound(format!("commit {}", hash)))?;

        let blob_hashes = self.load_commit_blobs(hash)?;
        let labels = self.load_entity_labels(hash)?;
        Ok(Commit {
            hash: hash.to_string(),
            message,
            author,
            parent_hash,
            blob_hashes,
            labels,
            created_at,
        })
    }

    fn commit_exists(&self, hash: &str) -> Result<bool> {
        let count: i64 = self.db.query_row(
            "SELECT COUNT(*) FROM commits WHERE hash = ?1",
            params![hash],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    fn load_commit_blobs(&self, hash: &str) -> Result<Vec<String>> {
        let mut stmt = self.db.prepare(
            "SELECT blob_hash FROM commit_blobs WHERE commit_hash = ?1",
        )?;
        let hashes: Vec<String> = stmt
            .query_map(params![hash], |row| row.get(0))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(hashes)
    }

    /// 查找包含指定 blob 的所有 commit hash
    pub fn commits_containing_blob(&self, blob_hash: &str) -> Result<Vec<String>> {
        let mut stmt = self.db.prepare(
            "SELECT commit_hash FROM commit_blobs WHERE blob_hash = ?1",
        )?;
        let hashes: Vec<String> = stmt
            .query_map(params![blob_hash], |row| row.get(0))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(hashes)
    }

    // ─── Ref 操作 ───

    pub fn ref_set(&self, name: &str, commit_hash: &str) -> Result<()> {
        if !self.commit_exists(commit_hash)? {
            return Err(Error::NotFound(format!("commit {}", commit_hash)));
        }
        self.db.execute(
            "INSERT OR REPLACE INTO refs (name, commit_hash) VALUES (?1, ?2)",
            params![name, commit_hash],
        )?;
        Ok(())
    }

    pub fn ref_get(&self, name: &str) -> Result<Ref> {
        let commit_hash = self.db.query_row(
            "SELECT commit_hash FROM refs WHERE name = ?1",
            params![name],
            |row| row.get(0),
        ).map_err(|_| Error::NotFound(format!("ref {}", name)))?;
        Ok(Ref {
            name: name.to_string(),
            commit_hash,
        })
    }

    pub fn ref_delete(&self, name: &str) -> Result<()> {
        if name == "HEAD" {
            return Err(Error::Validation("cannot delete HEAD ref".into()));
        }
        let rows = self.db.execute(
            "DELETE FROM refs WHERE name = ?1",
            params![name],
        )?;
        if rows == 0 {
            return Err(Error::NotFound(format!("ref {}", name)));
        }
        Ok(())
    }

    pub fn ref_list(&self) -> Result<Vec<Ref>> {
        let mut stmt = self.db.prepare("SELECT name, commit_hash FROM refs ORDER BY name")?;
        let refs = stmt
            .query_map([], |row| {
                Ok(Ref {
                    name: row.get(0)?,
                    commit_hash: row.get(1)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();
        Ok(refs)
    }

    // ─── Label 操作（通用，挂载在 blob 或 commit 上） ───

    pub fn label_add(&self, entity_hash: &str, key: &str, value: &str) -> Result<()> {
        // 检查实体是否存在（blob 或 commit）
        if !self.blob_exists(entity_hash)? && !self.commit_exists(entity_hash)? {
            return Err(Error::NotFound(format!("entity {}", entity_hash)));
        }

        // 检查 key 是否已存在（LABEL_CONFLICT）
        let existing = self.db.query_row(
            "SELECT COUNT(*) FROM labels WHERE entity_hash = ?1 AND key = ?2",
            params![entity_hash, key],
            |row| row.get::<_, i64>(0),
        )?;
        if existing > 0 {
            return Err(Error::Conflict(format!(
                "label key '{}' already exists on {}",
                key, entity_hash
            )));
        }

        self.db.execute(
            "INSERT INTO labels (entity_hash, key, value) VALUES (?1, ?2, ?3)",
            params![entity_hash, key, value],
        )?;
        Ok(())
    }

    pub fn label_query(&self, key: &str, value: Option<&str>) -> Result<Vec<Label>> {
        let labels = if let Some(v) = value {
            let mut stmt = self.db.prepare(
                "SELECT entity_hash, key, value FROM labels WHERE key = ?1 AND value = ?2",
            )?;
            let result: Vec<Label> = stmt.query_map(params![key, v], |row| {
                Ok(Label {
                    entity_hash: row.get(0)?,
                    key: row.get(1)?,
                    value: row.get(2)?,
                })
            })?.filter_map(|r| r.ok()).collect();
            drop(stmt);
            result
        } else {
            let mut stmt = self.db.prepare(
                "SELECT entity_hash, key, value FROM labels WHERE key = ?1",
            )?;
            let result: Vec<Label> = stmt.query_map(params![key], |row| {
                Ok(Label {
                    entity_hash: row.get(0)?,
                    key: row.get(1)?,
                    value: row.get(2)?,
                })
            })?.filter_map(|r| r.ok()).collect();
            drop(stmt);
            result
        };
        Ok(labels)
    }

    // ─── 工具函数 ───

    pub fn hash_content(content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    // ─── Commit ───

    fn write_blobs(db: &Storage, contents: &[&str]) -> Vec<String> {
        contents.iter().map(|c| {
            db.blob_write(c, &HashMap::new()).unwrap().hash
        }).collect()
    }

    #[test]
    fn commit_create_and_read() {
        let db = open_db();
        let hashes = write_blobs(&db, &["blob1", "blob2"]);
        let commit = db.commit_create(&hashes, "first commit", None, None, &HashMap::new()).unwrap();
        assert!(!commit.hash.is_empty());
        assert_eq!(commit.message, "first commit");
        assert!(commit.parent_hash.is_none());
        assert_eq!(commit.blob_hashes.len(), 2);

        let read = db.commit_read(&commit.hash).unwrap();
        assert_eq!(read.hash, commit.hash);
        assert_eq!(read.message, "first commit");
    }

    #[test]
    fn commit_create_empty_blobs_fails() {
        let db = open_db();
        let result = db.commit_create(&[], "empty", None, None, &HashMap::new());
        assert!(result.is_err());
    }

    #[test]
    fn commit_create_nonexistent_blob_fails() {
        let db = open_db();
        let result = db.commit_create(&["deadbeef".to_string()], "bad", None, None, &HashMap::new());
        assert!(result.is_err());
    }

    #[test]
    fn commit_create_nonexistent_parent_fails() {
        let db = open_db();
        let hashes = write_blobs(&db, &["x"]);
        let result = db.commit_create(&hashes, "orphan", Some("nope"), None, &HashMap::new());
        assert!(result.is_err());
    }

    #[test]
    fn commit_chain_and_log() {
        let db = open_db();
        let h1 = write_blobs(&db, &["a"]);
        let c1 = db.commit_create(&h1, "first", None, None, &HashMap::new()).unwrap();

        let h2 = write_blobs(&db, &["b"]);
        let c2 = db.commit_create(&h2, "second", Some(&c1.hash), None, &HashMap::new()).unwrap();

        let log = db.commit_log(None).unwrap();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].hash, c2.hash);
        assert_eq!(log[1].hash, c1.hash);
    }

    #[test]
    fn commit_log_from_hash() {
        let db = open_db();
        let h1 = write_blobs(&db, &["a"]);
        let c1 = db.commit_create(&h1, "first", None, None, &HashMap::new()).unwrap();

        let h2 = write_blobs(&db, &["b"]);
        let _c2 = db.commit_create(&h2, "second", Some(&c1.hash), None, &HashMap::new()).unwrap();

        // 从 c1 开始
        let log = db.commit_log(Some(&c1.hash)).unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].hash, c1.hash);
    }

    #[test]
    fn commit_log_empty() {
        let db = open_db();
        let log = db.commit_log(None).unwrap();
        assert!(log.is_empty());
    }

    #[test]
    fn commit_updates_head() {
        let db = open_db();
        let hashes = write_blobs(&db, &["x"]);
        let c = db.commit_create(&hashes, "init", None, None, &HashMap::new()).unwrap();
        let head = db.ref_get("HEAD").unwrap();
        assert_eq!(head.commit_hash, c.hash);
    }

    #[test]
    fn commit_create_with_author_and_labels() {
        let db = open_db();
        let hashes = write_blobs(&db, &["data1"]);
        let mut labels = HashMap::new();
        labels.insert("env".to_string(), "test".to_string());
        let c = db.commit_create(&hashes, "authored commit", None, Some("agent-001"), &labels).unwrap();
        assert_eq!(c.author.as_deref(), Some("agent-001"));
        assert_eq!(c.labels["env"], "test");
    }

    #[test]
    fn commit_read_returns_labels() {
        let db = open_db();
        let hashes = write_blobs(&db, &["data"]);
        let mut labels = HashMap::new();
        labels.insert("tier".to_string(), "prod".to_string());
        let c = db.commit_create(&hashes, "labeled", None, Some("root"), &labels).unwrap();

        let read = db.commit_read(&c.hash).unwrap();
        assert_eq!(read.author.as_deref(), Some("root"));
        assert_eq!(read.labels["tier"], "prod");
    }

    // ─── Ref ───

    #[test]
    fn ref_set_get_delete() {
        let db = open_db();
        let hashes = write_blobs(&db, &["x"]);
        let c = db.commit_create(&hashes, "init", None, None, &HashMap::new()).unwrap();

        db.ref_set("my-branch", &c.hash).unwrap();
        let r = db.ref_get("my-branch").unwrap();
        assert_eq!(r.commit_hash, c.hash);

        db.ref_delete("my-branch").unwrap();
        assert!(db.ref_get("my-branch").is_err());
    }

    #[test]
    fn ref_delete_head_fails() {
        let db = open_db();
        let result = db.ref_delete("HEAD");
        assert!(result.is_err());
    }

    #[test]
    fn ref_get_nonexistent() {
        let db = open_db();
        assert!(db.ref_get("nope").is_err());
    }

    #[test]
    fn ref_list() {
        let db = open_db();
        let hashes = write_blobs(&db, &["x"]);
        let c = db.commit_create(&hashes, "init", None, None, &HashMap::new()).unwrap();

        db.ref_set("main", &c.hash).unwrap();
        let refs = db.ref_list().unwrap();
        // HEAD + main = 2
        assert_eq!(refs.len(), 2);
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
}
