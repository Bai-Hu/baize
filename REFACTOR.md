# 白泽 MVP 重构修复文档

## 背景

对照 MVP.md 设计、REQUIREMENTS.md 需求、泽图协议规范（PROTOCOL_SPEC.md）逐项审查现有实现，发现以下偏差。本文档记录每个偏差的问题、修复方案和优先级。

---

## P0：基础设施修复

### P0-1：标签系统统一

**问题**：当前存在两张标签表 `blob_labels` 和 `labels`，写入和查询互不互通。`blob/write` 写入 `blob_labels`，`label/add` 写入 `labels`。违反协议规范——label 是 blob 的扩展属性，应统一存储。

**修复方案**：

1. 删除 `blob_labels` 表
2. `blob/write` 写入 `labels` 表
3. `blob/read` 从 `labels` 表加载标签
4. `blob/query` 通过 JOIN `labels` 表实现 AND 语义查询
5. `label/add` 保持写入 `labels` 表（已经是）
6. `load_blobs_batch` 批量标签查询改查 `labels` 表

**影响文件**：`crates/baize-core/src/storage.rs`

**Schema 变更**：

```sql
-- 删除
-- CREATE TABLE blob_labels (...);

-- 保留
CREATE TABLE labels (
    entity_hash TEXT NOT NULL,
    key         TEXT NOT NULL,
    value       TEXT NOT NULL,
    PRIMARY KEY (entity_hash, key, value)
);
CREATE INDEX idx_labels_kv ON labels(key, value);
CREATE INDEX idx_labels_hash ON labels(entity_hash);
```

---

### P0-2：借权请求改用 blob + label

**问题**：`elevation_requests` 是独立表，不在泽图协议的 4 种对象内。按协议设计，一切数据都用 blob + label 表达。

**修复方案**：

1. 删除 `elevation_requests` 表及相关存储方法（`elevation_save`、`elevation_update_status`、`elevation_list_all`）
2. 借权申请用 `blob/write` 创建，labels 标记：
   ```
   type: "elevation-request"
   elevation-agent: "<agent_id>"
   elevation-zones: "<JSON zones array>"
   elevation-mode: "ReadOnly" | "WriteOnly" | "ReadWrite"
   elevation-reason: "<reason>"
   elevation-status: "Pending"
   ```
3. 审批用 `label/add` 追加 `elevation-status: "Approved"`（append-only，历史保留）
4. 查询借权列表用 `blob/query`（labels: `{type: "elevation-request"}`）
5. 借权 ID = blob hash（天然唯一）

**影响文件**：`crates/baize-core/src/storage.rs`（删除 ElevationRow 及相关方法）、`crates/baize-server/src/pipeline.rs`

**删除的代码**：

```rust
// storage.rs — 删除
pub struct ElevationRow { ... }
pub fn elevation_save(...) { ... }
pub fn elevation_update_status(...) { ... }
pub fn elevation_list_all(...) { ... }
```

---

### P0-3：五关口管道贯穿所有操作

**问题**：当前只有 `agent_register` 走了 hook 管道。blob_write、commit_create、ref_set 等直接操作 storage，不经管道。审计只在部分操作上。

**修复方案**：

所有泽图写操作（blob/write、commit/create、ref/set、ref/delete、label/add、import、export）经过管道四步：

```
1. 验身份 — 证书验证（确认调用者身份）
2. 查权限 — scope 检查 + 三层决策路由
3. 执行   — 调用 storage 原语
4. 留痕   — 写入审计 blob
```

管道入口统一为 `Baize::execute(operation, agent_id, params)` 或每个方法内部调用管道步骤。

**影响文件**：`crates/baize-server/src/pipeline.rs`、`crates/baize-server/src/hook.rs`

---

### P0-4：证书系统修复

**问题**：

| 问题 | 说明 |
|------|------|
| `verify_chain` 不验签名 | 只查 parent_id 文本匹配，应验证 X.509 签名链 |
| `find_identity_json` 有误匹配风险 | 子串匹配 DER 二进制，应改用 ASN.1 OID 解析 |
| API 不用证书认证 | 用 `x-agent-id` header，应用证书验证身份 |
| `recover_issuer` 签名不一致 | 用 `self_signed` 重建改变了 DER 编码 |

**修复方案**：

1. `verify_chain` 改用 rcgen/x509-parser 的签名验证 API
2. `find_identity_json` 改用 ASN.1 解析按 OID 定位扩展
3. API 层 `extract_agent_id` 改为从请求证书中提取 agent_id（MVP 可先用 `x-agent-id` header + 证书校验的混合模式）
4. `recover_issuer` 使用 `signed_by` 而非 `self_signed` 重建（或存储完整 IssuerCtx 序列化）

**影响文件**：`crates/baize-core/src/cert.rs`、`crates/baize-server/src/api.rs`

**依赖**：可能需要引入 `x509-parser` crate 或使用 rcgen 0.13 的内建解析能力

---

## P1：治理逻辑修复

### P1-1：借权 Zone 限制修复

**问题**：当前实现拒绝了超出 agent scope 的借权申请。但借权的意义就是获取超出 scope 的权限——需要审批，但不应直接拒绝。

**需求文档原文**：

```
① 申请 — 声明需要的 Zone、访问模式、原因、期限
② 审批 — 按层级上报
   请求 ⊆ 父 Agent scope → 父 Agent 审批
   请求超出父 Agent scope → 上报白泽
   请求超出白泽范围    → 上报用户
```

**修复方案**：

1. `elevation_request` 不再检查 zone 是否在 agent scope 内
2. 改为检查 zone 是否在白泽 root scope 内（root 有 "*" 通配，所以默认允许）
3. 审批路由逻辑：请求的 zone 是否在父 agent scope 内？是 → 父 agent 审批；否 → 上报白泽

**影响文件**：`crates/baize-server/src/pipeline.rs`

---

### P1-2：借权到期与归还

**问题**：当前借权只有申请和审批，没有到期回收和归还清理。

**修复方案**：

1. 借权申请支持可选 `duration` 参数（如 "30m"、"1h"）
2. 借权审批后记录 `elevation-expires` label
3. 查询借权状态时检查是否过期，过期则追加 `elevation-status: "Expired"` label
4. 归还流程：调用 `elevation_return(request_id)`
   - 提交 workspace 中最终结果到主仓库
   - 扫描 workspace，清理超出当前 scope 的文件
   - 追加 `elevation-status: "Returned"` label

**影响文件**：`crates/baize-server/src/pipeline.rs`、`crates/baize-core/src/workspace.rs`

---

### P1-3：三层决策模型

**问题**：完全未实现。

**需求文档设计**：

```
Agent 发起操作
    ├── 在 scope 内           → 自主决策（直接执行，事后审计）
    ├── 超出 scope，可借权     → 授权决策（scope elevation，事前审批）
    └── 超出 scope，不可借权   → 用户决策（上报用户确认）
```

**修复方案**：

在管道的 `查权限` 步骤实现：

1. 判断操作类型需要的 scope（如 blob_write 需要 Write 权限到目标 zone）
2. 检查调用者 scope：
   - 在 scope 内 → 直接执行
   - 超出 scope → 自动发起 elevation request（授权决策）
   - 超出 root scope → 返回 NeedUserDecision 错误，CLI/API 层提示用户确认

MVP 阶段简化：
- 所有写操作需要调用者身份
- scope 检查基于 agent 的 level + zones
- 暂不实现细粒度的 per-operation scope 规则

**影响文件**：`crates/baize-server/src/pipeline.rs`、`crates/baize-server/src/hook.rs`

---

## P2：完善项

### P2-1：闭环数据管理——导出审批

**问题**：当前导出没有审批流程。

**修复方案**：导出操作经过管道 scope 检查。如果导出需要超出 scope 的权限，走借权审批。

**影响文件**：随管道修复一起完善。

---

### P2-2：工作目录 scope-aware 清理

**问题**：`clean()` 接收 Scope 参数但完全忽略（`_scope`）。

**修复方案**：`clean()` 实现按 scope 过滤文件：
- 读取 workspace 中所有文件
- 检查每个文件的 zone 标签（文件创建时带 zone label）
- 清理超出当前 scope 的文件

**影响文件**：`crates/baize-core/src/workspace.rs`

---

### P2-3：blob_write 幂等行为完善

**问题**：协议要求"相同 content 已存在时，将新 labels 中不冲突的 key 追加到已有 blob"。当前实现直接返回已有 blob，不合并新 labels。

**修复方案**：`blob_write` 在 blob 已存在时，检查新 labels 中是否有与已有 labels 不冲突的 key，如果有则追加到 labels 表。

**影响文件**：`crates/baize-core/src/storage.rs`

---

## 执行顺序

```
Phase 1: P0-1 标签系统统一 + P0-2 借权改 blob+label
         → storage.rs 重构
         → 运行单元测试确保不回归

Phase 2: P0-3 管道贯穿 + P1-3 三层决策
         → pipeline.rs 重构
         → hook.rs 增强
         → 运行集成测试

Phase 3: P0-4 证书修复
         → cert.rs 修复
         → api.rs 证书认证
         → 运行全量测试

Phase 4: P1-1 借权 zone 修复 + P1-2 到期归还
         → pipeline.rs 借权逻辑
         → workspace.rs 清理
         → 运行 E2E 测试

Phase 5: P2 完善项
```

---

## 预期代码量变化

| 模块 | 当前行数 | 预估变化 | 说明 |
|------|---------|---------|------|
| storage.rs | 903 | -100 | 删除 blob_labels 逻辑、删除 elevation 相关代码 |
| cert.rs | 383 | ±0 | 修复逻辑，行数不变 |
| scope.rs | 210 | +0 | 无修改 |
| workspace.rs | 310 | +20 | clean() 实现 |
| pipeline.rs | 653 | +80 | 管道贯穿 + 三层决策 + 借权逻辑 |
| hook.rs | 204 | +30 | 增强 pre/post hook |
| api.rs | 568 | ±0 | 调整调用方式 |
| main.rs (CLI) | 520 | +30 | 借权归还命令等 |
| **总计** | 3,835 | ~+60 | 净增约 60 行 |
