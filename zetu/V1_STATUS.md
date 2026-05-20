# 白泽 v1 开发现状

> 对照 V1_DEV.md，盘点 v0.1 已实现能力与 v1 待开发能力

---

## 1 已实现（v0.1 基础，可直接复用）

### 1.1 核心存储

| 能力 | 实现位置 | 状态 |
|------|---------|------|
| blob 写入（幂等） | `baize-core/storage.rs` — `blob_write()` | ✅ 完整 |
| blob 读取 | `baize-core/storage.rs` — `blob_read()` | ✅ 完整 |
| blob 查询（label AND） | `baize-core/storage.rs` — `blob_query()` / `blob_query_paginated()` | ✅ 完整 |
| label 追加 | `baize-core/storage.rs` — `label_add()` | ✅ 完整 |
| label 查询 | `baize-core/storage.rs` — `label_query()` | ✅ 完整 |
| SHA-256 content-addressed | `baize-core/storage.rs` | ✅ 完整 |

### 1.2 证书与身份

| 能力 | 实现位置 | 状态 |
|------|---------|------|
| Root CA 自签发 | `baize-core/cert.rs` — `generate_root_ca()` | ✅ 完整 |
| Agent 证书签发 | `baize-core/cert.rs` — `issue_agent()` | ✅ 完整 |
| 证书链验证 | `baize-core/cert.rs` — `verify_chain()` | ✅ 完整 |
| 身份追溯（agent → root） | `baize-server/pipeline/agent_manager.rs` — `trace_identity()` | ✅ 完整 |
| Agent 注册/撤销/列表 | `baize-server/pipeline/agent_manager.rs` | ✅ 完整 |

### 1.3 权限模型

| 能力 | 实现位置 | 状态 |
|------|---------|------|
| Level 0-4 等级 | `baize-core/scope.rs` — `Level` enum | ✅ 完整 |
| Zone 数据隔离 | `baize-core/scope.rs` — `Scope` struct | ✅ 完整 |
| 子集校验（zones/level） | `baize-core/scope.rs` — `is_subset_of()` / `validate_decrease()` | ✅ 完整 |
| 写权限验证 | `baize-server/pipeline/agent_manager.rs` — `verify_write_agent()` | ✅ 完整 |
| 文件 zone 校验 | `baize-server/pipeline/agent_manager.rs` — `verify_file_zone()` | ✅ 完整 |
| 借权（elevation） | `baize-server/pipeline/elevation.rs` | ✅ 完整 |

### 1.4 数据操作

| 能力 | 实现位置 | 状态 |
|------|---------|------|
| blob write（含审计） | `baize-server/pipeline/data_ops.rs` — `pipe_blob_write()` | ✅ 完整 |
| label add（含审计） | `baize-server/pipeline/data_ops.rs` — `pipe_label_add()` | ✅ 完整 |
| 导入/导出 | `baize-server/pipeline/data_ops.rs` — `pipe_import()` / `pipe_export()` | ✅ 完整 |

### 1.5 文件与同步

| 能力 | 实现位置 | 状态 |
|------|---------|------|
| 文件读写删列表 | `baize-server/pipeline/file_sync.rs` | ✅ 完整 |
| Workspace 管理 | `baize-core/workspace.rs` | ✅ 完整 |
| Push（workspace → 主仓库） | `baize-server/pipeline/file_sync.rs` — `pipe_push()` | ✅ 完整 |
| Pull（主仓库 → workspace） | `baize-server/pipeline/file_sync.rs` — `pipe_pull()` | ✅ 完整 |

### 1.6 Git 集成

| 能力 | 实现位置 | 状态 |
|------|---------|------|
| Git log | `baize-server/pipeline/git_ops.rs` | ✅ 完整 |
| Git ref 增删改查 | `baize-server/pipeline/git_ops.rs` | ✅ 完整 |
| 仓库统计 | `baize-server/pipeline/git_ops.rs` — `repo_stats()` | ✅ 完整 |

### 1.7 审计

| 能力 | 实现位置 | 状态 |
|------|---------|------|
| 写操作自动审计 | `baize-server/pipeline/auditor.rs` — `audit()` | ✅ 完整 |
| 审计日志查询 | `baize-server/api.rs` — `GET /audit` | ✅ 完整 |

### 1.8 HTTP API（v0 全部端点）

完整实现 `/api/v0` 下所有端点，见 `baize-server/src/api.rs`。

### 1.9 CLI

完整实现所有 v0 命令，见 `baize-cli/src/main.rs`。

---

## 2 待开发（v1 新增）

### 2.1 新 crate：baize-asl

| 能力 | 说明 | 参考 |
|------|------|------|
| payload.rs | ASL 载荷结构定义（IntentContent, SubIntentContent, ReceiptContent, AuthorizationContent, RuntimeProofContent），字段名统一使用 `_digest` 后缀 | V1_DEV §3.1 |
| adapter.rs | ASL payload ↔ blob+label 双向转换 + binding_context_digest 计算 | V1_DEV §5.2 |
| verify.rs | 约束收缩校验 + CNV 全链路 + AZN-VER 五项校验 | V1_DEV §5.4/§5.5 |

**依赖**：新建 crate，不修改 baize-core。

### 2.2 baize-core 变更

| 能力 | 变更类型 | 说明 |
|------|---------|------|
| `cert.rs` — CredentialStatus 枚举 | 扩展 | 新增 `status: CredentialStatus` 字段到 CertIdentity（Active/Suspended/Revoked/**Expired**，对齐协议 §7.3；`x-cert-expired` label） |
| `labels.rs` | 新增文件 | 集中管理所有 label 常量（v0 + v1，含 IDN-ATT 三组属性映射） |
| `constraint.rs` | 新增文件 | 约束收缩纯函数（verify_intent_constraint_reduction, verify_authz_constraint_reduction） |
| `error.rs` | 扩展 | 新增错误类型（ChannelClosed, ConstraintViolation, ChainBroken, SignatureInvalid 等） |

### 2.3 baize-server 变更

#### 2.3.1 现有模块扩展

| 模块 | 变更 | 说明 |
|------|------|------|
| `agent_manager.rs` | 扩展 | INF-SEE labels（x-see-level 等）、INF-KMS 5 密钥注册（含 x-key-algorithm）、IDN-ATT 属性写入 agent-cert labels、IDN-LCM 凭证生命周期管理（credential_status / update_credential_status）、IDN-TRC 增加凭证状态 |
| `data_ops.rs` | 扩展 | blob write 按 type 分发：intent / sub-intent / receipt / authorization / session-init / session-accept / session 消息校验 |
| `auditor.rs` | 扩展 | 审计哈希链（x-audit-prev + x-audit-chain-index + audit-head blob）、链验证（verify_chain） |
| `api.rs` | 扩展 | v1 路由表（见下文 §2.4） |
| `mod.rs` | 扩展 | Baize struct 新增 `asl: AslContext` 字段 |

#### 2.3.2 新增模块

| 模块 | 说明 |
|------|------|
| `identity.rs` | IDN-ATH：运行态证明生成/过期（短时 5 分钟 blob）、身份鉴别（CRED_ATH 凭证校验 + RTP_ATH 运行态校验两个原子鉴别项） |
| `auth.rs` | 请求签名认证 Axum middleware（HMAC-SHA256，X-Signature + X-Timestamp） |

#### 2.3.3 baize-middleware

v0.1 已有 `baize-middleware` crate（Agent 集成中间件）。v1 不需要修改此 crate，v1 新增能力通过 API 端点暴露，middleware 的调用方式不变。

### 2.4 v0→v1 API 兼容性

v0 全部端点在 `/api/v1` 下继续可用（路由层兼容，不需要重新实现 handler）。v1 新增端点与 v0 端点共存。

### 2.5 v1 新增 API 端点

| 端点 | 说明 |
|------|------|
| `POST /api/v1/intents` | 创建通用意图 |
| `POST /api/v1/intents/derive` | 派生子意图 |
| `GET /api/v1/intents/{digest}` | 读取意图 |
| `GET /api/v1/intents?status=active` | 查询意图 |
| `POST /api/v1/receipts` | 创建执行回执 |
| `GET /api/v1/receipts/{digest}` | 读取回执 |
| `GET /api/v1/receipts?executor={id}` | 查询回执 |
| `POST /api/v1/authorizations` | 签发授权 |
| `POST /api/v1/authorizations/delegate` | 委托子授权 |
| `POST /api/v1/authorizations/{digest}/verify` | 校验授权 |
| `GET /api/v1/authorizations/{digest}` | 读取授权 |
| `POST /api/v1/sessions/{id}/close` | 关闭 session |
| `POST /api/v1/cnv/verify` | 全链路校验 |
| `GET /api/v1/audit` | 查询审计日志（含哈希链信息） |
| `POST /api/v1/audit/verify-chain` | 验证审计哈希链 |
| `GET /api/v1/agents/{id}/status` | 查询凭证状态 |
| `PUT /api/v1/agents/{id}/status` | 更新凭证状态 |
| `POST /api/v1/agents/{id}/proof` | 生成运行态证明 |

### 2.6 v1 新增错误码

| HTTP 状态 | error-type | 说明 |
|-----------|-----------|------|
| 400 | constraint_violation | 约束收缩校验失败 |
| 400 | chain_broken | 链路断裂（digest 不匹配、节点缺失） |
| 401 | invalid_signature | 请求签名验证失败 |
| 401 | expired_timestamp | 请求时间戳超出窗口 |
| 410 | credential_expired | 凭证已过期（expired） |
| 410 | intent_expired | 意图已过期 |
| 410 | authorization_expired | 授权已过期 |
| 410 | session_closed | session 已关闭 |

### 2.7 v1 新增 CLI 命令

| 命令 | 说明 |
|------|------|
| `bz intent create / derive / read / query` | 意图操作 |
| `bz receipt create / read` | 回执操作 |
| `bz authz issue / delegate / verify / read` | 授权操作 |
| `bz session close <id>` | 关闭 session |
| `bz cnv verify --receipt <digest>` | 全链路校验 |
| `bz audit chain-verify` | 审计链验证 |
| `bz agent status / suspend / revoke` | 凭证状态管理（revoke 扩展 reason） |
| `bz agent proof <id>` | 运行态证明 |
| `bz agent register ... --see-level L1` | 注册时声明 SEE 等级 |

### 2.8 新增安全机制

| 能力 | 说明 |
|------|------|
| 请求签名认证 | HMAC-SHA256，X-Agent-ID + X-Timestamp + X-Signature（V1_DEV §4.1） |
| 密钥加密存储 | AES-256-GCM，master secret via 环境变量或命令行（V1_DEV §4.2） |
| 审计哈希链 | 每条审计 blob 携带 x-audit-prev + x-audit-chain-index，链头存于 audit-head blob（V1_DEV §5.6） |

---

## 3 开发优先级建议

### Phase 1：基础设施 + 安全增强

1. `baize-core/labels.rs` — label 常量集中管理
2. `baize-core/error.rs` — 新增错误类型
3. `baize-core/cert.rs` — CredentialStatus 枚举 + CertIdentity.status 字段
4. `baize-server/auth.rs` — 请求签名 middleware
5. `baize-core/crypto.rs` — 密钥加密存储

### Phase 2：ASL 合规层

6. `baize-asl` crate（payload.rs → adapter.rs → verify.rs）
7. `baize-core/constraint.rs` — 约束收缩纯函数
8. `agent_manager.rs` 扩展 — INF labels + IDN-ATT + IDN-LCM + 5 密钥注册
9. `identity.rs` — 运行态证明 + 身份鉴别

### Phase 3：业务能力

10. `data_ops.rs` 扩展 — INT（intent/sub-intent/receipt）type dispatch + 校验
11. `data_ops.rs` 扩展 — AZN（authorization）type dispatch + 校验 + 委托
12. `data_ops.rs` 扩展 — LNK（session-init/session-accept/channel）type dispatch
13. `baize-asl/verify.rs` — CNV 全链路 + AZN-VER 五项校验

### Phase 4：审计增强 + API + CLI

14. `auditor.rs` 扩展 — 审计哈希链 + 链验证
15. `api.rs` 扩展 — v1 路由表全部端点
16. `mod.rs` 扩展 — Baize struct 新增 asl 字段
17. CLI 新增命令
