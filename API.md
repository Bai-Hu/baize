# 白泽 API 手册

> 基于 `crates/baize-server/src/api.rs` 源码自动核对，最后更新：2026-06-02

协议: HTTP/1.1, JSON
基础路径: `/api/v2`
认证: **所有端点强制 Ed25519 签名**

---

# 认证

所有 v2 请求必须携带以下头：

```
x-agent-id: <agent-id>
x-timestamp: <ISO-8601-RFC3339>
x-signature: ed25519:<hex-signature>
```

可选重放防护头：

```
x-nonce: <unique-string>
```

| 场景 | HTTP 状态 | error-type |
|------|-----------|------------|
| 缺少签名头 | 401 | missing x-agent-id / x-timestamp / x-signature |
| 签名验证失败 | 401 | authentication failed |
| 时间戳超出 ±5 分钟窗口 | 401 | authentication failed |
| nonce 重复使用 | 409 | nonce already used |
| nonce 缓存窗口 | - | 5 分钟 |
| 密钥未找到 | 401 | no signing key found for agent |

> v2 **仅接受** Ed25519 签名（`ed25519:` 前缀），不接受 HMAC-SHA256。

## 签名生成

```
签名输入 = "<timestamp>\n<method>\n<path>\n<body>"
签名输出 = ed25519:<hex( Ed25519.sign(signing_key, 签名输入) )>
```

> **注意**: 签名输入中的 `<path>` 仅包含 URI path 部分，不含 query string。GET 请求 body 为空字符串。

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import datetime, json

def sign_request_ed25519(private_key_bytes: bytes, method: str, path: str, body_dict: dict):
    """Ed25519 签名"""
    timestamp = datetime.datetime.utcnow().isoformat() + "Z"
    body_str = json.dumps(body_dict, separators=(',', ':')) if body_dict else ""
    input_str = f"{timestamp}\n{method}\n{path}\n{body_str}"
    private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    sig = private_key.sign(input_str.encode())
    return {
        "x-agent-id": "alice",
        "x-timestamp": timestamp,
        "x-signature": f"ed25519:{sig.hex()}",
    }
```

密钥获取: 通过 INF-KMS `IDN_SIGN` 用途密钥，解密后提取 Ed25519 私钥（PKCS#8 PEM 格式）。

## 密钥体系

白泽使用两套独立的密码系统，分别服务于不同目的：

| 系统 | 算法 | KMS 用途密钥 | 用途 |
|------|------|-------------|------|
| API 请求签名 | Ed25519 | `IDN_SIGN` | HTTP 请求认证（本节描述的签名机制） |
| X.509 证书签发 | ECDSA P-256 | `cert-sign` | Agent 身份证书链 |

- **Ed25519 / `IDN_SIGN`**: 每个 agent 注册时自动生成，用于对所有 API 请求进行签名认证。私钥为 PKCS#8 格式的 32 字节 seed。
- **ECDSA P-256 / `cert-sign`**: 每个 agent 注册时自动生成，用于签发 X.509 身份证书。Agent 注册响应中的 `cert_pem` 即由此密钥签发。

两套密钥完全独立，互不替代。API 签名验证**仅使用** Ed25519 密钥。

其他 KMS 用途密钥（均基于 Ed25519）：

| 用途密钥 | 说明 |
|---------|------|
| `INT_SIGN` | 意图签名 |
| `AZN_SIGN` | 授权签名 |
| `RCT_SIGN` | 回执签名 |
| `SESSION` | 会话密钥 |

---

# 错误响应

所有错误返回统一格式：

```json
{ "error": "<error-type>" }
```

| HTTP 状态 | error-type | 含义 |
|-----------|-----------|------|
| 400 | validation failed | 请求参数不合法 |
| 400 | constraint violation | 约束收缩校验失败 |
| 400 | chain broken | 引用的链上 blob 不存在或类型不匹配 |
| 400 | certificate error | 证书相关错误 |
| 401 | missing x-agent-id header | 缺少认证头 |
| 401 | authentication failed | 签名验证失败或时间戳过期 |
| 403 | permission denied | 权限不足（zone/level） |
| 403 | proof required | L3+ 敏感操作需要运行态证明 |
| 403 | approval rejected | 审批请求被驳回 |
| 404 | not found | 资源不存在 |
| 409 | conflict | 资源冲突（如重复创建、nonce 已使用） |
| 409 | key rotation error | 密钥轮换失败 |
| 410 | channel closed | 通道已关闭 |
| 410 | credential expired | 凭证已过期 |
| 410 | intent expired | 意图已过期 |
| 410 | authorization expired | 授权已过期 |
| 422 | user decision required | 需要用户决策 |
| 500 | internal error | 内部错误 |
| 503 | nonce cache full, retry later | nonce 缓存已满 |

---

# 端点总览

| 方法 | 路径 | 说明 |
|------|------|------|
| | **Agent 管理** | |
| POST | /api/v2/agents | 注册 Agent |
| GET | /api/v2/agents | 列出 Agent |
| DELETE | /api/v2/agents/{id} | 撤销 Agent |
| GET | /api/v2/agents/{id}/status | 查询凭证状态 |
| PUT | /api/v2/agents/{id}/status | 更新凭证状态 |
| POST | /api/v2/agents/{id}/proof | 生成运行态证明 |
| GET | /api/v2/agents/{id}/proof/verify | 验证运行态证明 |
| POST | /api/v2/agents/{id}/keys/rotate | 密钥轮换 |
| | **Blob 操作** | |
| POST | /api/v2/blobs | 写入 Blob |
| GET | /api/v2/blobs/{hash} | 读取 Blob |
| POST | /api/v2/blobs/query | 查询 Blob |
| | **文件操作** | |
| POST | /api/v2/files/{path} | 写入文件 |
| GET | /api/v2/files/{path} | 读取文件 |
| DELETE | /api/v2/files/{path} | 删除文件 |
| GET | /api/v2/files | 列出文件 |
| | **Push / Pull** | |
| POST | /api/v2/push | Push（workspace → 主仓库工作区） |
| POST | /api/v2/pull | Pull（主仓库工作区 → workspace） |
| | **Git 操作** | |
| GET | /api/v2/log | 查看 Git 日志 |
| GET | /api/v2/refs | 列出 Ref |
| GET | /api/v2/refs/{name} | 获取 Ref |
| PUT | /api/v2/refs/{name} | 设置 Ref |
| DELETE | /api/v2/refs/{name} | 删除 Ref |
| | **Label 操作** | |
| POST | /api/v2/labels | 添加 Label |
| GET | /api/v2/labels/query | 查询 Label |
| | **借权（Elevation）** | |
| POST | /api/v2/elevation | 申请借权 |
| GET | /api/v2/elevation | 列出借权记录 |
| POST | /api/v2/elevation/{id}/approve | 审批借权 |
| POST | /api/v2/elevation/{id}/return | 归还借权 |
| | **追溯** | |
| GET | /api/v2/trace/identity/{id} | 身份追溯 |
| | **导入 / 导出** | |
| POST | /api/v2/import | 导入外部数据 |
| GET | /api/v2/export/{hash} | 导出数据 |
| | **审计** | |
| GET | /api/v2/audit | 查询审计日志（含链信息） |
| POST | /api/v2/audit/verify-chain | 验证审计哈希链 |
| | **仓库统计** | |
| GET | /api/v2/repo/stats | 仓库统计 |
| | **意图管理（INT）** | |
| POST | /api/v2/intents | 创建意图 |
| POST | /api/v2/intents/derive | 派生子意图 |
| GET | /api/v2/intents/{hash} | 读取意图 |
| GET | /api/v2/intents | 查询意图 |
| | **回执管理（RCT）** | |
| POST | /api/v2/receipts | 创建回执 |
| GET | /api/v2/receipts/{hash} | 读取回执 |
| GET | /api/v2/receipts | 查询回执 |
| | **授权管理（AZN）** | |
| POST | /api/v2/authorizations | 签发授权 |
| POST | /api/v2/authorizations/delegate | 委托授权 |
| GET | /api/v2/authorizations/{hash} | 读取授权 |
| POST | /api/v2/authorizations/{hash}/verify | 验证授权（AZN-VER） |
| | **会话管理（LNK）** | |
| POST | /api/v2/sessions | 创建会话 |
| POST | /api/v2/sessions/{id}/accept | 接受会话 |
| GET | /api/v2/sessions/{id} | 读取会话 |
| POST | /api/v2/sessions/{id}/close | 关闭会话 |
| POST | /api/v2/sessions/{id}/message | 会话内加密消息（v2 专用） |
| | **收敛验证（CNV）** | |
| POST | /api/v2/cnv/verify | CNV 全链路校验 |
| | **审批管理** | |
| GET | /api/v2/approval/pending | 列出待审批请求 |
| GET | /api/v2/approval/requests/{id} | 查看审批请求详情 |
| POST | /api/v2/approval/requests/{id}/approve | 审批通过 |
| POST | /api/v2/approval/requests/{id}/reject | 驳回请求 |
| POST | /api/v2/approval/requests/{id}/escalate | 越权上报 |
| GET | /api/v2/approval/preauth | 列出预授权 |
| POST | /api/v2/approval/preauth | 创建预授权 |
| DELETE | /api/v2/approval/preauth/{id} | 删除预授权 |
| GET | /api/v2/approval/policy | 查看审批策略 |
| PUT | /api/v2/approval/policy | 更新审批策略（仅 root） |

---

# Agent 管理

## 注册 Agent

```
POST /api/v2/agents
```

**请求体**:
```json
{
  "name": "agent-name",
  "level": 3,
  "zones": ["zone-a", "zone-b"],
  "parent_id": "baize-root"
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| name | string | 是 | Agent 名称，全局唯一标识 |
| level | u8 | 是 | 权限等级 0-4 |
| zones | string[] | 是 | 可操作的 zone 列表，`["*"]` 表示全部 |
| parent_id | string | 否 | 父 agent ID，默认为 root |

**成功响应** `201 Created`:
```json
{
  "id": "agent-name",
  "agent_id": "agent-name",
  "level": 3,
  "zones": ["zone-a", "zone-b"],
  "cert_pem": "-----BEGIN CERTIFICATE-----\n..."
}
```

**权限规则**:
- 签名者（x-agent-id）必须是 root 或指定的 parent_id
- 签名者的 level 必须 **严格大于** 新 agent 的 level（root 豁免）
- 子 agent 的 level 必须 < 父 agent 的 level
- 子 agent 的 zones 必须是父 agent zones 的子集
- 名称不可重复

## 列出 Agent

```
GET /api/v2/agents
```

**响应** `200 OK`:
```json
[
  {
    "id": "baize-root",
    "level": 4,
    "zones": ["*"],
    "parent_id": null
  }
]
```

## 撤销 Agent

```
DELETE /api/v2/agents/{id}
```

**响应**: `204 No Content`（成功）或错误。

**权限规则**:
- 签名者必须是 root 或目标 agent 的 parent
- root agent 不可撤销
- 撤销会销毁该 agent 的所有密钥

## 查询凭证状态

```
GET /api/v2/agents/{id}/status
```

**响应** `200 OK`:
```json
{ "agent_id": "agent-name", "status": "active" }
```

状态枚举: `active` / `suspended` / `revoked` / `expired`

## 更新凭证状态

```
PUT /api/v2/agents/{id}/status
```

**请求体**:
```json
{ "status": "suspended", "reason": "安全审查" }
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| status | string | 是 | 目标状态: `active` / `suspended` / `revoked` / `expired` |
| reason | string | 否 | 变更原因 |

**状态机**: Active → Suspended/Revoked, Suspended → Active/Revoked

**响应** `200 OK`: `{ "agent_id": "...", "status": "suspended" }`

## 生成运行态证明（IDN-ATH）

```
POST /api/v2/agents/{id}/proof
```

**请求体**:
```json
{
  "instance_state_attributes": {
    "instance_id": "host-01",
    "instance_status": "running"
  },
  "proof_anchor_mode": "CREDENTIAL_ANCHORED"
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| instance_state_attributes | object | 否 | 实例状态属性，默认 `{ instance_id: <agent_id>, instance_status: "running" }` |
| proof_anchor_mode | string | 否 | 锚定模式，默认 `CREDENTIAL_ANCHORED`。可选: `CREDENTIAL_ANCHORED` / `ENVIRONMENT_ANCHORED` |

**成功响应** `201 Created`:
```json
{ "hash": "...", "proof_id": "proof-agent-name-1716806400000", "expires_at": "..." }
```

**规则**: Proof 有效期 5 分钟。L3+ agent 执行敏感操作时必须有有效 proof。

**Proof 强制范围**（`proof_required_for_blob_type`）:
- `authorization`
- `receipt`
- `session-init`
- `session-accept`

> `intent`、`sub-intent`、通用 blob 等类型**不需要** proof。

## 验证运行态证明

```
GET /api/v2/agents/{id}/proof/verify
```

**响应** `200 OK`:
```json
{ "valid": true, "proof_id": "proof-...", "expires_at": "..." }
```

## 密钥轮换（INF-KMS）

```
POST /api/v2/agents/{id}/keys/rotate
```

只有 agent 本人或 `baize-root` 可以轮换。

**请求体**:
```json
{ "purpose": "IDN_SIGN" }
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| purpose | string | 是 | 密钥用途: `IDN_SIGN` / `INT_SIGN` / `AZN_SIGN` / `RCT_SIGN` / `SESSION` / `cert-sign` |

**成功响应** `200 OK`:
```json
{ "agent_id": "...", "purpose": "IDN_SIGN", "new_key_hash": "..." }
```

**规则**: root agent 的 `IDN_SIGN` 密钥不可轮换。

---

# Blob 操作

## 写入 Blob

```
POST /api/v2/blobs
```

**请求体**:
```json
{
  "content": "blob 内容",
  "labels": {
    "key1": "value1"
  }
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| content | string | 是 | Blob 内容 |
| labels | object | 否 | 标签键值对，默认 `{}` |

**成功响应** `201 Created`:
```json
{
  "hash": "a1b2c3d4...",
  "content": "blob 内容",
  "labels": { "key1": "value1" },
  "created_at": "2026-05-16T05:30:00+00:00"
}
```

**规则**:
- 相同内容的重复写入是幂等的（返回已有 blob）
- 新 labels 会合并到已有 labels（冲突的 key 跳过）
- Level 0 agent 不可写入
- 审计自动记录

## 读取 Blob

```
GET /api/v2/blobs/{hash}
```

**响应** `200 OK`: 同写入响应格式。hash 不存在返回 `404`。

## 查询 Blob

```
POST /api/v2/blobs/query
```

**请求体**:
```json
{
  "labels": { "key1": "value1" },
  "limit": 50,
  "offset": 0
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| labels | object | 是 | 查询条件，AND 语义 |
| limit | uint | 否 | 返回数量上限 |
| offset | uint | 否 | 跳过前 N 条记录 |

**响应** `200 OK`: Blob 数组。

---

# 文件操作

## 写入文件

```
POST /api/v2/files/{path}
```

**请求体**:
```json
{ "content": "文件内容", "labels": { "key1": "value1" } }
```

**成功响应** `201 Created`:
```json
{ "path": "config/app.yaml", "hash": "sha256...", "size": 1024 }
```

## 读取文件

```
GET /api/v2/files/{path}
```

**响应** `200 OK`:
```json
{ "path": "config/app.yaml", "content": "文件内容", "hash": "sha256...", "size": 1024 }
```

## 删除文件

```
DELETE /api/v2/files/{path}
```

**响应**: `204 No Content`。

## 列出文件

```
GET /api/v2/files
```

**响应** `200 OK`: `{ "files": ["config/app.yaml", "data/log.txt"] }`

## Zone 规则

文件路径的第一段（`/` 之前）视为 zone。例如：
- `config/app.yaml` — 根级文件，所有 agent 可访问
- `A/data.txt` — zone A，需要 agent scope 包含 `"A"` 或 `"*"`

---

# Push / Pull

> **术语澄清**: 白泽的 push/pull 是 **workspace ↔ 主仓库** 之间的文件同步操作，**不是** git push/pull。
> - **push**: 将 agent workspace 中的文件发布到主仓库工作区（workspace → main repo），可能触发审批流程
> - **pull**: 将主仓库工作区的文件同步到 agent workspace（main repo → workspace），会先清空 workspace
> - 主仓库本身是一个 Git 仓库，但 push/pull 操作 **不会自动产生 git commit**，需要通过 Git 操作单独管理

## Push（workspace → 主仓库工作区）

```
POST /api/v2/push
```

**请求体**:
```json
{
  "message": "提交描述",
  "ref": "shared"
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| message | string | 是 | 提交描述 |
| ref | string | 否 | 目标 ref（保留字段） |

**成功响应** `201 Created`:
```json
{ "files": 3, "pending": true }
```

## Pull（主仓库工作区 → workspace）

```
POST /api/v2/pull
```

**请求体**:
```json
{ "ref": "shared" }
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| ref | string | 否 | 来源 ref（保留字段） |

**成功响应** `200 OK`:
```json
{ "files": 3 }
```

**注意**: pull 会清空 workspace。

---

# Git 操作

## 查看 Git 日志

```
GET /api/v2/log?limit=50
```

| 参数 | 必填 | 说明 |
|------|------|------|
| limit | 否 | 返回数量上限，默认 50，最大 200 |

**响应** `200 OK`:
```json
{
  "commits": [
    { "hash": "...", "message": "...", "author": "...", "time": "..." }
  ]
}
```

## 列出 Ref

```
GET /api/v2/refs
```

**响应** `200 OK`: `{ "refs": ["main", "stable"] }`

## 获取 Ref

```
GET /api/v2/refs/{name}
```

**响应** `200 OK`: `{ "name": "stable", "oid": "a1b2c3..." }`

## 设置 Ref

```
PUT /api/v2/refs/{name}
```

**请求体**: `{ "oid": "git-commit-oid" }`

**响应**: `204 No Content`

## 删除 Ref

```
DELETE /api/v2/refs/{name}
```

**响应**: `204 No Content`。`HEAD` 不可删除。

---

# Label 操作

## 添加 Label

```
POST /api/v2/labels
```

**请求体**:
```json
{
  "entity_hash": "blob-hash",
  "key": "label-key",
  "value": "label-value"
}
```

**响应**: `201 Created`（无 body）。同一 (entity_hash, key) 重复添加返回 `409 Conflict`。

## 查询 Label

```
GET /api/v2/labels/query?key=<key>&value=<value>
```

| 参数 | 必填 | 说明 |
|------|------|------|
| key | 是 | Label key |
| value | 否 | Label value |

**响应** `200 OK`:
```json
{
  "labels": [
    { "entity_hash": "...", "key": "env", "value": "production" }
  ]
}
```

---

# 借权（Elevation）

## 申请借权

```
POST /api/v2/elevation
```

**请求体**:
```json
{
  "agent_id": "agent-name",
  "zones": ["zone-a"],
  "mode": "readonly",
  "reason": "申请原因",
  "duration": "2h"
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| agent_id | string | 是 | 申请借权的 agent |
| zones | string[] | 是 | 申请访问的 zone 列表 |
| mode | string | 是 | `"readonly"` / `"write"` / `"readwrite"` |
| reason | string | 是 | 申请原因 |
| duration | string | 否 | 有效时长，格式 `<数字><单位>`，如 `"30m"` `"2h"` |

**成功响应** `201 Created`:
```json
{ "request_id": "..." }
```

## 审批借权

```
POST /api/v2/elevation/{id}/approve
```

**响应** `200 OK`: `{ "status": "approved" }`

**规则**:
- root 可审批任何请求
- 非 root 只能审批自己的子 agent，且请求的 zones 不能超出审批人自身 scope

## 归还借权

```
POST /api/v2/elevation/{id}/return
```

**请求体**: `{ "agent_id": "agent-name" }`

**响应** `200 OK`: `{ "status": "returned" }`

## 列出借权记录

```
GET /api/v2/elevation
```

**响应** `200 OK`:
```json
{
  "requests": [
    {
      "id": "...",
      "agent_id": "agent-name",
      "mode": "Readonly",
      "reason": "原因",
      "status": "Approved",
      "created_at": "...",
      "expires_at": "..."
    }
  ]
}
```

> 注意：`mode` 和 `status` 为 Debug 格式输出（PascalCase），如 `Readonly`、`Approved`。

---

# 追溯（Trace）

## 身份追溯

```
GET /api/v2/trace/identity/{id}
```

**响应** `200 OK`:
```json
{
  "chain": [
    { "agent_id": "child", "parent_id": "parent", "level": 2, "zones": ["zone-a"] },
    { "agent_id": "parent", "parent_id": null, "level": 4, "zones": ["*"] }
  ]
}
```

---

# 导入 / 导出

## 导入外部数据

```
POST /api/v2/import
```

**请求体**:
```json
{
  "content": "外部数据内容",
  "source": "数据来源标识",
  "trust_level": 1,
  "labels": { "key": "value" }
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| content | string | 是 | 数据内容 |
| source | string | 是 | 来源标识 |
| trust_level | u8 | 否 | 信任级别 0-4，默认 2 |
| labels | object | 否 | 附加标签 |

**成功响应** `201 Created`:
```json
{ "hash": "...", "trust_level": 1 }
```

**规则**: trust_level 不可超过 agent 自身 level。

## 导出数据

```
GET /api/v2/export/{hash}
```

**响应** `200 OK`:
```json
{
  "hash": "...",
  "content": "数据内容",
  "labels": { ... }
}
```

---

# 审计

## 查询审计日志（含链信息）

```
GET /api/v2/audit
```

支持查询参数过滤：

| 参数 | 说明 |
|------|------|
| agent | 按操作 agent 过滤 |
| type | 按操作类型过滤（如 `blob_write`、`push`、`file_write`） |

**响应** `200 OK`:
```json
{
  "records": [
    {
      "hash": "...",
      "type": "blob_write",
      "agent": "agent-name",
      "result": "success",
      "target": "config/app.yaml",
      "time": "2026-05-16T05:30:00+00:00",
      "chain_index": 5,
      "prev": "..."
    }
  ]
}
```

## 验证审计哈希链

```
POST /api/v2/audit/verify-chain
```

**响应** `200 OK`:
```json
{
  "valid": true,
  "chain_length": 42,
  "head_digest": "...",
  "genesis_digest": "...",
  "errors": []
}
```

---

# 仓库统计

```
GET /api/v2/repo/stats
```

**响应** `200 OK`:
```json
{ "total_blobs": 42, "total_commits": 10, "total_refs": 3 }
```

---

# 意图管理（INT）

## 创建意图

```
POST /api/v2/intents
```

**请求体**:
```json
{
  "content": "<IntentContent JSON 字符串>"
}
```

`content` 字段为 **JSON 字符串**，内部结构（`IntentContent`）：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| intent_id | string | 是 | 意图唯一标识 |
| intent_owner | string | 是 | 意图所有者 agent |
| intent_creator | string | 是 | 意图创建者 agent |
| task_id | string | 否 | 关联任务 ID |
| intent_goal | string | 是 | 意图目标描述 |
| intent_constraints | object | 是 | 意图约束（**必须非空且非 null**） |
| intent_preferences | object | 否 | 意图偏好 |
| origin_input_digest | string | 否 | 原始输入摘要 |
| origin_input_excerpt | string | 否 | 原始输入摘录 |
| version | string | 是 | 协议版本 |
| created_at | string | 是 | 创建时间（RFC3339） |
| expires_at | string | 是 | 过期时间（RFC3339），必须 > created_at |

**系统自动从 content 中提取 labels**: `type=intent`, `x-intent-id`, `x-intent-owner`, `x-intent-status=active`, `x-intent-expires`。

**成功响应** `201 Created`:
```json
{ "hash": "..." }
```

**校验规则**:
- `intent_constraints` 必须非空（不能是 `null`、`{}`）
- `expires_at` 必须 > `created_at`（DateTime 比较而非字符串比较）
- `intent_id` 在 active 状态下全局唯一
- 有效期运行时检查：过期意图直接拒绝

## 派生子意图

```
POST /api/v2/intents/derive
```

**请求体**:
```json
{
  "content": "<SubIntentContent JSON 字符串>"
}
```

`content` 内部结构（`SubIntentContent`）：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| sub_intent_id | string | 是 | 子意图唯一标识 |
| parent_intent_digest | string | 是 | 父意图 blob hash |
| deriver_id | string | 是 | 派生者 agent |
| subject | string | 是 | 子意图主题 |
| derivation_depth | u32 | 是 | 必须等于父 depth + 1 |
| derivation_basis | string | 否 | 派生依据 |
| intent_goal | string | 是 | 子意图目标 |
| intent_constraints | object | 是 | 子意图约束（**必须非空**） |
| created_at | string | 是 | 创建时间 |
| expires_at | string | 是 | 过期时间，不晚于父 expires_at |

**校验规则**:
- 父意图必须存在且 type 为 `intent` 或 `sub-intent`
- 父意图不能已过期
- 约束必须收缩（子 ≤ 父，逐维度比较）
- `derivation_depth` = 父 depth + 1
- 子意图 `expires_at` 不晚于父 `expires_at`（DateTime 比较）

**约束收缩校验细节**:
- **数组维度**（如 `target_scope`）: 子集检查
- **数值维度**（如 `max_budget`）: 子 ≤ 父
- **对象维度**: 递归比较各字段
- **字符串维度**: 严格等值
- **布尔维度**: 父=false 时子不能=true
- 父约束中不存在的维度: 视为不限制

## 读取意图

```
GET /api/v2/intents/{hash}
```

**响应** `200 OK`:
```json
{ "hash": "...", "content": "...", "labels": {...}, "created_at": "..." }
```

## 查询意图

```
GET /api/v2/intents?status=active&owner=commander
```

| 参数 | 说明 |
|------|------|
| status | 按状态过滤（如 `active`） |
| owner | 按所有者过滤 |

**响应** `200 OK`:
```json
{
  "intents": [
    { "hash": "...", "intent_id": "...", "owner": "...", "status": "active", "expires": "..." }
  ]
}
```

---

# 回执管理（RCT）

## 创建回执

```
POST /api/v2/receipts
```

**请求体**:
```json
{
  "content": "<ReceiptContent JSON 字符串>"
}
```

`content` 内部结构（`ReceiptContent`）：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| receipt_id | string | 是 | 回执唯一标识 |
| executor_id | string | 是 | 执行者 agent |
| task_id | string | 是 | 关联任务 ID |
| action_type | string | 是 | 操作类型，**必须在关联授权的 `grant_type` 范围内**（见下方说明） |
| intent_digest | string | 是 | 关联意图 blob hash |
| authorization_digest | string | 是 | 关联授权 blob hash |
| execution_params_digest | string | 否 | 执行参数摘要 |
| result_status | string | 是 | 枚举: `SUCCEEDED` / `FAILED` / `PARTIAL` / `REJECTED` / `CANCELLED` / `EXPIRED` |
| execution_result | string | 否 | 执行结果 |
| rejection_reason | string | 否 | 拒绝原因（result_status 为 `REJECTED` 时必须提供） |
| started_at | string | 是 | 开始时间 |
| finished_at | string | 是 | 结束时间 |
| downstream_receipt_digests | string[] | 否 | 下游回执摘要列表 |

**校验规则**:
- `intent_digest` 必须指向 intent/sub-intent blob
- `authorization_digest` 必须指向 authorization blob
- 授权未过期
- 写入后自动触发 CNV 全链路校验

> **`action_type` 与 `grant_type` 的关联**: Receipt 的 `action_type` 不是自由文本，它必须在关联授权（`authorization_digest` 指向的 blob）的 `grant_type` 范围内。
>
> 匹配规则：`grant_type` 支持逗号分隔的多值（如 `"execute,deploy"`），`action_type` 必须是其中之一。单值时必须严格等值。
>
> 例如：授权的 `grant_type` 为 `"execute"`，则回执的 `action_type` 必须为 `"execute"`，传 `"evacuation"` 等业务语义字符串会被 CNV 校验拒绝（400 constraint violation）。
>
> **INT → AZN → RCT 链路贯通校验**：回执创建后，服务端自动执行 CNV 全链路校验，追溯意图链、验证授权有效性、检查 `action_type` 是否在 `grant_type` 范围内。任何一项不通过，回执写入会被回滚。

## 读取回执

```
GET /api/v2/receipts/{hash}
```

**响应** `200 OK`: `{ "hash": "...", "content": "...", "labels": {...}, "created_at": "..." }`

## 查询回执

```
GET /api/v2/receipts?executor=agent-name&status=SUCCEEDED
```

| 参数 | 说明 |
|------|------|
| executor | 按执行者过滤 |
| status | 按状态过滤 |

---

# 授权管理（AZN）

## 签发授权

```
POST /api/v2/authorizations
```

**请求体**:
```json
{
  "content": "<AuthorizationContent JSON 字符串>"
}
```

`content` 内部结构（`AuthorizationContent`）：

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| authorization_id | string | 是 | 授权唯一标识 |
| issuer | string | 是 | 签发者 agent |
| subject | string | 是 | 被授权者 agent |
| grant_type | string | 是 | 授权类型（如 `execute`） |
| constraints | AuthzConstraints | 是 | 授权约束（**必须非空**） |
| delegatable | bool | 是 | 是否可委托 |
| delegation_depth_remaining | u32 | 否 | 委托深度剩余 |
| delegation_mode | string | 否 | 枚举: `SPECIFIED` / `BOUNDED`（SCREAMING_SNAKE_CASE） |
| source_intent_digest | string | 是 | 源意图 blob hash |
| parent_authz_digest | string | 否 | 父授权 blob hash（委托时必填） |
| root_authorizer | string | 是 | 根授权者 |
| aud | string[] | 否 | 受众列表 |
| nbf | string | 是 | 生效时间（RFC3339） |
| exp | string | 是 | 过期时间（RFC3339），不晚于意图 expires_at |
| iat | string | 是 | 签发时间 |
| jti | string | 是 | JWT ID |
| version | string | 是 | 协议版本 |

**AuthzConstraints 结构**:

| 字段 | 类型 | 说明 |
|------|------|------|
| target_scope | Value | 目标范围（如 `["deploy"]`） |
| amount_scope | Value | 数量约束（如 `{"max_budget": 500}`） |
| time_scope | Value | 时间约束 |
| method_scope | Value | 方法约束 |
| environment_scope | Value | 环境约束 |
| behavior_scope | Value | 行为约束 |
| cumulative_limit | Value | 累积限制 |

> `constraints` 必须非空（不能是 `{}`），至少包含一个维度。

**校验规则**:
- `source_intent_digest` 必须指向有效且未过期的 intent
- `constraints` 必须非空
- 签发方凭证未被 revoked/suspended/expired
- `exp` 不晚于意图 `expires_at`（DateTime 比较）
- L3+ agent 写入 authorization 时需要有效的运行态证明（proof）

## 委托授权

```
POST /api/v2/authorizations/delegate
```

**请求体**: 同签发授权结构，但必须包含 `parent_authz_digest`。

**额外校验规则**:
- 父授权状态为 `valid`
- 约束收缩（子 ≤ 父，同意图约束收缩逻辑）
- `delegation_depth_remaining` = 父 - 1
- `root_authorizer` 一致
- 父 `delegatable` = true

## 读取授权

```
GET /api/v2/authorizations/{hash}
```

**响应** `200 OK`: `{ "hash": "...", "content": "...", "labels": {...}, "created_at": "..." }`

## 验证授权（AZN-VER）

```
POST /api/v2/authorizations/{hash}/verify
```

**请求体**:
```json
{
  "action_type": "execute",
  "subject": "agent-name",
  "target": { "zone": "deploy" },
  "amount": 300.0,
  "environment": "production"
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| action_type | string | 是 | 操作类型 |
| subject | string | 否 | 被授权者 |
| target | Value | 否 | 执行目标 |
| amount | f64 | 否 | 执行金额 |
| environment | string | 否 | 执行环境 |

**响应** `200 OK`:
```json
{
  "valid": true,
  "checks": {
    "credential_authenticity": true,
    "credential_validity": true,
    "intent_reference": true,
    "delegation_chain": true,
    "execution_applicability": true
  },
  "errors": []
}
```

AZN-VER 五项校验: 凭证真实性、凭证有效性、意图引用、委托链、执行适用性。

---

# 会话管理（LNK）

## 创建会话

```
POST /api/v2/sessions
```

**请求体**:
```json
{
  "session_id": "sess-001",
  "peer_a": "alice",
  "peer_b": "bob",
  "ephemeral_pub": "<X25519-public-key-PEM>",
  "cipher_suites": ["AES-256-GCM"],
  "credential_digest_a": "<hash>",
  "credential_digest_b": "<hash>",
  "handshake_transcript_digest": "<hash>",
  "expires_at": "2099-12-31T23:59:59Z"
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| session_id | string | 是 | 会话 ID，全局唯一 |
| peer_a | string | 是 | 发起方 agent |
| peer_b | string | 是 | 接收方 agent（必须已注册） |
| ephemeral_pub | string | 是 | 发起方 X25519 临时公钥（**PEM 格式**，见下方说明） |
| cipher_suites | string[] | 是 | 密码套件列表（须包含 `AES-256-GCM`） |
| credential_digest_a | string | 是 | 发起方凭证摘要 |
| credential_digest_b | string | 是 | 接收方凭证摘要 |
| handshake_transcript_digest | string | 是 | 握手记录摘要 |
| expires_at | string | 否 | 过期时间，默认 30 分钟 |

**成功响应** `201 Created`:
```json
{ "hash": "...", "session_id": "sess-001", "peer_a": "alice", "peer_b": "bob", "status": "active" }
```

> **`ephemeral_pub` 格式要求**:
>
> 服务端使用 `decode_x25519_public()` 解码，期望 **PEM 格式**（含 header/footer 行），而非裸 base64 字符串。
>
> 正确格式（由 `generate_x25519_keypair()` 生成）:
> ```
> -----BEGIN X25519 PUBLIC KEY-----
> <标准 base64，44 字符（含 padding =）>
> -----END X25519 PUBLIC KEY-----
> ```
>
> 错误格式（会被拒绝）:
> - 裸 base64 无 padding: `rbo1uB7guZMBnDQAjq7O1YY1w7xQhOdE5mGvJKtVKnU`（base64 解码失败）
> - PKIX PEM: `-----BEGIN PUBLIC KEY-----...`（header 不匹配）
> - 任意字符串: `base64x25519pubkeyA`（不是合法 base64）
>
> **生成方式**: 调用 `generate_x25519_keypair()` 获取 `(private_pem, public_pem)`，将 `public_pem` 作为 `ephemeral_pub` 传入。

> **`peer_b` 必须已注册**: `peer_b` 对应的 agent 必须在系统中完成注册（有 agent-cert 或 root-ca blob），否则返回 400 validation failed。

## 接受会话

```
POST /api/v2/sessions/{id}/accept
```

**请求体**:
```json
{
  "credential_digest_responder": "<hash>",
  "ephemeral_pub": "<X25519-public-key-PEM>",
  "selected_cipher_suite": "AES-256-GCM",
  "handshake_transcript_digest": "<hash>",
  "expires_at": "..."
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| credential_digest_responder | string | 是 | 响应方凭证摘要 |
| ephemeral_pub | string | 是 | 响应方 X25519 临时公钥（PEM 格式，同 session-create 要求） |
| selected_cipher_suite | string | 是 | 选择的密码套件 |
| handshake_transcript_digest | string | 是 | 握手记录摘要 |
| expires_at | string | 否 | 过期时间 |

**成功响应** `201 Created`:
```json
{ "hash": "...", "session_id": "sess-001", "status": "active" }
```

**规则**: 只有 peer_b 可以接受；每个 session 只能 accept 一次。

## 读取会话

```
GET /api/v2/sessions/{id}
```

**响应** `200 OK`: `{ "session_id": "...", "content": "...", "labels": {...}, "created_at": "..." }`

## 关闭会话

```
POST /api/v2/sessions/{id}/close
```

**请求体**:
```json
{ "reason": "task completed" }
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| reason | string | 否 | 关闭原因 |

**成功响应** `201 Created`:
```json
{ "hash": "...", "session_id": "sess-001", "status": "closed" }
```

**规则**: 已关闭的 session 不能再次关闭（`409 Conflict`）。

## 会话内加密消息（LNK-DTX）

```
POST /api/v2/sessions/{id}/message
```

**请求体**:
```json
{
  "ciphertext": "<encrypted-message>",
  "seq": 1
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| ciphertext | string | 是 | 加密消息内容（服务端不解密，只记录密文） |
| seq | u64 | 是 | 消息序列号（必须单调递增） |

**成功响应** `201 Created`:
```json
{ "hash": "...", "session_id": "...", "seq": 1 }
```

> **前置条件**: 发送消息前，会话必须已被 peer_b 通过 `/api/v2/sessions/{id}/accept` 接受（状态为 `active`）。在 `init` 状态下发送消息将返回 `400 validation failed`。会话生命周期严格为：`init`（创建）→ `active`（接受）→ 发送消息 → `closed`（关闭）。

---

# 收敛验证（CNV）

```
POST /api/v2/cnv/verify
```

**请求体**:
```json
{ "receipt_digest": "<hash>" }
```

**响应** `200 OK`:
```json
{
  "valid": true,
  "intent_chain": [
    { "hash": "...", "intent_id": "...", "depth": 0, "valid": true }
  ],
  "authorization_chain": [
    {
      "authz_found": true,
      "issuer_valid": true,
      "source_intent_match": true,
      "delegation_chain_valid": true
    }
  ],
  "errors": []
}
```

---

# 审批管理

## 列出待审批请求

```
GET /api/v2/approval/pending
```

列出当前 agent 需要审批的请求。

**响应** `200 OK`:
```json
{
  "requests": [
    {
      "id": "...",
      "requester_id": "...",
      "requester_level": 2,
      "action": "blob_write",
      "status": "pending",
      "created_at": "..."
    }
  ]
}
```

## 查看审批请求详情

```
GET /api/v2/approval/requests/{id}
```

**响应** `200 OK`:
```json
{
  "id": "...",
  "requester_id": "...",
  "requester_level": 2,
  "action": "blob_write",
  "status": "pending",
  "pending_at": "...",
  "granted_count": 0,
  "remaining_count": 1,
  "created_at": "...",
  "expires_at": "...",
  "chain": [
    {
      "agent_id": "...",
      "level": 3,
      "decision": "granted",
      "note": "...",
      "decided_at": "..."
    }
  ]
}
```

## 审批通过

```
POST /api/v2/approval/requests/{id}/approve
```

**请求体**:
```json
{ "granted_count": 1, "note": "approved" }
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| granted_count | u32 | 是 | 授予的操作次数 |
| note | string | 否 | 审批备注 |

**响应** `200 OK`: `{ "request_id": "...", "status": "approved" }`

## 驳回请求

```
POST /api/v2/approval/requests/{id}/reject
```

**请求体**:
```json
{ "reason": "不符合策略" }
```

**响应** `200 OK`: `{ "request_id": "...", "status": "rejected" }`

## 越权上报

```
POST /api/v2/approval/requests/{id}/escalate
```

**请求体**:
```json
{ "reason": "需要更高级别审批" }
```

**响应** `200 OK`: `{ "request_id": "...", "status": "escalated" }`

## 列出预授权

```
GET /api/v2/approval/preauth
```

**响应** `200 OK`:
```json
{
  "preauths": [
    {
      "id": "...",
      "granter_id": "...",
      "grantee_id": "...",
      "action": "blob_write",
      "granted_count": 10,
      "remaining_count": 7,
      "created_at": "..."
    }
  ]
}
```

## 创建预授权

```
POST /api/v2/approval/preauth
```

**请求体**:
```json
{
  "grantee_id": "agent-name",
  "action": "blob_write",
  "count": 10
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| grantee_id | string | 是 | 被预授权的 agent |
| action | string | 是 | 操作类型（如 `blob_write`） |
| count | u32 | 是 | 预授权次数 |

**成功响应** `201 Created`:
```json
{
  "id": "...",
  "granter_id": "...",
  "grantee_id": "...",
  "action": "blob_write",
  "granted_count": 10,
  "remaining_count": 10
}
```

## 删除预授权

```
DELETE /api/v2/approval/preauth/{id}
```

仅 root 或授权者可操作。**响应**: `204 No Content`。

## 查看审批策略

```
GET /api/v2/approval/policy
```

**响应** `200 OK`: `{ "rules": [...] }`

## 更新审批策略

```
PUT /api/v2/approval/policy
```

仅 root 可操作。

**请求体**:
```json
{ "rules": [...] }
```

**响应** `200 OK`: `{ "status": "updated" }`

---

# 权限模型

## Level（等级）

| Level | 名称 | 说明 |
|-------|------|------|
| 0 | Isolated | 隔离区，不可写入 |
| 1 | Restricted | 受限操作 |
| 2 | Standard | 标准操作 |
| 3 | Core | 核心操作（敏感操作需 proof） |
| 4 | Root | 最高权限，仅 root agent |

## Zone（区域）

zone 是字符串标签，用于数据隔离。agent 只能操作自己 zone 范围内的数据。
`"*"` 表示通配，root 默认拥有。

## IDN-ATH Proof 机制

- L3+ agent 执行 `authorization`、`receipt`、`session-init`、`session-accept` 写入时，必须持有有效运行态证明
- Proof 有效期 5 分钟
- Root agent 豁免
- Proof 通过 `POST /api/v2/agents/{id}/proof` 生成

---

# 全局规则

1. 所有端点强制 Ed25519 签名认证
2. 子 agent 的 level 必须 **严格小于** 父 agent
3. 子 agent 的 zones 必须 **是父 zones 的子集**（父含 `"*"` 时无限制）
4. blob 是 **鉴权凭证**，不是数据存储
5. 每个 blob 有 `type` label，标明凭证用途
6. 主仓库是 **Git 仓库**，版本管理由 Git 原生提供
7. 白泽 push/pull ≠ git push/pull：push 将 workspace 文件发布到主仓库工作区，pull 将主仓库文件同步到 workspace，两者均不触发 git commit
8. 同一内容的 blob 写入是 **幂等的**
9. 调用者注册子 agent 时，调用者 level 必须 **严格大于** 新 agent level
10. root agent **不可撤销**
11. `HEAD` ref **不可删除**
12. 所有写操作 **自动审计**（通过 `x-audit=true` 的 label 记录）
13. 文件路径首段（`/` 之前）视为 **zone**，受 agent scope 约束
14. 文件操作 Level 0 agent **不可写入**
15. 审计链为**单向哈希链**，包含 `x-audit-prev` 和 `x-audit-chain-index`
