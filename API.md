# 白泽 API 手册 v0

版本: v0 (MVP)
协议: HTTP/1.1, JSON
基础路径: `/api/v0`
认证: `x-agent-id` 请求头

---

## 认证

写操作（POST/PUT/DELETE）需要在请求头中携带 agent 身份：

```
x-agent-id: <agent-id>
```

缺少此头返回 `401 Unauthorized`。agent 不存在返回 `422 Unprocessable Entity`。

---

## 错误响应

所有错误返回统一格式：

```json
{ "error": "<error-type>" }
```

| HTTP 状态 | error-type | 含义 |
|-----------|-----------|------|
| 400 | validation failed | 请求参数不合法 |
| 401 | missing x-agent-id header | 缺少认证头 |
| 403 | permission denied | 权限不足 |
| 404 | not found | 资源不存在 |
| 409 | conflict | 资源冲突（如重复创建） |
| 422 | user decision required | 需要用户决策（如 agent 未注册） |
| 500 | internal error | 内部错误 |

---

## Agent 管理

### 注册 Agent

```
POST /api/v0/agents
```

**认证**: 需要 `x-agent-id`

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

**规则**:
- 子 agent 的 level 必须 < 父 agent 的 level
- 子 agent 的 zones 必须是父 agent zones 的子集
- 名称不可重复

### 列出 Agent

```
GET /api/v0/agents
```

无需认证。

**响应** `200 OK`:
```json
[
  {
    "id": "baize-root",
    "level": 4,
    "zones": ["*"],
    "parent_id": null
  },
  {
    "id": "agent-name",
    "level": 3,
    "zones": ["zone-a", "zone-b"],
    "parent_id": "baize-root"
  }
]
```

### 撤销 Agent

```
DELETE /api/v0/agents/{id}
```

**认证**: 需要 `x-agent-id`

**响应**: `204 No Content`（成功）或错误。

**规则**: root agent 不可撤销。

---

## Blob 操作

### 写入 Blob

```
POST /api/v0/blobs
```

**认证**: 需要 `x-agent-id`

**请求体**:
```json
{
  "content": "blob 内容",
  "labels": {
    "key1": "value1",
    "key2": "value2"
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
  "hash": "a1b2c3d4...（SHA-256，64 字符）",
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

### 读取 Blob

```
GET /api/v0/blobs/{hash}
```

无需认证。

**响应** `200 OK`: 同写入响应格式。hash 不存在返回 `404`。

### 查询 Blob

```
POST /api/v0/blobs/query
```

无需认证。

**请求体**:
```json
{
  "labels": {
    "key1": "value1",
    "key2": "value2"
  },
  "limit": 50,
  "offset": 0
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| labels | object | 是 | 查询条件，AND 语义 |
| limit | uint | 否 | 返回数量上限 |
| offset | uint | 否 | 跳过前 N 条记录 |

**响应** `200 OK`: Blob 数组，满足 AND 语义（所有 label 条件同时匹配）。

---

## Push / Pull

Agent 与主仓库之间的数据同步操作。主仓库是 Git 仓库。

**白泽 push ≠ git commit：**
- 白泽 push = Agent 将 workspace 文件推送到主仓库工作区。blob 鉴权后即可执行。
- git commit = 主仓库更新 Git 版本历史。**需要用户审批**，不由 Agent 触发。

### Push（workspace → 主仓库工作区）

将 agent workspace 文件推送到主仓库工作区。文件到达后等待用户审批 git commit。

```
POST /api/v0/push
```

**认证**: 需要 `x-agent-id`

**请求体**:
```json
{
  "message": "提交描述",
  "ref": "shared"
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| message | string | 是 | 提交描述（用于后续 git commit） |
| ref | string | 否 | 目标 ref（保留，暂未使用） |

**成功响应** `201 Created`:
```json
{
  "files": 3,
  "pending": true
}
```

**执行流程**:
1. 验证 agent 身份和 zone 权限（blob 鉴权）
2. workspace 文件写入主仓库工作区
3. 创建鉴权 blob，记录本次操作
4. 文件在主仓库工作区等待用户审批

### Pull（主仓库工作区 → workspace）

从主仓库工作区拉取文件到 agent workspace。无 zone 权限的文件被静默跳过。

```
POST /api/v0/pull
```

**认证**: 需要 `x-agent-id`

**请求体**:
```json
{
  "ref": "shared"
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| ref | string | 否 | 来源 Git ref（保留，暂未使用） |

**成功响应** `200 OK`:
```json
{
  "files": 3
}
```

**执行流程**:
1. 验证 agent 身份和 zone 权限
2. 清空 agent workspace
3. 从主仓库工作区遍历文件，按 zone 过滤后复制到 workspace
4. 审计记录

**注意**: pull 会清空 workspace。调用方必须保证先 pull 再 write，否则 write 的内容会被 pull 清空。

**流程**: Alice push → 文件到达主仓库工作区 → Bob pull → Bob workspace 获得文件（仅限 Bob 有权限的 zone）。

---

## Git 操作

### 查看 Git 日志

查看主仓库 Git 日志。

```
GET /api/v0/log?limit=50
```

无需认证。

| 参数 | 必填 | 说明 |
|------|------|------|
| limit | 否 | 返回数量上限，默认 50，最大 200 |

**响应** `200 OK`:
```json
{
  "commits": [
    {
      "hash": "...",
      "message": "...",
      "author": "...",
      "time": "..."
    }
  ]
}
```

---

## Ref 操作（Git ref）

Ref 对应主仓库 Git 的 branch/tag。操作直接映射到 Git ref。

### 列出 Ref

```
GET /api/v0/refs
```

无需认证。

**响应** `200 OK`:
```json
{
  "refs": ["main", "stable", "v1"]
}
```

### 获取 Ref

```
GET /api/v0/refs/{name}
```

无需认证。

**响应** `200 OK`:
```json
{
  "name": "stable",
  "oid": "a1b2c3..."
}
```

### 设置 Ref

```
PUT /api/v0/refs/{name}
```

**认证**: 需要 `x-agent-id`

**请求体**:
```json
{
  "oid": "git-commit-oid"
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| oid | string | 是 | Git commit OID（40 字符 hex） |

**响应**: `204 No Content`（成功）。

**规则**: OID 必须指向一个已存在的 git commit。如果 ref 已存在则更新，否则创建。

### 删除 Ref

```
DELETE /api/v0/refs/{name}
```

**认证**: 需要 `x-agent-id`

**响应**: `204 No Content`。`HEAD` 不可删除。

---

## Label 操作

### 添加 Label

```
POST /api/v0/labels
```

**认证**: 需要 `x-agent-id`

**请求体**:
```json
{
  "entity_hash": "blob-hash",
  "key": "label-key",
  "value": "label-value"
}
```

**规则**: label 只能挂在 blob 上。同一 (entity_hash, key) 组合重复添加返回 `409 Conflict`。

**响应**: `201 Created`（成功，无 body）。

### 查询 Label

```
GET /api/v0/labels/query?key=<key>&value=<value>
```

无需认证。

| 参数 | 必填 | 说明 |
|------|------|------|
| key | 是 | Label key |
| value | 否 | Label value，省略则按 key 查询所有 |

**响应** `200 OK`:
```json
{
  "labels": [
    {
      "entity_hash": "...",
      "key": "env",
      "value": "production"
    }
  ]
}
```

---

## 借权（Elevation）

### 申请借权

```
POST /api/v0/elevation
```

无需 `x-agent-id`（在请求体中指定 agent）。

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

### 审批借权

```
POST /api/v0/elevation/{id}/approve
```

**认证**: 需要 `x-agent-id`（审批人）

**响应** `200 OK`:
```json
{ "status": "Approved" }
```

**规则**:
- root 可审批任何请求
- 非 root 只能审批自己的子 agent，且请求的 zones 不能超出审批人自身 scope

### 归还借权

```
POST /api/v0/elevation/{id}/return
```

**认证**: 需要 `x-agent-id`

**请求体**:
```json
{
  "agent_id": "agent-name"
}
```

**响应** `200 OK`:
```json
{ "status": "Returned" }
```

### 列出借权记录

```
GET /api/v0/elevation
```

无需认证。

**响应** `200 OK`:
```json
{
  "requests": [
    {
      "id": "...",
      "agent_id": "agent-name",
      "mode": "readonly",
      "reason": "原因",
      "status": "Approved",
      "created_at": "...",
      "expires_at": "..."
    }
  ]
}
```

status 枚举: `Pending` / `Approved` / `Expired` / `Revoked` / `Returned`

---

## 追溯（Trace）

### 身份追溯

追踪 agent 的证书签发链（从该 agent 到 root 的完整链路）。

```
GET /api/v0/trace/identity/{id}
```

无需认证。

**响应** `200 OK`:
```json
{
  "chain": [
    {
      "agent_id": "child-agent",
      "parent_id": "parent-agent",
      "level": 2,
      "zones": ["zone-a"]
    },
    {
      "agent_id": "parent-agent",
      "parent_id": null,
      "level": 4,
      "zones": ["*"]
    }
  ]
}
```

---

## 导入 / 导出

### 导入外部数据

```
POST /api/v0/import
```

**认证**: 需要 `x-agent-id`

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
{
  "hash": "...",
  "trust_level": 1
}
```

### 导出数据

```
GET /api/v0/export/{hash}
```

**认证**: 需要 `x-agent-id`

**响应** `200 OK`:
```json
{
  "hash": "...",
  "content": "数据内容",
  "labels": { ... },
  "created_at": "..."
}
```

**规则**: 高敏感度或受限 zone 的数据导出需要足够的权限等级。

---

## 审计

### 查询审计日志

```
GET /api/v0/audit
```

无需认证。支持查询参数过滤：

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
      "time": "2026-05-16T05:30:00+00:00"
    }
  ]
}
```

所有写操作自动生成审计记录，不可关闭。

---

## 文件操作（网关代理）

文件操作通过白泽 API 代理，所有文件存储在 agent 的 workspace 目录中。每次操作自动计算 hash、记录 blob 并审计。

### 写入文件

```
POST /api/v0/files/{path}
```

**认证**: 需要 `x-agent-id`

**请求体**:
```json
{
  "content": "文件内容",
  "labels": {
    "key1": "value1"
  }
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| content | string | 是 | 文件内容 |
| labels | object | 否 | 附加标签 |

**成功响应** `201 Created`:
```json
{
  "path": "config/app.yaml",
  "hash": "sha256...",
  "size": 1024
}
```

### 读取文件

```
GET /api/v0/files/{path}
```

**认证**: 需要 `x-agent-id`

**响应** `200 OK`:
```json
{
  "path": "config/app.yaml",
  "content": "文件内容",
  "hash": "sha256...",
  "size": 1024
}
```

### 删除文件

```
DELETE /api/v0/files/{path}
```

**认证**: 需要 `x-agent-id`

**响应**: `204 No Content`（成功）或错误。

### 列出文件

```
GET /api/v0/files
```

**认证**: 需要 `x-agent-id`

**响应** `200 OK`:
```json
{
  "files": [
    "config/app.yaml",
    "data/log.txt"
  ]
}
```

### Zone 规则

文件路径的第一段（`/` 之前）视为 zone。例如：
- `config/app.yaml` — 根级文件，所有 agent 可访问
- `A/data.txt` — zone A，需要 agent scope 包含 `"A"` 或 `"*"`

---

## 仓库统计

```
GET /api/v0/repo/stats
```

无需认证。

**响应** `200 OK`:
```json
{
  "total_blobs": 42,
  "total_commits": 10,
  "total_refs": 3
}
```

| 字段 | 说明 |
|------|------|
| total_blobs | 数据库中的 blob 总数 |
| total_commits | 主仓库 Git commit 总数 |
| total_refs | 主仓库 Git ref 总数 |

---

## CLI 速查

```
bz init                                    # 初始化仓库（含 Git 初始化）
bz serve --addr 127.0.0.1:3000             # 启动 HTTP 服务

bz agent register <NAME> --level 3 --zones zone-a,zone-b [--parent <ID>]
bz agent delegate <PARENT> <NAME> --level 2 --zones zone-a
bz agent list
bz agent revoke <ID>

bz blob write --content "..." [--labels k=v,k2=v2] [--agent <ID>]
bz blob read <hash>
bz blob query [--labels k=v]

bz push -m "message" [--ref <name>] [--agent <ID>]
bz pull [--ref <name>] [--agent <ID>]
bz log                                     # 主仓库 Git 日志

bz ref get <name>                          # 获取 Git ref
bz ref set <name> <oid>                    # 设置 Git ref
bz ref delete <name>                       # 删除 Git ref（不可删 HEAD）
bz ref list                                # 列出 Git refs

bz label add <hash> <key> <value> [--agent <ID>]
bz label query <key> [--value <val>]

bz elevate request --agent <ID> --zones zone-a --mode readonly --reason "..." [--duration 2h]
bz elevate approve <request-id> [--agent <ID>]
bz elevate return <request-id> --agent <ID>
bz elevate list

bz trace <agent-id>                        # 身份链追溯
bz audit                                   # 查看审计日志
bz stats                                   # 仓库统计

bz import <file> --source <source> [--trust-level 2] [--agent <ID>]
bz export <hash> --output <path> [--agent <ID>]

bz file write <path> --content "..." [--labels k=v] [--agent <ID>]
bz file read <path> [--agent <ID>]
bz file rm <path> [--agent <ID>]
bz file ls [--agent <ID>]
```

---

## 权限模型

### Level（等级）

| Level | 名称 | 说明 |
|-------|------|------|
| 0 | Isolated | 隔离区，不可写入 |
| 1 | Restricted | 受限操作 |
| 2 | Standard | 标准操作 |
| 3 | Core | 核心操作 |
| 4 | Root | 最高权限，仅 root agent |

### Zone（区域）

zone 是字符串标签，用于数据隔离。agent 只能操作自己 zone 范围内的数据。
`"*"` 表示通配，root 默认拥有。zone 数量不受 level 限制，仅受父 agent scope 约束。

### 规则

1. 子 agent 的 level 必须 **严格小于** 父 agent
2. 子 agent 的 zones 必须 **是父 zones 的子集**（父含 `"*"` 时无限制）
3. blob 是 **鉴权凭证**，不是数据存储
4. 每个 blob **MUST 有 `type` label**，标明凭证用途
5. blob content **推荐 JSON**；PEM、hash 等格式视场景允许
6. 主仓库是 **Git 仓库**，版本管理由 Git 原生提供
7. 白泽 push ≠ git commit：push 推送文件到工作区，git commit 由用户审批后执行
8. 同一内容的 blob 写入是 **幂等的**
9. root agent **不可撤销**
10. `HEAD` ref **不可删除**
11. 所有写操作 **自动审计**（通过 `type: "audit"` 的鉴权 blob 记录）
12. 文件路径首段（`/` 之前）视为 **zone**，受 agent scope 约束
13. 文件操作 Level 0 agent **不可写入**
