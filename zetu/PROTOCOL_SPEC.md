# 泽图协议（Zétú Protocol）Specification v0

> **泽图** 取自《白泽图》。传说黄帝东巡遇神兽白泽，白泽通晓万物，能言人语。
> 黄帝命人将白泽所述天下万物之形貌习性记录成图，颁告天下。
> 泽图协议如其名 — 将 Agent 的交互记录为标准图谱，供所有系统查阅。

## 1. 概述

泽图协议（Zétú Protocol）定义了一种用于存储、版本化、查询 LLM 交互数据的标准。

设计目标：
- **极简** — 最少的原语，最大的表达力
- **内容寻址** — 相同内容 = 相同标识，天然去重
- **不可变** — 写入即固化，不修改历史
- **可扩展** — 所有上层语义通过 labels 表达

### 1.1 术语

| 术语 | 定义 |
|------|------|
| blob | 内容寻址的不可变数据单元 |
| commit | 一组 blob 的命名快照 |
| label | 挂在 blob 或 commit 上的 key-value 元数据 |
| ref | 指向 commit 的命名引用（分支/标签） |
| repository | 存储 blob、commit、label、ref 的完整数据库 |

### 1.2 一致性要求

实现本协议的系统（下称"实现"）必须：

- MUST 支持 blob、commit、label、ref 四种对象
- MUST 使用 SHA-256 作为内容寻址的 hash 函数
- MUST 保证 blob 写入后不可变
- MUST 支持 label 的写入和按 key-value 查询
- MAY 选择任何存储后端（SQLite、文件系统、远程服务等）
- MAY 选择任何传输方式（HTTP REST、gRPC、CLI、库调用）

---

## 2. 对象模型

### 2.1 Blob

```
Blob {
    hash:       string    // SHA-256, 由实现计算
    content:    string    // 原始文本内容
    created_at: datetime  // ISO 8601 UTC, 由实现自动设置
    labels:     map<string, string>  // 可扩展元数据
}
```

**语义：**
- 一个 blob 存储一段 LLM 交互的原始文本（prompt、response、或任何辅助文本）
- hash 由 `SHA-256(content)` 计算，相同内容产生相同 hash
- blob 一旦写入，不可修改、不可删除
- created_at 由实现在写入时自动设置
- labels 在写入时指定初始值，写入后为 append-only（可追加新 key，不可修改或删除已有 key）

### 2.1.1 Label 命名与扩展协议

**内建 label（协议定义）：**

| key | 值域 | 说明 |
|-----|------|------|
| `role` | `"user"` / `"model"` / `"system"` | 交互角色 |
| `parent` | blob hash 或 commit hash | 指向父级实体（构建 pair、thread、event 链） |
| `type` | 自由字符串 | 对象用途分类 |

实现 SHOULD 理解这 3 个内建 key 的语义。

**扩展 label（社区约定）：**

| 前缀 | 命名空间 | 说明 |
|-------|---------|------|
| 无前缀 | 内建 | `role`、`parent`、`type` |
| `x-` | 社区扩展 | `x-token-count`、`x-quality-score` |
| `com.xxx.` | 私有扩展 | `com.acme.eval-result` |

**扩展规范格式：**

任何人定义新 label key 时，应提供如下规范：

```yaml
name: model                # key 名称
version: "1"               # 语义版本
description: 产生该内容的模型标识
value_type: string         # string | integer | float | boolean
valid_values: any          # 可选：约束值域
examples:
  - "claude-sonnet-4-6"
  - "gpt-4"
```

实现 MAY 选择支持哪些扩展 label，不支持的扩展 label 仅做存储，不解释语义。

### 2.2 Commit

```
Commit {
    hash:       string              // SHA-256, 由实现计算
    blobs:      list<string>        // 包含的 blob hash 列表
    parent:     option<string>      // 父 commit hash（首个 commit 为 null）
    message:    string              // 提交说明
    author:     string              // 作者标识
    timestamp:  datetime            // ISO 8601 UTC
    labels:     map<string, string> // 可扩展元数据
}
```

**语义：**
- commit 是一组 blob 在某个时刻的快照
- commit 通过 parent 形成有向无环图（DAG）
- commit 一旦写入，不可修改

### 2.3 Ref

```
Ref {
    name:    string    // 引用名称
    target:  string    // 指向的 commit hash
}
```

**语义：**
- ref 是 commit 的命名指针
- 特殊 ref `HEAD` 指向当前工作分支的最新 commit
- ref 可以被更新（指向不同的 commit）

### 2.4 Label

```
Label {
    entity_type:  "blob" | "commit"   // 挂载目标类型
    entity_id:    string               // blob hash 或 commit hash
    key:          string               // 键
    value:        string               // 值
}
```

**语义：**
- label 是 key-value 对，挂在 blob 或 commit 上
- 同一实体可以有多个 label
- label 的 key 和 value 都是字符串
- label 是 **append-only**：可通过 `label/add` 追加新 key，不可修改或删除已有 key
- label 支持按 key+value 高效查询

---

## 3. 操作

### 3.1 Blob 操作

#### `blob/write`

写入一个 blob。如果相同 content 已存在，返回已有 hash（幂等），并将新 labels 中不冲突的 key 追加到已有 blob。

```
输入:
  content:  string              // 必选
  labels:   map<string, string> // 可选，默认 {}

输出:
  hash:     string              // blob 的 SHA-256 hash
```

#### `blob/read`

按 hash 读取 blob。

```
输入:
  hash:     string

输出:
  blob:     Blob
```

hash 不存在时返回错误。

#### `blob/query`

按 labels 查询 blob。

```
输入:
  labels:   map<string, string> // 匹配条件（AND 语义）
  limit:    option<uint32>      // 最大返回数
  offset:   option<uint32>      // 偏移量

输出:
  blobs:    list<Blob>
```

空 labels 返回所有 blob。

### 3.2 Commit 操作

#### `commit/create`

创建一个 commit，显式指定包含的 blob 列表。

```
输入:
  blobs:     list<string>        // 必选，blob hash 列表
  message:   string              // 必选
  author:    string              // 可选，默认为仓库配置
  labels:    map<string, string> // 可选，默认 {}

输出:
  hash:      string              // commit hash
```

blobs 为空时返回 `VALIDATION` 错误。blobs 列表中的 hash 不存在时返回 `NOT_FOUND` 错误。

parent 自动指向当前 HEAD ref 指向的 commit（如果 HEAD 存在）。

#### `commit/read`

按 hash 读取 commit。

```
输入:
  hash:      string

输出:
  commit:    Commit
```

#### `commit/log`

列出从 HEAD 往回的 commit 链。

```
输入:
  limit:     option<uint32>

输出:
  commits:   list<Commit>
```

### 3.3 Ref 操作

#### `ref/list`

列出所有 ref。

```
输出:
  refs:      list<Ref>
```

#### `ref/get`

读取指定 ref。

```
输入:
  name:      string

输出:
  target:    string    // commit hash
```

#### `ref/set`

更新 ref 指向。

```
输入:
  name:      string
  target:    string    // commit hash
```

#### `ref/delete`

删除 ref。

```
输入:
  name:      string
```

不可删除 `HEAD`。

### 3.4 Label 操作

#### `label/add`

向已有 blob 或 commit 追加一个 label。append-only：key 已存在时返回 `LABEL_CONFLICT`。

```
输入:
  entity_type:  "blob" | "commit"
  entity_id:    string           // blob hash 或 commit hash
  key:          string           // 必选
  value:        string           // 必选

输出:
  ok:           bool
```

#### `label/query`

按 key-value 查询关联的实体。

```
输入:
  key:       string
  value:     option<string>   // null = 查所有 value
  entity:    option<"blob" | "commit">  // 限定实体类型

输出:
  results:   list<{ entity_type, entity_id, key, value }>
```

### 3.5 仓库操作

#### `repo/init`

初始化一个新仓库。

```
输入:
  author:          option<string>
  default_branch:  option<string>   // 默认 "main"

输出:
  path:            string    // 仓库路径
```

#### `repo/stats`

返回仓库统计信息。

```
输出:
  total_blobs:     uint64
  total_commits:   uint64
  total_refs:      uint64
```

---

## 4. HTTP REST API（参考传输层）

本节定义一个基于 HTTP REST 的传输层。实现可以选择其他传输方式，
但如果提供 HTTP API，应遵循本节规范。

### 4.1 通用约定

- 基础路径: `/api/v0`（实现 MAY 使用 `/zetu/v0` 作为替代）
- 内容类型: `application/json`
- 错误响应: `{ "error": "<message>" }`
- hash 参数在 URL 路径中传递
- label 查询参数在 query string 中: `?labels.role=user&labels.model=claude`

### 4.2 端点

#### Blob

| 方法 | 路径 | 对应操作 |
|------|------|---------|
| POST | `/blobs` | blob/write |
| GET | `/blobs/{hash}` | blob/read |
| GET | `/blobs` | blob/query |

POST `/blobs` 请求体:
```json
{
  "content": "实现一个排序算法",
  "labels": {
    "role": "user",
    "session_id": "abc123"
  }
}
```

GET `/blobs?labels.role=user&labels.session_id=abc123` 响应体:
```json
{
  "blobs": [
    {
      "hash": "e3b0c442...",
      "content": "实现一个排序算法",
      "labels": { "role": "user", "session_id": "abc123" }
    }
  ]
}
```

#### Commit

| 方法 | 路径 | 对应操作 |
|------|------|---------|
| POST | `/commits` | commit/create |
| GET | `/commits/{hash}` | commit/read |
| GET | `/commits` | commit/log |

#### Ref

| 方法 | 路径 | 对应操作 |
|------|------|---------|
| GET | `/refs` | ref/list |
| GET | `/refs/{name}` | ref/get |
| PUT | `/refs/{name}` | ref/set |
| DELETE | `/refs/{name}` | ref/delete |

#### Label

| 方法 | 路径 | 对应操作 |
|------|------|---------|
| POST | `/labels` | label/add |
| GET | `/labels?key=role&value=user` | label/query |

POST `/labels` 请求体:
```json
{
  "entity_type": "blob",
  "entity_id": "e3b0c442...",
  "key": "model",
  "value": "claude-sonnet-4-6"
}
```

#### 仓库

| 方法 | 路径 | 对应操作 |
|------|------|---------|
| POST | `/repo/init` | repo/init |
| GET | `/repo/stats` | repo/stats |

---

## 5. 错误

| 错误码 | 含义 |
|--------|------|
| `NOT_FOUND` | 请求的对象不存在 |
| `ALREADY_EXISTS` | 写入冲突（对 blob 是幂等的，不报此错误） |
| `VALIDATION` | 输入参数不合法（如 blobs 列表为空） |
| `LABEL_CONFLICT` | label/add 时 key 已存在 |
| `CONFLICT` | ref 指向的 commit 不存在 |

---

## 6. Push/Pull 即元操作

### 6.1 核心发现

PromptHub 的 push/pull **不是** Git 意义上的仓库同步。

Git 管理的是**一套代码**，所有人在同一份文件上协作编辑，push/pull 是同步同一份代码的不同版本。

PromptHub 管理的是**无数条独立的交互数据流**，每个 Agent、每个 Session 都是独立的数据流。它们之间不需要"合并"，不需要"冲突解决"。

因此 push/pull 就是核心协议的元操作：

- **push = `blob/write` + `commit/create`** — Agent 写入自己的交互数据
- **pull = `blob/query`（by labels）** — Agent 或仲裁器拉取关心的数据

Labels 是路由键：

| label | 通讯语义 |
|-------|---------|
| `thread_id` | 对话线程（仲裁器按线程聚合多 Agent 的交互） |
| `from` | 消息发送方 |
| `to` | 消息接收方 |
| `type` | 消息类型（task / result / feedback / decision） |

### 6.2 Agent 通讯架构

```
┌──────────┐  push   ┌──────────────┐  push   ┌──────────┐
│ Agent A  │ ──────→ │              │ ←────── │ Agent B  │
└──────────┘         │  PromptHub   │         └──────────┘
                     │  (数据层)     │
┌──────────┐  pull   │              │  pull   ┌──────────┐
│ 评估器   │ ←────── │              │ ──────→ │ 训练系统 │
└──────────┘         └──────────────┘         └──────────┘
                           ↑ pull
                           ↓ push
                     ┌──────────┐
                     │  仲裁器   │
                     └──────────┘
```

- Agent 通过 `blob/write` 推送交互数据
- 仲裁器通过 `blob/query` 拉取线程内所有 Agent 的数据
- 仲裁器通过 `blob/write` 下发任务和决策
- 评估器/训练系统通过 `blob/query` 按条件拉取数据

### 6.3 与 Git push/pull 的对比

| | Git | PromptHub |
|---|---|---|
| 管理对象 | 一套代码 | 无数条独立数据流 |
| push 含义 | 推送本地 commit 到远程 | 写入交互数据 |
| pull 含义 | 拉取远程 commit 到本地 | 按 labels 查询数据 |
| 冲突 | 频繁（文件内容冲突） | 不可能（blob 不可变 + 内容寻址） |
| 合并 | 核心操作 | 不需要（数据流独立） |
| 需要额外协议 | 是（传输协议） | 否（就是元操作本身） |

### 6.4 对协议完整性的意义

由于 push/pull 是元操作，v0 协议**已经是完整的**：

- `blob/write` = push
- `blob/query` = pull
- `labels` = 路由
- `commit` = 版本化
- `ref` = 分支/标签

不需要额外的同步协议、传输协议或合并机制。

---

## 7. 上层约定（非协议强制）

以下概念不在 v0 协议中，通过 labels + 上层约定实现：

| 概念 | 约定 labels |
|------|------------|
| Pair | `role: "prompt"` + `role: "response", parent: "<hash>"` |
| Session | `session_id: "xxx"` 聚合 |
| Evaluation | `type: "eval-input"` + `type: "eval-output", parent: "<hash>"` |
| Comparison | `type: "comparison", ref_a: "...", ref_b: "..."` |
| Proposal | 通过分支 + commit 链追踪状态 |
| Thread | `thread_id: "xxx", from: "...", to: "...", msg_type: "..."` |

实现可以支持这些约定，也可以定义自己的上层语义。

---

## 8. 设计决策记录

### 8.1 为什么 role 是 label 而不是 blob 的字段？

因为"角色"是使用约定，不是数据本质。blob 存储的是文本。角色可以是 user/model/system，也可以是 arbitrator/tool-result/note。协议不应预定义角色类型。

### 8.2 为什么 blob 不可变？

与 Git 相同的理由：内容寻址存储的基础是不可变性。hash 是内容的身份。如果内容可以修改，hash 就失去了意义。

### 8.3 为什么 labels 是 append-only？

Agent 运行模式是"先写入 blob，后补充 metadata"：
1. 执行时记录 prompt/response → blob/write
2. 执行结束后补充 token 计数、模型标识 → label/add
3. 评估后补充质量评分 → label/add

如果 labels 完全不可修改，第二步和第三步无法完成。

append-only 是折中：允许追加新信息，但不允许篡改已有信息。这保证了：
- 已有 label 不可篡改（审计可追溯）
- 新 label 可以追加（支持增量元数据）

如果需要"更新"一个 label（如状态变迁），正确做法是通过 commit 链追踪状态，而不是修改 label。

### 8.4 为什么 commit 直接指定 blob 列表，不用暂存区？

暂存区（staging area）是给人用的 — 人类手动挑选文件分批提交。Agent 的运行模式不同：

- Agent 的交互是成批的、有边界的
- 一个 session/task 内的 blob 天然是一个原子单元
- 不存在"只提交这批中的 3 条交互中的 2 条"的场景

去掉暂存区使协议更精简：少 3 个操作（stage/add、stage/remove、stage/list），无中间态，实现更简单。

### 8.5 为什么不用 tree 对象？

Git 需要 tree 因为代码有目录结构。prompt 没有目录结构。如果需要分组，用 labels（session_id、thread_id 等）。

---

## 9. 版本

- **v0** — 初始版本，定义最小可行协议
- 未来版本将根据实现经验和社区反馈迭代
- 遵循语义化版本：补丁修复不改变协议，小版本向后兼容，大版本允许破坏性变更
