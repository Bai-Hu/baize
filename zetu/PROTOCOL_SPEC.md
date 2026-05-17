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
| blob | 鉴权凭证 — 记录"谁在什么权限下做了什么操作"，内容寻址，不可变 |
| commit | Agent 与主仓库之间的数据同步操作（Agent → 主仓库的推送），主仓库为 Git 仓库，commit 即 Git commit |
| label | 挂在 blob 上的 key-value 元数据 |
| main repo | 主仓库，初始化为 Git 仓库，存储所有经过 commit 推送的数据 |
| workspace | Agent 的独立工作目录，与主仓库隔离 |
| repository | 存储 blob、label 的数据库 + 主仓库 Git 仓库 |

### 1.2 一致性要求

实现本协议的系统（下称"实现"）必须：

- MUST 支持 blob、label 两种核心对象
- MUST 使用 SHA-256 作为内容寻址的 hash 函数
- MUST 保证 blob 写入后不可变
- MUST 支持 label 的写入和按 key-value 查询
- MUST 将主仓库初始化为 Git 仓库
- MAY 选择任何存储后端（SQLite、文件系统、远程服务等）
- MAY 选择任何传输方式（HTTP REST、gRPC、CLI、库调用）

---

## 2. 对象模型

### 2.1 Blob

```
Blob {
    hash:       string    // SHA-256, 由实现计算
    content:    string    // 鉴权凭证内容（推荐 JSON；PEM、hash 等格式视场景允许）
    created_at: datetime  // ISO 8601 UTC, 由实现自动设置
    labels:     map<string, string>  // 可扩展元数据
}
```

**语义：**
- blob 是鉴权凭证，记录 Agent 的操作：谁（agent）、在什么权限下（scope）、做了什么（operation）、结果如何（result）
- hash 由 `SHA-256(content)` 计算，相同内容产生相同 hash
- blob 一旦写入，不可修改、不可删除
- created_at 由实现在写入时自动设置
- labels 在写入时指定初始值，写入后为 append-only（可追加新 key，不可修改或删除已有 key）

**内建 blob 类型的 `type` label 约定：**

| type 值 | content 格式 | 用途 |
|---------|-------------|------|
| `audit` | JSON | 审计记录，所有写操作自动产生 |
| `agent-cert` | PEM | Agent 证书 |
| `agent-key` | PEM | Agent 私钥 |
| `root-ca` | PEM | Root CA 证书 |
| `file` | SHA-256 hash | 文件操作凭证（content = 文件内容 hash） |
| `push-auth` | JSON | Push 操作鉴权凭证 |
| `elevation-request` | JSON | 借权请求 |

实现 MUST 为每个 blob 设置 `type` label。自定义类型使用 `x-` 前缀。

**blob 在数据传输中的角色：**

push/pull 传输的是 **blob-data 对**：blob 证明操作的合法性（鉴权），data 是实际传输的内容。
不同数据路线中 blob 的鉴权对象不同：

| 数据路线 | blob 鉴权 | data | push/pull 对数 |
|---------|----------|------|---------------|
| Agent ↔ Agent | 证明 agent 有权读/写该数据流 | 交互数据（prompt、response 等） | 两对（双向） |
| Agent ↔ 主仓库 | 证明 agent 有权 commit 到主仓库 | workspace 文件 | 一对（即 commit） |

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

白泽 commit 是 Agent 将文件推送到主仓库的操作。这**不是** git commit。

主仓库是 Git 仓库，有两层操作：

| 操作 | 执行者 | 含义 |
|------|--------|------|
| 白泽 commit（push） | Agent | Agent 将 workspace 文件推送到主仓库工作区 |
| git commit | 主仓库（系统） | 主仓库更新 Git 版本历史，**需要用户审批** |

```
Agent workspace  ──白泽 commit──→  主仓库工作区  ──用户审批──→  git commit  →  Git 历史
                   (blob 鉴权)     (文件就绪)     (用户决策)    (版本固化)
```

**白泽 commit ≠ git commit：**
- 白泽 commit 是 Agent 的数据推送操作，blob 鉴权后即可执行
- git commit 是主仓库的版本管理操作，必须经过用户审批才能执行
- 一次白泽 commit 后，文件到达主仓库工作区，但尚未进入 Git 历史
- 用户审批后，主仓库执行 git commit，文件正式进入版本管理

### 2.3 主仓库 Git 操作

主仓库的 Git 操作是独立的版本管理层，由用户（而非 Agent）控制：

- **git commit**：将主仓库工作区的变更写入 Git 历史。需要用户审批。
- **git ref（branch/tag）**：版本分支管理。
- **git log / diff / revert**：版本历史查询和回退。

Agent 只能通过白泽 commit 将文件推送到主仓库工作区，不能直接触发 git commit。

### 2.4 Ref

白泽 ref 是主仓库 Git 的 branch/tag：
- Git branch/tag 即白泽的 ref
- 特殊 ref `HEAD` 指向当前工作分支的最新 commit
- ref 可以被更新（指向不同的 commit）

### 2.4 Label

```
Label {
    entity_hash:  string    // 挂载的 blob hash
    key:          string    // 键
    value:        string    // 值
}
```

**语义：**
- label 是 key-value 对，挂在 blob 上
- 同一 blob 可以有多个 label
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

#### `commit/push`（白泽 commit）

将 agent workspace 的文件推送到主仓库工作区。

```
输入:
  agent_id:  string              // 必选，执行 commit 的 agent
  message:   string              // 必选，commit 描述

输出:
  files:      uint32             // 推送的文件数
  pending:    bool               // 文件在主仓库工作区，等待用户审批 git commit
```

执行流程：
1. 验证 agent 身份和 zone 权限（blob 鉴权）
2. 将 workspace 文件写入主仓库工作区
3. 创建鉴权 blob，记录本次操作
4. 文件到达主仓库工作区，**等待用户审批**后才会执行 git commit

注意：白泽 commit 只是把文件推到主仓库工作区。git commit 是独立的用户操作，不在本操作范围内。

#### `commit/pull`（白泽 pull）

从主仓库拉取指定 ref 的文件到 agent workspace。

```
输入:
  agent_id:  string              // 必选，执行 pull 的 agent
  ref:       option<string>      // 可选，Git ref，默认 HEAD

输出:
  commit_hash: string            // 拉取的 Git commit hash
  files:      uint32             // 拉取的文件数
  ref:        string             // 实际使用的 ref
```

执行流程：
1. 验证 agent 身份和 zone 权限（blob 鉴权）
2. 从主仓库 Git 历史中读取指定 ref 的文件
3. 按权限过滤，复制到 agent workspace
4. 创建鉴权 blob，记录本次操作

### 3.3 Git 操作（用户控制）

主仓库的 Git 操作由用户控制，不由 Agent 触发：

| 操作 | 执行者 | 说明 |
|------|--------|------|
| `git commit` | 用户审批后 | 将主仓库工作区变更写入 Git 历史 |
| `git ref` 管理 | 用户 | branch/tag 的创建、更新、删除 |
| `git log/diff/revert` | 用户 | 版本历史查询和回退 |

Agent 通过白泽 commit 推送的文件在主仓库工作区等待用户审批。
用户审批后才执行 git commit，文件正式进入 Git 版本历史。

### 3.4 Ref 操作

Ref 由主仓库 Git 仓库管理：

| 白泽操作 | Git 等价操作 | 执行者 |
|---------|------------|--------|
| `ref/list` | `git branch -a` + `git tag` | 用户 |
| `ref/get` | `git show-ref <name>` | 用户 |
| `ref/set` | `git update-ref <name> <hash>` | 用户 |
| `ref/delete` | `git update-ref -d <name>` | 用户 |

不可删除 `HEAD`。

### 3.4 Label 操作

#### `label/add`

向已有 blob 追加一个 label。append-only：key 已存在时返回 `LABEL_CONFLICT`。

```
输入:
  entity_hash:  string           // blob hash
  key:          string           // 必选
  value:        string           // 必选

输出:
  ok:           bool
```

#### `label/query`

按 key-value 查询关联的 blob。

```
输入:
  key:       string
  value:     option<string>   // null = 查所有 value

输出:
  results:   list<{ entity_hash, key, value }>
```

### 3.5 仓库操作

#### `repo/init`

初始化一个新仓库（包括主仓库 Git 初始化）。

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
  total_commits:   uint64    // Git commit 数量
  total_refs:      uint64    // Git ref 数量
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

#### Commit（主仓库 Git 操作）

| 方法 | 路径 | 对应操作 |
|------|------|---------|
| POST | `/push` | commit/push（workspace → 主仓库 Git commit） |
| POST | `/pull` | commit/pull（主仓库 Git → workspace） |
| GET | `/log` | commit/log（主仓库 Git log） |

#### Ref（Git ref 操作）

| 方法 | 路径 | 对应操作 |
|------|------|---------|
| GET | `/refs` | ref/list（git branch -a + git tag） |
| GET | `/refs/{name}` | ref/get（git show-ref） |
| PUT | `/refs/{name}` | ref/set（git update-ref） |
| DELETE | `/refs/{name}` | ref/delete（git update-ref -d） |

#### Label

| 方法 | 路径 | 对应操作 |
|------|------|---------|
| POST | `/labels` | label/add |
| GET | `/labels?key=role&value=user` | label/query |

POST `/labels` 请求体:
```json
{
  "entity_hash": "e3b0c442...",
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

## 6. Push/Pull：数据传输的元操作

### 6.1 核心概念

Push/pull 传输的是 **blob-data 对**：
- **blob** = 鉴权凭证，证明操作的合法性
- **data** = 实际传输的内容

白泽有两条数据路线：

| 数据路线 | 方向 | push/pull 对数 | 说明 |
|---------|------|---------------|------|
| Agent ↔ Agent | 双向 | 两对 | Agent 间直接交换数据，blob 鉴权读写权限 |
| Agent ↔ 主仓库 | Agent→主仓库推送，主仓库→Agent 拉取 | 一对 | 即 commit，blob 鉴权 commit 权限 |

### 6.2 Agent ↔ Agent 通讯

Agent 间的数据交换通过 blob 操作完成：

```
┌──────────┐  push(blob+data)  ┌──────────────┐  push(blob+data)  ┌──────────┐
│ Agent A  │ ────────────────→ │              │ ←──────────────── │ Agent B  │
└──────────┘                   │  白泽         │                   └──────────┘
                               │  (blob 存储)  │
┌──────────┐  pull(blob+query) │              │  pull(blob+query) ┌──────────┐
│ 评估器   │ ←──────────────── │              │ ────────────────→ │ 训练系统 │
└──────────┘                   └──────────────┘                   └──────────┘
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

Labels 是路由键：

| label | 通讯语义 |
|-------|---------|
| `thread_id` | 对话线程（仲裁器按线程聚合多 Agent 的交互） |
| `from` | 消息发送方 |
| `to` | 消息接收方 |
| `type` | 消息类型（task / result / feedback / decision） |

### 6.3 Agent ↔ 主仓库（Commit）

主仓库是 Git 仓库。白泽 commit 和 git commit 是两个不同层次的操作：

```
Agent workspace  ──白泽 commit──→  主仓库工作区  ──用户审批──→  git commit  →  Git 历史
                  (blob 鉴权)     (文件就绪)     (用户决策)    (版本固化)
```

- **白泽 commit**：Agent 将 workspace 文件推送到主仓库工作区。blob 鉴权后即可执行。
- **git commit**：主仓库更新 Git 版本历史。**需要用户审批**，不由 Agent 触发。
- **白泽 pull**：从主仓库 Git 历史拉取文件到 workspace。blob 鉴权后执行。

主仓库 Git 机制提供的天然能力（用户控制）：
- **版本历史**：Git commit chain 提供完整的变更追溯
- **分支/标签**：Git ref 管理不同版本和发布
- **差异比较**：git diff 比较不同版本
- **回滚**：git revert 回退错误操作

### 6.4 与 Git push/pull 的对比

| | Git | 白泽 Agent↔Agent | 白泽 Agent↔主仓库 |
|---|---|---|---|
| 管理对象 | 一套代码 | 无数条独立数据流 | workspace 文件 |
| push 含义 | 推送本地 commit 到远程 | 写入交互数据 | git commit（鉴权 blob 记录） |
| pull 含义 | 拉取远程 commit 到本地 | 按 labels 查询数据 | git checkout（鉴权 blob 记录） |
| 冲突 | 频繁 | 不可能（blob 不可变） | 不可能（各 agent workspace 独立） |
| 版本管理 | commit chain | 通过 labels 约定 | Git 原生版本管理 |

### 6.5 对协议完整性的意义

v0 协议基于两个核心原语：

- **blob** = 鉴权凭证（记录操作）
- **labels** = 路由（查询和过滤）

Agent ↔ Agent 通讯：
- `blob/write` = push（写入交互数据）
- `blob/query` = pull（按 labels 查询数据）

Agent ↔ 主仓库（commit）：
- `commit/push` = workspace → git commit（鉴权 blob 记录）
- `commit/pull` = git checkout → workspace（鉴权 blob 记录）

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

### 8.4 为什么白泽 commit 不等于 git commit？

白泽 commit 和 git commit 是两个不同层次的操作：

- **白泽 commit** = Agent 的数据推送操作。Agent 通过 blob 鉴权后，将 workspace 文件推送到主仓库工作区。这是 Agent 的权限范围。
- **git commit** = 主仓库的版本管理操作。将工作区变更写入 Git 历史。这是用户的决策权限。

分离两者的原因：
- Agent 不应拥有直接修改 Git 历史的权限。Git 历史是不可变的真相来源。
- 用户需要审批 Agent 的推送，确认后才固化到版本历史。
- 这提供了一个人工审查的检查点，防止 Agent 推送错误或恶意数据。

### 8.5 为什么 blob 不是数据存储？

blob 是鉴权凭证，不是文件内容存储。文件数据存在主仓库（Git）中。
将 blob 用作数据存储会导致：
- 与 blob 幂等性冲突（相同内容去重，无法区分不同文件的相同内容）
- 与 blob 鉴权职责混淆（一个对象承担两个不相关的职责）
- 数据膨胀（文件内容全部存入 SQLite）

### 8.6 为什么 blob content 不强制 JSON？

blob 的职责是鉴权凭证，content 是凭证的载体。不同场景的凭证有自然的最佳格式：

| 场景 | content 格式 | 原因 |
|------|-------------|------|
| 审计记录 | JSON | 结构化操作日志，便于查询和解析 |
| Agent 交互数据 | JSON | prompt/response 天然是结构化数据 |
| 文件操作凭证 | SHA-256 hash | 只需证明文件内容的完整性，hash 本身就是凭证 |
| 身份证书 | PEM | X.509 证书和私钥的标准序列化格式 |
| Push 鉴权 | JSON | 记录推送操作的元信息 |

强制所有 content 为 JSON 会产生无意义的包装（如 `{"pem": "-----BEGIN..."}`），增加复杂度但不增加信息量。

协议对 content 的要求是：
- **MUST** 是合法的 UTF-8 字符串
- **SHOULD** 使用 JSON 格式（结构化凭证的场景）
- **MAY** 使用其他格式（当该格式是该凭证类型的行业标准时）

实现可通过 label `type` 判断 content 的格式，按类型选择解析策略。

### 8.7 为什么不用 tree 对象？

Git 需要 tree 因为代码有目录结构。白泽的 Agent 间通讯数据没有目录结构。
如果需要分组，用 labels（session_id、thread_id 等）。

---

## 9. 版本

- **v0** — 初始版本，定义最小可行协议
- 未来版本将根据实现经验和社区反馈迭代
- 遵循语义化版本：补丁修复不改变协议，小版本向后兼容，大版本允许破坏性变更
