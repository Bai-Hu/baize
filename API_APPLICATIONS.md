# 白泽 HTTP API 应用场景

## 1. 定位

白泽是 **Agent 治理基础设施** — 管理身份、权限、审计和数据同步。不内置仲裁器、不绑定 LLM 后端、不预定义协作模式。

核心原则：
- blob = 鉴权凭证（记录"谁在什么权限下做了什么"）
- 主仓库 = Git 仓库（版本管理交给 Git）
- 提供标准数据结构 + 可扩展字段（labels）
- 暴露输入/输出分离的 API，上层系统自由组合

---

## 2. 场景总览

| 场景 | 核心价值 | 状态 |
|------|---------|------|
| Agent 管理 prompt-response | 通过 blob + labels 记录交互，支持多模型对比 | API 已支持 |
| 多 Agent 协作 | 白泽作为数据层，push/pull 实现跨 Agent 文件同步 | API 已支持 |
| Agent ↔ 主仓库 | push 推送文件到主仓库工作区，用户审批后 git commit | API 已支持 |
| 模型行为量化 | 存储相似 prompt 的多模型响应，量化退化、一致性 | 需补全 token 计数 labels |
| CI/CD 质量门控 | prompt 变更自动评估，评估能力由外部提供 | 需新增评估 API |
| Web 前端后端 | 先补全 API，Web UI 后做 | 暂不做 |
| 模型训练优化 | 数据集版本管理 + 多模型对比 | 远景 |

---

## 3. 场景 1：Agent 记录 Prompt-Response

### 3.1 通过 blob + labels 记录交互

Agent 执行时，把 prompt 和 response 存为 blob，通过 labels 标记角色：

```
agent 产生一次交互
    ↓
POST /blobs { content: "长 prompt...", labels: { role: "prompt", model: "claude" } }  → 返回 hash
POST /blobs { content: "长 response...", labels: { role: "response", parent: "<hash>" } } → 返回 hash
    ↓
后续需要时 GET /blobs/{hash} 按需拉取
```

### 3.2 量化分析 — 模型行为测量

存储的数据可支撑：
- **相似 prompt 的模型响应差异** — 同一意图不同表述，模型表现如何
- **上下文退化** — prompt 加到多长时质量开始下降
- **执行一致性** — 同一 prompt 多次执行，结果是否稳定

通过 labels 查询实现聚合：
```
POST /blobs/query { labels: { model: "claude", session_id: "xxx" } }
```

---

## 4. 场景 2：多 Agent 协作

### 4.1 白泽是数据层，不是仲裁器

```
┌──────────────┐
│   仲裁器      │  ← 决策层（上层实现）：任务分配、路由、冲突解决
│  （不在白泽）  │
└──────┬───────┘
       │ 读写
       ↓
┌──────────────┐
│  白泽          │  ← 数据层：blob 鉴权 + labels 查询 + push/pull 同步
│  API          │
└──────────────┘
```

### 4.2 Agent ↔ Agent：通过 blob 通讯

```
Agent A push(blob+data) → 白泽 → Agent B pull(blob+query)
```

- Agent 通过 `blob/write` 推送交互数据
- 仲裁器通过 `blob/query` 拉取线程内所有 Agent 的数据
- labels 标记跨 agent 的关联（thread_id, from, to, msg_type）

### 4.3 Agent ↔ 主仓库：通过 push/pull 同步

```
Agent workspace ──push──→ 主仓库工作区 ──用户审批──→ git commit → Git 历史
Agent workspace ←──pull── 主仓库工作区（按 zone 过滤）
```

- Agent push: workspace 文件推到主仓库工作区，等待用户审批
- Agent pull: 从主仓库工作区拉取文件到 workspace（按 zone 过滤）

---

## 5. 场景 3：Zone 隔离

文件路径的首段视为 zone，Agent 只能操作自己 zone 范围内的文件：

```
Agent alice (zones: A, B)
  ✅ file write A/config.yaml
  ✅ file write B/data.txt
  ❌ file write C/secret.yaml   — zone C 不在 scope 内

alice push → 主仓库只有 A/ 和 B/ 的文件
bob (zones: C) pull → 只能拉到 C/ 的文件，A/B 被静默跳过
```

---

## 6. 场景 4：审计追踪

所有写操作自动生成审计 blob：

```
file write → 审计 blob (type: file_write, agent: alice, result: success)
push       → 审计 blob (type: push, agent: alice, result: success files=3)
blob write → 审计 blob (type: blob_write, agent: alice, result: success)
```

通过 `GET /api/v0/audit` 查询审计日志，支持按 agent 和 type 过滤。

---

## 7. Labels 扩展机制

labels 是挂在 blob 上的 key-value 元数据，append-only：

| 场景 | labels 示例 |
|------|------------|
| Agent 交互 | `role: "prompt"`, `model: "claude"`, `session_id: "xxx"` |
| 多 Agent | `thread_id: "task-001"`, `from: "arbitrator"`, `to: "agent-b"` |
| 审计 | `x-audit: "true"`, `x-audit-type: "push"`, `x-audit-agent: "alice"` |
| 导入数据 | `imported: "true"`, `source: "unittest"`, `trust-level: "2"` |
| Push 鉴权 | `type: "push-auth"`, `agent: "alice"` |

---

## 8. 设计原则总结

1. **白泽是治理基础设施** — 身份、权限、审计、数据同步
2. **blob = 鉴权凭证** — 记录操作，不是数据存储
3. **主仓库 = Git 仓库** — 版本管理交给 Git，白泽管理 push/pull 工作流
4. **labels 可扩展** — 标准数据结构 + 用户自定义 key-value
5. **push ≠ git commit** — Agent push 到工作区，用户审批后 git commit
6. **Zone 隔离** — Agent 只能操作自己 zone 范围内的文件
