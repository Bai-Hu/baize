# PromptHub HTTP API 应用场景

## 1. 定位

PromptHub 是纯粹的 **prompt 基础设施**。不内置仲裁器、不绑定 LLM 后端、不预定义协作模式。

核心原则：
- 提供标准数据结构 + 可扩展字段（labels）
- 暴露输入/输出分离的 API，上层系统自由组合
- 所有 LLM 调用由外部完成，PromptHub 只管存储和查询

---

## 2. 场景总览

| 场景 | 核心价值 | 状态 |
|------|---------|------|
| 外部 Agent 管理 prompt | agent 通过 API 记录 prompt-response，上下文用 hash 而非原文，减少 token 消耗 | API 已支持 |
| 模型行为量化 | 存储相似 prompt 的多模型响应，量化退化、一致性、成本 | 需补全 token 计数 + labels |
| CI/CD 质量门控 | prompt 变更自动评估，评估能力由外部提供，PromptHub 管理流程 | 需新增评估 API |
| 多 Agent 协作 | PromptHub 作为仲裁器的数据层，提供存储和查询，仲裁逻辑由上层实现 | 需补全 labels 查询 |
| Web 前端后端 | 先补全 API，Web UI 后做 | 暂不做 |
| 开源 prompt 基础设施 | 远景方向 | 远景 |
| 模型训练优化 | 数据集版本管理 + 多模型对比 | 远景 |

---

## 3. 场景 1：外部 Agent 管理 Prompt

### 3.1 记录层 — 减少 token 消耗

agent 执行时，把完整的 prompt 和 response 存入 PromptHub，上下文窗口只保留 hash：

```
agent 产生一次交互
    ↓
POST /blobs { role: "user", content: "长 prompt..." }  → 返回 hash
POST /blobs { role: "model", content: "长 response..." } → 返回 hash
POST /pairs  { prompt_hash, response_hash, model }      → 配对
    ↓
agent 上下文里只记 3 个 hash（固定长度），不记原文
    ↓
后续需要时 GET /blobs/{hash} 按需拉取
```

### 3.2 量化分析 — 模型行为测量

存储的数据可支撑：
- **相似 prompt 的模型响应差异** — 同一意图不同表述，模型表现如何
- **上下文退化** — prompt 加到多长时质量开始下降
- **执行一致性** — 同一 prompt 多次执行，结果是否稳定

需要的增量能力：
- Token 计数（`input_tokens` / `output_tokens`）→ 通过 labels 存储
- 按模型/标签聚合查询 → 通过 labels 查询实现

---

## 4. 场景 2：CI/CD 质量门控

### 4.1 输入/输出分离的评估 API

PromptHub 不做 LLM 调用，只管理评估流程：

```
CI Pipeline 创建评估任务:
POST /evaluations { proposal_id, input: "评估这个 prompt...", labels: {...} }
       → 返回 evaluation_id

外部评估器（LLM / 规则引擎 / 人工）执行评估:
       ↓

评估器写入结果:
POST /evaluations/{id}/result {
    quality_passed: true,
    score: 0.85,
    issues: [...],
    findings: {...}
}
```

评估器可以是任意实现：Claude、GPT、本地模型、代码规则、人工标注。

### 4.2 效果对比（非文本 diff）

两个版本之间的"差异"不是文字 diff，而是**行为对比**：

```
POST /comparisons {
    type: "session",
    ref_a: "session-v1",
    ref_b: "session-v2",
    labels: { purpose: "prompt-regression" }
}

评估器写入对比结果:
POST /comparisons/{id}/result {
    metrics: {
        quality:  { a: 0.6, b: 0.85, delta: +0.25 },
        tokens:   { a: 500, b: 300, delta: -200 },
        turns:    { a: 3, b: 1, delta: -2 },
    },
    verdict: "improved",
    summary: "v2 prompt 效果更好，token 消耗更低"
}
```

---

## 5. 场景 3：多 Agent 协作

### 5.1 PromptHub 是数据层，不是仲裁器

```
┌──────────────┐
│   仲裁器      │  ← 决策层（上层实现）：任务分配、路由、冲突解决
│  （不在 PH）  │
└──────┬───────┘
       │ 读写
       ↓
┌──────────────┐
│  PromptHub    │  ← 数据层：存储 + 版本管理 + 可扩展 labels
│  API          │
└──────────────┘
```

### 5.2 append-only 模型

blob 不可变，不需要更新状态。任务是否完成 = 链上是否有后续记录：

```
blob 1 (agent-A): "实现排序算法"          ← 任务
blob 2 (agent-B): "已实现，代码如下..."    ← 执行结果
blob 3 (agent-A): "缺少测试"              ← 反馈
blob 4 (agent-B): "已补充测试"            ← 修复
```

"完成"不是一个字段状态，而是最后一条记录的内容。

### 5.3 labels 支持仲裁器需求

仲裁器通过 labels 标记跨 agent 的关联：

```json
{
  "labels": {
    "from": "arbitrator",
    "to": "agent-a",
    "thread_id": "task-calc-001",
    "parent": "abc123...",
    "msg_type": "task"
  }
}
```

PromptHub 不解释这些字段的语义，只负责存储和查询。

---

## 6. 可扩展数据结构：Labels

### 6.1 设计

**blob 新增 `labels: HashMap<String, String>`**

用户可扩展的 key-value 对，用于存储任何结构化元数据。

**存储：EAV 表（Entity-Attribute-Value）**

```sql
CREATE TABLE blob_labels (
    blob_hash TEXT NOT NULL REFERENCES blobs(hash),
    key TEXT NOT NULL,
    value TEXT NOT NULL
);
CREATE INDEX idx_blob_labels_key_value ON blob_labels(key, value);
CREATE INDEX idx_blob_labels_hash ON blob_labels(blob_hash);
```

**查询：**

```
GET /blobs?labels.thread_id=task-001&labels.from=arbitrator
```

### 6.2 各场景使用 labels 的方式

| 场景 | labels 示例 |
|------|------------|
| Agent 记录 | `input_tokens: "150"`, `output_tokens: "320"`, `from: "agent-a"` |
| CI/CD | `pipeline: "github-actions"`, `branch: "prompt-42"`, `eval_result: "pass"` |
| 多 Agent | `thread_id: "task-001"`, `from: "arbitrator"`, `to: "agent-b"`, `msg_type: "task"` |
| 训练数据 | `dataset: "v2"`, `split: "train"`, `quality: "high"` |

---

## 7. 需要补全的 API 端点

### 高优先级

| 端点 | 说明 |
|------|------|
| labels 查询 | `GET /blobs?labels.xxx=yyy` — EAV 表查询 |
| 评估输入 | `POST /evaluations` — 创建评估任务 |
| 评估输出 | `POST /evaluations/{id}/result` — 写入评估结果 |
| 对比输入 | `POST /comparisons` — 创建对比任务 |
| 对比输出 | `POST /comparisons/{id}/result` — 写入对比结果 |
| 对比查询 | `GET /comparisons` — 查询对比历史 |

### 中优先级

| 端点 | 说明 |
|------|------|
| `GET /export` | 导出 JSON/CSV |
| `GET /search?q=xxx` | 全文搜索（FTS5） |
| `GET /sessions` | session 列表 + 详情 |

### 底层数据结构变更

| 变更 | 说明 |
|------|------|
| `blob_labels` 表 | EAV 表 + 索引（新增） |
| `NewPrompt` 加 `labels` | `HashMap<String, String>`（扩展） |
| `comparisons` 表 | 对比任务 + 结果（新增） |
| evaluations 扩展 | 输入/输出分离（修改） |

---

## 8. 设计原则总结

1. **PromptHub 是纯粹的基础设施** — 不内置仲裁器、不绑定 LLM、不预定义协作模式
2. **输入/输出分离** — 评估和对比的 API 只管存储，执行由外部完成
3. **labels 可扩展** — 标准数据结构 + 用户自定义 key-value，支持高效查询
4. **append-only** — blob 不可变，状态通过链上记录推断，不修改历史
5. **效果对比而非文本 diff** — 两个版本之间比较的是行为差异（质量、成本、轮次），不是文字差异
