# 白泽 MVP — 所有特性的最小可运行实现

## 目标

实现白泽架构的**完整骨架** — 每个特性都以最小可运行形态存在，形成一个端到端可运行的治理脚手架。不追求生产级质量，追求架构完整性。

---

## 特性清单

### 1. 泽图 v0 存储引擎

最小实现：blob/commit/ref/label 四种对象的 SQLite 存储 + CRUD。

```
blob     → SHA-256 内容寻址，不可变
commit   → blob 列表快照 + parent 链
ref      → 指向 commit 的命名指针
label    → EAV 表，append-only
```

### 2. X.509 证书链

最小实现：白泽作为 Root CA 自签名，为 Agent 签发证书，Agent 可签发子 Agent 证书。

```
rcgen 生成 Root CA 证书 + Agent 证书
证书包含: agent_id, parent_id, security_level, zones
验证: 沿证书链逐级校验签名
```

不实现：CRL、OCSP、证书 renewal 复杂流程。撤销通过 status 标记。

### 3. Scope 模型（Level + Zone）

最小实现：Level 0-4 整数 + Zone 字符串列表。证书中携带，每次操作检查。

```
Level: 0(隔离) / 1(受限) / 2(标准) / 3(核心) / 4(用户)
Zone: 用户定义的字符串列表，白泽不预定义含义
递减: 子 Level ≤ 父 Level, 子 Zone ⊆ 父 Zone ∩ 新 Level 上限
```

### 4. Scope Elevation（临时借权）

最小实现：Agent 申请 → 父 Agent/白泽审批 → 临时 scope 生效 → 到期自动回收。

```
访问模式: 只读(默认) / 只写 / 读写
归还时: 扫描 workspace，清理超出权限的数据
```

### 5. 三层决策模型

最小实现：根据 scope 自动路由。

```
操作在 scope 内            → 自主决策，直接执行
操作超出 scope，可借权      → 授权决策，走 elevation 审批
操作超出所有 Agent scope    → 用户决策，CLI 确认提示
```

### 6. Agent 注册与管理

最小实现：注册（签发证书 + 分配 scope）、层级关系、撤销。

```
bz agent register <name> --level 2 --zones A,B    # 注册
bz agent delegate <parent> <name> --level 1 --zones A  # 子 Agent
bz agent revoke <agent-id>                         # 撤销
bz agent list                                      # 列出
```

### 7. 五关口管道

最小实现：每个泽图操作经过 验身份 → 查权限 → 执行 → 留痕 管道。

```
pre hook:  证书验证 + scope 检查
execute:   泽图原语
post hook: 审计 blob 写入
```

Hook 以函数指针注册，可替换。默认提供基础实现。

### 8. 闭环数据管理

最小实现：

**导入**: 外部数据 → 基本格式检查 → 来源标注 → 入库
**导出**: 审批 → blob → 写出外部 + 审计记录

```
bz import <file> --source "filesystem" --trust-level 2
bz export <hash> --output /path/to/file
```

非可信数据（trust-level 0）进入沙箱区，不进入主仓库。

### 9. Agent 工作目录

最小实现：每个 Agent 一个临时目录，注册时创建，撤销时销毁。

```
注册 → 创建 workspace 目录
借权归还 → 扫描清理超出 scope 的文件
撤销 → workspace 整体销毁，主仓库 blob 保留
```

### 10. 追溯查询

最小实现：按 parent label 正向/反向追溯 + 证书链查询。

```
bz trace <hash>          # 数据链追溯
bz trace --identity <id> # 身份链追溯（证书链）
```

### 11. 审计

最小实现：所有操作自动产生审计 blob。

```
审计 blob labels:
  x-audit: "true"
  x-audit-type: "blob_write" | "agent_register" | "scope_elevate" | ...
  x-audit-agent: <agent-id>
  x-audit-result: "success" | "denied"
```

---

## 技术选型

| 组件 | 选择 | 理由 |
|------|------|------|
| 语言 | Rust | 性能、安全、与 PromptHub 一致 |
| 存储 | SQLite + FTS5 | 轻量、单文件、trigram CJK |
| HTTP | Axum | 与 PromptHub 一致 |
| CLI | Clap | 与 PromptHub 一致 |
| 证书 | rcgen | 轻量 X.509 生成，无 OpenSSL 依赖 |
| SHA-256 | sha2 crate | 协议规定 |
| 序列化 | serde + serde_json | 标准 |

## 项目结构

```
baize/
  crates/
    baize-core/        # 存储引擎 + Scope 模型 + 证书工具
    baize-server/      # HTTP API + 五关口管道 + Hook 机制
    baize-cli/         # CLI（bz 命令）
  docs/
    REQUIREMENTS.md
    MVP.md
    zetu/
      PROTOCOL_SPEC.md
      PROTOCOL_VISION.md
```

## CLI 命令

```
# 仓库
bz init                                     # 初始化仓库（生成 Root CA）

# Agent 管理
bz agent register <name> --level N --zones A,B   # 注册 Agent，签发证书
bz agent delegate <parent> <name> --level N --zones A  # 子 Agent
bz agent revoke <agent-id>                        # 撤销 Agent
bz agent list                                     # 列出

# 泽图操作
bz blob write --content "..." --labels k=v,k=v    # 写入 blob
bz blob read <hash>                               # 读取 blob
bz blob query --labels role=user                   # 查询

bz commit create --blobs h1,h2 -m "message"       # 创建 commit
bz log                                            # commit 历史

bz label add <hash> <key> <val>                   # 追加 label
bz label query <key> [<val>]                      # 查询 label

# 数据闭环
bz import <file> --source <src> [--trust-level N]  # 导入
bz export <hash> --output <path>                   # 导出

# Scope Elevation
bz elevate request --zones C --mode readonly --reason "..."  # 申请借权
bz elevate approve <request-id>                              # 审批
bz elevate list                                              # 查看借权记录

# 追溯
bz trace <hash>              # 数据链追溯
bz trace --identity <id>     # 身份链追溯

# 审计
bz audit log                 # 查看审计日志
bz audit query --agent <id>  # 查看特定 Agent 操作记录
```

## HTTP API

```
# 泽图操作
POST   /api/v0/blobs              # blob/write
GET    /api/v0/blobs/{hash}       # blob/read
GET    /api/v0/blobs?labels.x=y   # blob/query

POST   /api/v0/commits            # commit/create
GET    /api/v0/commits/{hash}     # commit/read
GET    /api/v0/commits            # commit/log

GET    /api/v0/refs               # ref/list
GET    /api/v0/refs/{name}        # ref/get
PUT    /api/v0/refs/{name}        # ref/set

POST   /api/v0/labels             # label/add
GET    /api/v0/labels?key=x       # label/query

# Agent 管理
POST   /api/v0/agents                        # register
POST   /api/v0/agents/{id}/delegate           # 子 Agent
POST   /api/v0/agents/{id}/revoke             # 撤销
GET    /api/v0/agents                         # 列出

# 数据闭环
POST   /api/v0/import                         # 导入外部数据
POST   /api/v0/export                         # 导出

# Scope Elevation
POST   /api/v0/elevations                     # 申请借权
POST   /api/v0/elevations/{id}/approve        # 审批
GET    /api/v0/elevations                     # 借权记录

# 追溯 & 审计
GET    /api/v0/trace/{hash}                   # 数据链追溯
GET    /api/v0/trace/{id}/identity            # 身份链追溯
GET    /api/v0/audit                          # 审计日志
```

所有 API 通过 TLS 客户端证书认证（mTLS）。

## 端到端验证流程

```
# 1. 初始化仓库（生成 Root CA）
bz init

# 2. 注册 Agent A（Level 2, Zone A/B）
bz agent register agent-a --level 2 --zones A,B
# → agent_id: agent-001, cert: agent-001.crt

# 3. Agent A 创建子 Agent A1（Level 1, Zone A）
bz agent delegate agent-001 sub-a1 --level 1 --zones A

# 4. 导入外部数据
bz import /path/to/task.md --source filesystem --trust-level 2
# → blob hash: abc123..., labels: {source: "filesystem", trust: "2"}

# 5. 写入任务 blob（用户决策 — 初始定义）
bz blob write --content "整理桌面" --labels 'from=user,to=agent-001,type=task'
# → 自主决策：用户在 scope 内，直接执行

# 6. Agent A 发现需要 Zone D（Agent 管理），申请借权
bz elevate request --zones D --mode readonly --reason "需要创建子 Agent 处理图片"
# → 授权决策：父级审批

# 7. 审批借权
bz elevate approve <request-id>
# → Agent A 临时获得 Zone D（只读）

# 8. Agent A 在借权 scope 内工作，完成后归还
# → 自动扫描 workspace，清理 Zone D 相关数据

# 9. Agent A 写入结果
bz blob write --content "已完成" --labels 'from=agent-001,to=user,type=result,parent=<task-hash>'

# 10. 导出结果到外部
bz export <result-hash> --output /path/to/result.md
# → 审计记录: 谁、导出了什么、到哪里、何时

# 11. 追溯
bz trace <result-hash>
# → 数据链: result → task → import → 外部来源
# → 身份链: agent-001 → Root CA

# 12. 任务结束，撤销子 Agent
bz agent revoke sub-a1-id
# → workspace 销毁，主仓库 blob 保留

# 13. 查看审计日志
bz audit log
# → 完整操作记录
```

## MVP 的"最小"定义

每个特性只实现核心路径，不实现边缘情况：

| 特性 | 实现 | 不实现 |
|------|------|--------|
| 证书 | 单向签发 + 链验证 | CRL/OCSP、自动 renewal、密钥轮换 |
| Scope | Level + Zone 检查 | 复杂 RBAC、动态 Zone、细粒度 ACL |
| 借权 | 申请/审批/归还 | 借权链委托、部分归还 |
| 决策 | 自动路由 | 复杂策略引擎、条件决策 |
| 闭环 | 基本 import/export | 内容安全扫描、格式转换、批量导入 |
| Workspace | 创建/销毁/基本清理 | 增量备份、workspace 恢复 |
| Hook | pre/post 函数指针 | 异步 hook、hook 链优先级、hook 热加载 |
| 审计 | 自动写入审计 blob | 审计分析、异常检测、告警 |
