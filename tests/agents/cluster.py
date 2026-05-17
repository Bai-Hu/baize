"""白泽 Agent 集群 — 全流程测试

用白泽项目自身源码作为工作对象，测试完整的治理流程:
  1. coordinator 将白泽源码写入 main repo
  2. writer-a 分析安全相关模块（workspace.rs）
  3. writer-b 分析治理管道模块（pipeline.rs）
  4. critic 审查两份分析报告
  5. coordinator 汇总最终报告

集群拓扑:
  baize-root (L4, ["*"])
  └── coordinator (L3, ["task", "writing", "review"])
      ├── writer-a (L2, ["task", "writing"])
      ├── writer-b (L2, ["task", "writing"])
      └── critic (L2, ["review"])
"""

import argparse
import os
import re
import requests
import sys

from baize_client import BaizeClient


# ─── Agent 封装 ───

class Agent:
    """一个白泽 agent = client + agent_id"""

    def __init__(self, client: BaizeClient, agent_id: str):
        self.client = client
        self.id = agent_id

    def write(self, path: str, content: str, labels: dict | None = None) -> dict:
        return self.client.file_write(self.id, path, content, labels)

    def read(self, path: str) -> dict:
        return self.client.file_read(self.id, path)

    def list_files(self) -> list[str]:
        return self.client.file_list(self.id)

    def push(self, message: str, ref: str | None = None) -> dict:
        return self.client.push(self.id, message, ref)

    def pull(self, ref: str | None = None) -> dict:
        return self.client.pull(self.id, ref)


# ─── 集群注册 ───

def setup_cluster(client: BaizeClient) -> dict[str, Agent]:
    """注册所有 agent，返回 id → Agent 映射"""
    agents = {}

    info = client.register_agent("coordinator", 3, ["task", "writing", "review"])
    agents["coordinator"] = Agent(client, info["id"])
    print(f"  注册: {info['id']} (L{info['level']}, zones={info['zones']})")

    info = client.register_agent("writer-a", 2, ["task", "writing"], parent="coordinator")
    agents["writer-a"] = Agent(client, info["id"])
    print(f"  注册: {info['id']} (L{info['level']}, zones={info['zones']}, parent=coordinator)")

    info = client.register_agent("writer-b", 2, ["task", "writing"], parent="coordinator")
    agents["writer-b"] = Agent(client, info["id"])
    print(f"  注册: {info['id']} (L{info['level']}, zones={info['zones']}, parent=coordinator)")

    info = client.register_agent("critic", 2, ["review"], parent="coordinator")
    agents["critic"] = Agent(client, info["id"])
    print(f"  注册: {info['id']} (L{info['level']}, zones={info['zones']}, parent=coordinator)")

    return agents


# ─── 简易分析工具 ───

def analyze_rust_source(source: str, filename: str) -> str:
    """对 Rust 源码做静态分析，返回结构化报告"""
    lines = source.split("\n")
    total_lines = len(lines)
    code_lines = sum(1 for l in lines if l.strip() and not l.strip().startswith("//"))
    comment_lines = sum(1 for l in lines if l.strip().startswith("//"))

    # 提取 pub fn / fn 定义
    pub_fns = re.findall(r'pub fn (\w+)', source)
    priv_fns = re.findall(r'(?<!pub )fn (\w+)', source)

    # 提取 struct / enum / impl
    structs = re.findall(r'pub struct (\w+)', source)
    enums = re.findall(r'pub enum (\w+)', source)
    impls = re.findall(r'impl (\w+)', source)

    # 提取 use 依赖
    uses = re.findall(r'use (?:crate|super|self)::(\w+)', source)

    # 安全相关关键字
    security_keywords = {
        "validate": 0, "canonicalize": 0, "traversal": 0,
        "permission": 0, "symlink": 0, "hash": 0, "audit": 0,
    }
    for kw in security_keywords:
        security_keywords[kw] = len(re.findall(kw, source, re.IGNORECASE))

    report = f"""# 源码分析: {filename}

## 基本信息
- 总行数: {total_lines}
- 代码行: {code_lines}
- 注释行: {comment_lines}
- 代码占比: {code_lines / max(total_lines, 1) * 100:.0f}%

## 公开接口 (pub fn: {len(pub_fns)})
{chr(10).join(f'  - `{fn}()`' for fn in pub_fns) if pub_fns else '  (无)'}

## 私有函数 (fn: {len(priv_fns)})
{chr(10).join(f'  - `{fn}()`' for fn in priv_fns) if priv_fns else '  (无)'}

## 类型定义
- struct: {', '.join(structs) if structs else '(无)'}
- enum: {', '.join(enums) if enums else '(无)'}
- impl blocks: {', '.join(impls) if impls else '(无)'}

## 模块依赖
{', '.join(set(uses)) if uses else '(无内部依赖)'}

## 安全相关关键字出现次数
{chr(10).join(f'  - {kw}: {count}' for kw, count in security_keywords.items() if count > 0)}
"""
    return report


def analyze_audit_coverage(source: str) -> str:
    """分析审计相关代码覆盖情况"""
    audit_calls = re.findall(r'self\.audit\("(\w+)"', source)
    pipe_fns = re.findall(r'pub fn (pipe_\w+)', source)

    report = f"""# 审计覆盖分析

## 已审计操作 ({len(audit_calls)} 处)
{chr(10).join(f'  - {op}' for op in sorted(set(audit_calls)))}

## 所有管道操作 (pipe_*)
{chr(10).join(f'  - {fn}' for fn in pipe_fns)}

## 未审计的管道操作
"""
    audited_pipes = {f"pipe_{op}" for op in audit_calls}
    unverified = [fn for fn in pipe_fns if fn not in audited_pipes]
    if unverified:
        report += chr(10).join(f'  - {fn}' for fn in unverified)
    else:
        report += "  (所有管道操作均已审计)"

    return report


# ─── Agent 行为 ───

def coordinator_submit_project(coordinator: Agent, project_dir: str) -> list[str]:
    """Coordinator 将项目源码写入 main repo 并 push"""
    source_files = {
        "task/src/workspace.rs": "crates/baize-core/src/workspace.rs",
        "task/src/pipeline.rs": "crates/baize-server/src/pipeline/mod.rs",
    }

    pushed = []
    for baize_path, local_rel in source_files.items():
        local_path = os.path.join(project_dir, local_rel)
        if not os.path.exists(local_path):
            print(f"  跳过: {local_rel} 不存在")
            continue
        with open(local_path) as f:
            content = f.read()
        coordinator.write(baize_path, content, labels={"source": "baize"})
        pushed.append(baize_path)
        print(f"  coordinator: 写入 {baize_path} ({len(content)} bytes)")

    result = coordinator.push("提交白泽项目源码", ref="task")
    print(f"  coordinator: push task ({len(pushed)} 文件, ref={result.get('ref_name', 'task')})")
    return pushed


def writer_analyze(agent: Agent, target_file: str, wave_ref: str,
                   analyzer) -> str:
    """Writer agent: pull 源码 → 分析 → push 报告

    注意: pull 会先清空 workspace（clear_all），所以必须先 pull 再 write。
    """
    agent.pull("task")

    # 读取源码
    source_data = agent.read(target_file)
    source_code = source_data.get("content", "")

    # 运行分析
    report = analyzer(source_code, target_file)

    # 写入分析报告
    report_path = f"writing/{agent.id}/analysis.md"
    agent.write(report_path, report, labels={"wave": "0", "agent": agent.id})

    result = agent.push(f"Wave 0: {agent.id} 分析报告", ref=wave_ref)
    print(f"  {agent.id}: 分析 {target_file} → {report_path} → push {result.get('ref_name', wave_ref)}")
    return wave_ref


def consolidate_writes(coordinator: Agent, writer_refs: list[str],
                       consolidated_ref: str) -> None:
    """Coordinator 从 writing zone 拉取所有 writer 输出，汇总到 review zone"""
    parts = []
    for ref in writer_refs:
        coordinator.pull(ref)

    for writer_name in ["writer-a", "writer-b"]:
        path = f"writing/{writer_name}/analysis.md"
        try:
            f = coordinator.read(path)
            parts.append(f.get("content", ""))
        except requests.exceptions.HTTPError:
            parts.append(f"(无法读取 {path})")

    consolidated = "# 白泽项目分析报告汇总\n\n" + "\n---\n".join(parts)
    coordinator.write("review/consolidated.md", consolidated,
                      labels={"wave": "0", "type": "consolidated"})

    result = coordinator.push("Coordinator 汇总分析报告", ref=consolidated_ref)
    print(f"  coordinator: 汇总 {len(parts)} 份报告 → push {result.get('ref_name', consolidated_ref)}")


def critic_review(agent: Agent, consolidated_ref: str,
                  critique_ref: str) -> None:
    """Critic agent: 拉取汇总报告 → 生成评审意见 → push"""
    agent.pull(consolidated_ref)

    # 读取汇总报告
    consolidated = agent.read("review/consolidated.md")
    content = consolidated.get("content", "")

    # 简易评审：统计报告特征
    sections = content.count("## ")
    has_security = "安全" in content or "security" in content.lower()
    has_coverage = "覆盖" in content or "audit" in content.lower()
    total_chars = len(content)

    critique = f"""# 白泽项目评审报告

## 评审对象
- 分析报告汇总 ({total_chars} chars, {sections} 个章节)

## 评审结论

### 报告质量
- {'通过' if sections >= 4 else '不足'}: 报告包含 {sections} 个分析章节
- {'通过' if has_security else '缺失'}: 安全相关分析{'已覆盖' if has_security else '未覆盖'}
- {'通过' if has_coverage else '缺失'}: 审计覆盖分析{'已包含' if has_coverage else '未包含'}

### 发现
1. workspace.rs 包含路径验证和符号链接防护，安全基础扎实
2. pipeline.rs 的审计覆盖需要逐操作验证
3. 两份报告互补 — 一份侧重安全机制，一份侧重审计完整性

### 建议
- 后续可增加测试覆盖率分析
- 建议增加错误处理路径的审计覆盖验证

评审: critic
"""

    agent.write("review/critique.md", critique,
                labels={"wave": "0", "type": "critique"})

    result = agent.push("Critic 评审报告", ref=critique_ref)
    print(f"  critic: 写入 review/critique.md → push {result.get('ref_name', critique_ref)}")


# ─── 验证 ───
# 注意: PASS/FAIL 是模块级计数器，verify_cluster 设计为单次调用。
# 如果需要多次调用或集成到测试框架，应改为类封装。

PASS = 0
FAIL = 0


def check(desc: str, condition: bool):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  PASS: {desc}")
    else:
        FAIL += 1
        print(f"  FAIL: {desc}")


def verify_cluster(client: BaizeClient, agents: dict[str, Agent]):
    """验证集群治理能力"""
    print("\n--- 验证 ---")

    # 1. Agent 注册验证
    all_agents = client.list_agents()
    check("agent 总数 >= 5 (含 root)", len(all_agents) >= 5)

    agent_ids = {a["id"] for a in all_agents}
    for name in ["coordinator", "writer-a", "writer-b", "critic"]:
        check(f"{name} 已注册", name in agent_ids)

    # 2. 身份链验证
    chain = client.trace_identity("writer-a")
    chain_ids = [c["agent_id"] for c in chain]
    check("writer-a 身份链: writer-a → coordinator → root",
          chain_ids == ["writer-a", "coordinator", "baize-root"])

    # 3. Zone 隔离验证
    try:
        client.file_write("critic", "writing/test.md", "should fail")
        check("critic 不能写 writing zone", False)
    except requests.exceptions.HTTPError as e:
        check("critic 不能写 writing zone (403)",
              e.response.status_code == 403)

    try:
        client.file_write("writer-a", "review/test.md", "should fail")
        check("writer-a 不能写 review zone", False)
    except requests.exceptions.HTTPError as e:
        check("writer-a 不能写 review zone (403)",
              e.response.status_code == 403)

    # critic pull 只能获取 review zone 文件
    client.pull("critic", ref="consolidated/wave-0")
    critic_files = client.file_list("critic")
    has_review = any("review/" in f for f in critic_files)
    no_writing = all("writing/" not in f for f in critic_files)
    check("critic pull 后有 review zone 文件", has_review)
    check("critic pull 后没有 writing zone 文件", no_writing)

    # 4. 文件内容验证
    for name in ["coordinator", "writer-a", "writer-b"]:
        files = client.file_list(name)
        check(f"{name} workspace 有文件", len(files) > 0)

    # 验证 writer 报告包含分析内容
    writer_a_files = client.file_list("writer-a")
    check("writer-a 生成了分析报告",
          any("analysis" in f for f in writer_a_files))

    writer_b_files = client.file_list("writer-b")
    check("writer-b 生成了分析报告",
          any("analysis" in f for f in writer_b_files))

    # 5. 审计完整性
    audit = client.audit_query()
    records = audit.get("records", [])
    check("审计记录 >= 15 条", len(records) >= 15)

    audit_types = {r.get("type") for r in records}
    for expected in ["agent_register", "file_write", "file_read", "push", "pull"]:
        check(f"审计含 {expected} 操作", expected in audit_types)

    # 6. 审计 target 字段
    with_target = [r for r in records if r.get("target") and r.get("target") != "-"]
    check("审计记录含 target 字段", len(with_target) > 0)


# ─── 主流程 ───

def main():
    parser = argparse.ArgumentParser(description="白泽 Agent 集群 — 全流程测试")
    parser.add_argument("--base", default="http://127.0.0.1:9478",
                        help="白泽 API 地址")
    parser.add_argument("--project", default=os.environ.get("BAIZE_PROJECT", ""),
                        help="白泽项目目录（用于读取源码）")
    args = parser.parse_args()

    client = BaizeClient(args.base)
    project_dir = args.project

    if not project_dir:
        # 自动推断: 从脚本位置往上找 Cargo.toml
        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_dir = os.path.join(script_dir, "..", "..")
        project_dir = os.path.normpath(project_dir)

    # 验证项目目录
    if not os.path.exists(os.path.join(project_dir, "Cargo.toml")):
        print(f"错误: 找不到白泽项目目录 (尝试: {project_dir})")
        print("  使用 --project 或设置 BAIZE_PROJECT 环境变量")
        sys.exit(1)

    # 等待 server 就绪
    print("等待白泽 server...")
    for i in range(30):
        try:
            client.list_agents()
            break
        except Exception:
            import time
            time.sleep(0.5)
    else:
        print("错误: 无法连接白泽 server")
        sys.exit(1)
    print(f"  server 已就绪, 项目目录: {project_dir}")

    # 注册集群
    print("\n--- 注册集群 ---")
    agents = setup_cluster(client)

    # Step 1: coordinator 提交项目源码
    print("\n--- Step 1: Coordinator 提交白泽源码 ---")
    coordinator = agents["coordinator"]
    coordinator_submit_project(coordinator, project_dir)

    # Step 2: writer-a 分析安全模块 (workspace.rs)
    #         writer-b 分析治理管道 (pipeline.rs)
    print("\n--- Step 2: Writer 分析源码 ---")
    writer_a_ref = writer_analyze(
        agents["writer-a"], "task/src/workspace.rs",
        "wave-0/writer-a", analyze_rust_source)
    writer_b_ref = writer_analyze(
        agents["writer-b"], "task/src/pipeline.rs",
        "wave-0/writer-b", lambda src, name: (
            analyze_rust_source(src, name) +
            "\n" + analyze_audit_coverage(src)
        ))

    # Step 3: coordinator 跨 zone 搬运到 review zone
    print("\n--- Step 3: Coordinator 跨 zone 搬运 ---")
    consolidate_writes(coordinator, [writer_a_ref, writer_b_ref],
                       "consolidated/wave-0")

    # Step 4: critic 评审
    print("\n--- Step 4: Critic 评审 ---")
    critic_review(agents["critic"], "consolidated/wave-0",
                  "critique/wave-0")

    # Step 5: coordinator 收取最终报告
    print("\n--- Step 5: Coordinator 收取报告 ---")
    coordinator.pull("critique/wave-0")
    result = coordinator.read("review/critique.md")
    print(f"  coordinator: 读取评审报告 ({result.get('size', 0)} bytes)")

    # 验证
    verify_cluster(client, agents)

    # 结果
    total = PASS + FAIL
    print(f"\n{'=' * 40}")
    print(f"  结果: {PASS}/{total} 通过, {FAIL} 失败")
    print(f"{'=' * 40}")

    if FAIL > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
