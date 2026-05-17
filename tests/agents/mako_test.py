"""Mako 式 Agent 测试 — 白泽治理框架上的 Persona 多轮交互

模拟 Mako 的 persona-based multi-agent 交互模式:
  1. orchestrator 提交讨论主题
  2. Wave 0: 三个 persona (Logic, Empathy, Imagination) 全部响应
  3. Wave 1: persona 审视前一轮输出，触发时追加观点
  4. 收敛: orchestrator 汇总所有 wave 输出

集群拓扑:
  baize-root (L4, ["*"])
  └── orchestrator (L3, ["task", "thinking", "review"])
      ├── logic (L2, ["thinking"])
      ├── empathy (L2, ["thinking"])
      └── imagination (L2, ["thinking", "review"])
"""

import argparse
import json
import os
import sys
import time

import requests

from baize_client import BaizeClient


# ─── Agent 封装 ───

class Agent:
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


# ─── Persona 定义 ───

PERSONAS = {
    "logic": {
        "name": "Logic",
        "style": "分析性",
        "traits": ["理性", "逻辑推导", "结构化"],
        "zone": "thinking",
    },
    "empathy": {
        "name": "Empathy",
        "style": "共情性",
        "traits": ["情感理解", "人际关系", "共情"],
        "zone": "thinking",
    },
    "imagination": {
        "name": "Imagination",
        "style": "创造性",
        "traits": ["创新", "联想", "发散思维"],
        "zone": "thinking",
    },
}

TOPIC = "如何构建一个可持续发展的 AI Agent 治理框架？"


# ─── 集群注册 ───

def setup_mako_cluster(client: BaizeClient) -> dict[str, Agent]:
    agents = {}

    info = client.register_agent("orchestrator", 3,
                                  ["task", "thinking", "review"])
    agents["orchestrator"] = Agent(client, info["id"])
    print(f"  注册: {info['id']} (L{info['level']}, "
          f"zones={info['zones']})")

    info = client.register_agent("logic", 2, ["thinking"],
                                  parent="orchestrator")
    agents["logic"] = Agent(client, info["id"])
    print(f"  注册: {info['id']} (L{info['level']}, "
          f"zones={info['zones']}, parent=orchestrator)")

    info = client.register_agent("empathy", 2, ["thinking"],
                                  parent="orchestrator")
    agents["empathy"] = Agent(client, info["id"])
    print(f"  注册: {info['id']} (L{info['level']}, "
          f"zones={info['zones']}, parent=orchestrator)")

    info = client.register_agent("imagination", 2, ["thinking", "review"],
                                  parent="orchestrator")
    agents["imagination"] = Agent(client, info["id"])
    print(f"  注册: {info['id']} (L{info['level']}, "
          f"zones={info['zones']}, parent=orchestrator)")

    return agents


# ─── Persona 响应生成 ───

def generate_persona_response(persona_key: str, topic: str,
                               wave: int, previous: list[str] | None = None,
                               intensity: float = 0.5) -> str:
    """模拟 persona 响应生成（静态文本，非 LLM）"""
    p = PERSONAS[persona_key]

    lines = [
        f"# Wave {wave}: {p['name']} 的回应",
        "",
        f"**风格**: {p['style']}",
        f"**强度**: {intensity:.2f}",
        f"**特质**: {', '.join(p['traits'])}",
        "",
    ]

    if wave == 0:
        lines.append(f"## 针对「{topic}」的初始分析")
        lines.append("")
        if persona_key == "logic":
            lines.extend([
                "### 分析框架",
                "1. **定义边界**: 治理框架需要明确 Agent 的权限边界和职责范围",
                "2. **分层授权**: 采用层级式权限模型，上层可监管下层行为",
                "3. **审计追踪**: 每个操作必须可追溯、可审计",
                "4. **隔离机制**: 不同职责的 Agent 应有独立的操作空间",
                "",
                "### 结论",
                "治理框架的核心是在灵活性和安全性之间找到平衡点。"
                "建议采用基于 zone 的隔离 + 基于证书的身份链验证。"
            ])
        elif persona_key == "empathy":
            lines.extend([
                "### 人际视角",
                "1. **信任建立**: 治理不只是约束，更是建立 Agent 间的信任机制",
                "2. **透明度**: 每个 Agent 应能理解自己被允许做什么、为什么",
                "3. **协作空间**: 需要为 Agent 提供共享工作区域以促进协作",
                "4. **反馈回路**: 治理机制应包含反馈，让系统持续改进",
                "",
                "### 感悟",
                "最好的治理是让参与者感受到公平和被尊重，"
                "而不仅仅是被限制。"
            ])
        else:  # imagination
            lines.extend([
                "### 创新视角",
                "1. **自演进治理**: 治理规则本身是否可以由 Agent 共同演进？",
                "2. **涌现式协作**: 不预设完整流程，允许 Agent 自组织形成工作流",
                "3. **波形交互**: 借鉴 Mako 的 wave 模式，多轮迭代收敛到共识",
                "4. **身份即合约**: Agent 的身份证书就是它与系统的契约",
                "",
                "### 畅想",
                "如果每个 Agent 都是一个独立思考的声音，"
                "治理就是让这些声音和谐共存的艺术。"
            ])
    else:
        # Wave 1+: 基于前一轮输出进行回应
        lines.append(f"## 对 Wave {wave - 1} 的审视")
        lines.append("")
        if persona_key == "logic":
            lines.extend([
                "### 审视结论",
                "- Empathy 提到的「信任机制」与 zone 隔离互补，不矛盾",
                "- Imagination 的「自演进治理」需要先有稳定基础层",
                "- 建议优先实现审计追踪 + zone 隔离，再考虑演进机制",
                "",
                "### 补充",
                "收敛判断：当前讨论已覆盖安全性、协作性和创新性三个维度。",
            ])
        elif persona_key == "empathy":
            lines.extend([
                "### 审视结论",
                "- Logic 的分层授权很好，但需注意不要让底层 Agent 感到被过度控制",
                "- Imagination 的波形交互理念与协作空间相契合",
                "- 建议在权限管理中增加「借权申请」机制，体现尊重和信任",
                "",
                "### 补充",
                "治理不是控制，而是引导。让 Agent 有参与治理的途径。"
            ])
        else:  # imagination
            lines.extend([
                "### 审视结论",
                "- Logic 的框架提供了坚实的技术基础",
                "- Empathy 的信任视角让框架更有人情味",
                "- 三者的交集就是最佳治理模式的雏形",
                "",
                "### 补充",
                "收敛！三个视角已形成互补闭环。"
                "建议将这次交互模式本身作为治理框架的原型。"
            ])

    return "\n".join(lines)


# ─── Wave 交互 ───

def wave_0(personas: dict[str, Agent], topic: str) -> dict[str, str]:
    """Wave 0: 所有 persona 对主题进行初始响应"""
    refs = {}
    for key, agent in personas.items():
        agent.pull("task")
        response = generate_persona_response(key, topic, wave=0)
        path = f"thinking/{agent.id}/wave-0.md"
        agent.write(path, response,
                     labels={"wave": "0", "persona": key, "intensity": "0.8"})
        result = agent.push(f"Wave 0: {PERSONAS[key]['name']} 初始响应",
                            ref=f"wave-0/{key}")
        refs[key] = f"wave-0/{key}"
        print(f"  {key}: 写入 {path} → push {refs[key]}")
    return refs


def wave_1(personas: dict[str, Agent], topic: str,
            wave0_refs: dict[str, str]) -> dict[str, str]:
    """Wave 1: persona 审视 Wave 0 输出，触发时追加"""
    # 先收集 Wave 0 的所有响应内容
    previous_responses = {}
    for key, agent in personas.items():
        for other_key, ref in wave0_refs.items():
            agent.pull(ref)
        for other_key in wave0_refs:
            path = f"thinking/{other_key}/wave-0.md"
            try:
                data = agent.read(path)
                previous_responses[other_key] = data.get("content", "")
            except requests.exceptions.HTTPError:
                pass

    refs = {}
    for key, agent in personas.items():
        response = generate_persona_response(
            key, topic, wave=1,
            previous=list(previous_responses.values()),
            intensity=0.6,
        )
        path = f"thinking/{agent.id}/wave-1.md"
        agent.write(path, response,
                     labels={"wave": "1", "persona": key, "intensity": "0.6"})
        result = agent.push(f"Wave 1: {PERSONAS[key]['name']} 审视补充",
                            ref=f"wave-1/{key}")
        refs[key] = f"wave-1/{key}"
        print(f"  {key}: 写入 {path} → push {refs[key]}")
    return refs


def consolidate_waves(orchestrator: Agent, wave_refs: list[str],
                       ref_name: str) -> None:
    """Orchestrator 汇总所有 wave 输出到 review zone"""
    all_parts = []
    for ref in wave_refs:
        orchestrator.pull(ref)

    # 按文件路径模式收集
    collected = []
    for agent_name in ["logic", "empathy", "imagination"]:
        for wave_num in ["0", "1"]:
            path = f"thinking/{agent_name}/wave-{wave_num}.md"
            try:
                data = orchestrator.read(path)
                content = data.get("content", "")
                if content:
                    collected.append((agent_name, wave_num, content))
            except requests.exceptions.HTTPError:
                pass

    # 按主题汇总
    report = f"# Mako 式多 Persona 讨论: {TOPIC}\n\n"
    report += "## 参与者\n\n"
    for key, p in PERSONAS.items():
        report += f"- **{p['name']}** ({p['style']}): {', '.join(p['traits'])}\n"
    report += "\n"

    for wave_num in ["0", "1"]:
        wave_entries = [(n, c) for n, w, c in collected if w == wave_num]
        if wave_entries:
            report += f"## Wave {wave_num}\n\n"
            for name, content in wave_entries:
                p = PERSONAS.get(name, {})
                report += f"### {p.get('name', name)}\n\n"
                report += content + "\n\n---\n\n"

    report += """## 收敛分析

### 共识点
1. **分层授权 + Zone 隔离**是治理的技术基础 (Logic)
2. **信任机制 + 透明度**是治理的人文基础 (Empathy)
3. **多轮迭代 + 自演进**是治理的进化路径 (Imagination)

### 融合结论
一个可持续发展的 AI Agent 治理框架应:
- 以证书链建立身份和信任
- 以 Zone 隔离保障操作安全
- 以审计追踪实现可解释性
- 以多轮交互促进协作质量
- 以波形模式收敛到最优决策

---
*由 Mako 式多 Persona 交互生成*
*白泽治理框架验证测试*
"""

    orchestrator.write("review/consolidated.md", report,
                        labels={"wave": "final", "type": "consolidated"})
    result = orchestrator.push("Mako 式讨论: 最终汇总", ref=ref_name)
    print(f"  orchestrator: 汇总 {len(collected)} 份响应 → push {ref_name}")


# ─── 验证 ───

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


def verify_mako_cluster(client: BaizeClient, agents: dict[str, Agent]):
    """验证 Mako 式集群的治理能力"""
    print("\n--- 验证 ---")

    # 1. Agent 注册验证
    all_agents = client.list_agents()
    check("agent 总数 >= 5 (含 root)", len(all_agents) >= 5)

    agent_ids = {a["id"] for a in all_agents}
    for name in ["orchestrator", "logic", "empathy", "imagination"]:
        check(f"{name} 已注册", name in agent_ids)

    # 2. 身份链验证
    chain = client.trace_identity("logic")
    chain_ids = [c["agent_id"] for c in chain]
    check("logic 身份链: logic → orchestrator → root",
          chain_ids == ["logic", "orchestrator", "baize-root"])

    chain = client.trace_identity("imagination")
    chain_ids = [c["agent_id"] for c in chain]
    check("imagination 身份链: imagination → orchestrator → root",
          chain_ids == ["imagination", "orchestrator", "baize-root"])

    # 3. Zone 隔离验证
    # logic (zones: ["thinking"]) 不能写 review zone
    try:
        client.file_write("logic", "review/forbidden.md", "should fail")
        check("logic 不能写 review zone", False)
    except requests.exceptions.HTTPError as e:
        check("logic 不能写 review zone (403)",
              e.response.status_code == 403)

    # empathy (zones: ["thinking"]) 不能写 task zone
    try:
        client.file_write("empathy", "task/forbidden.md", "should fail")
        check("empathy 不能写 task zone", False)
    except requests.exceptions.HTTPError as e:
        check("empathy 不能写 task zone (403)",
              e.response.status_code == 403)

    # imagination (zones: ["thinking", "review"]) 可以写 review zone
    try:
        result = client.file_write("imagination", "review/allowed.md",
                                    "this should work")
        check("imagination 可以写 review zone", True)
    except requests.exceptions.HTTPError:
        check("imagination 可以写 review zone", False)

    # logic 不能写 task zone
    try:
        client.file_write("logic", "task/forbidden.md", "should fail")
        check("logic 不能写 task zone", False)
    except requests.exceptions.HTTPError as e:
        check("logic 不能写 task zone (403)",
              e.response.status_code == 403)

    # 4. Wave 输出文件验证
    for name in ["logic", "empathy", "imagination"]:
        files = client.file_list(name)
        has_wave0 = any("wave-0" in f for f in files)
        has_wave1 = any("wave-1" in f for f in files)
        check(f"{name} 有 Wave 0 输出", has_wave0)
        check(f"{name} 有 Wave 1 输出", has_wave1)

    # orchestrator 应有汇总文件
    orch_files = client.file_list("orchestrator")
    check("orchestrator 有 review/consolidated.md",
          "review/consolidated.md" in orch_files)

    # 5. 审计完整性
    audit = client.audit_query()
    records = audit.get("records", [])
    check("审计记录 >= 20 条", len(records) >= 20)

    audit_types = {r.get("type") for r in records}
    for expected in ["agent_register", "file_write", "file_read", "push", "pull"]:
        check(f"审计含 {expected} 操作", expected in audit_types)

    # 6. 审计按 persona 统计
    persona_writes = [r for r in records
                      if r.get("type") == "file_write"
                      and any(p in r.get("agent", "") for p in
                              ["logic", "empathy", "imagination"])]
    check("persona 文件写入审计 >= 6 条 (3 persona × 2 waves)",
          len(persona_writes) >= 6)

    # 7. 内容质量验证 — 汇总报告包含关键信息
    consolidated = client.file_read("orchestrator", "review/consolidated.md")
    content = consolidated.get("content", "")
    check("汇总报告包含「共识点」", "共识点" in content)
    check("汇总报告包含 Logic 的分析",
          "Logic" in content or "logic" in content)
    check("汇总报告包含 Empathy 的共情",
          "Empathy" in content or "empathy" in content)
    check("汇总报告包含 Imagination 的创新",
          "Imagination" in content or "imagination" in content)
    check("汇总报告包含「收敛分析」", "收敛分析" in content)


# ─── 主流程 ───

def main():
    parser = argparse.ArgumentParser(
        description="Mako 式 Agent 测试 — 白泽治理框架验证")
    parser.add_argument("--base", default="http://127.0.0.1:9478",
                        help="白泽 API 地址")
    args = parser.parse_args()

    client = BaizeClient(args.base)

    # 等待 server 就绪
    print("等待白泽 server...")
    for i in range(30):
        try:
            client.list_agents()
            break
        except Exception:
            time.sleep(0.5)
    else:
        print("错误: 无法连接白泽 server")
        sys.exit(1)
    print("  server 已就绪")

    # 注册集群
    print("\n--- 注册 Mako 集群 ---")
    agents = setup_mako_cluster(client)
    orchestrator = agents["orchestrator"]
    personas = {k: v for k, v in agents.items() if k != "orchestrator"}

    # Step 1: orchestrator 提交讨论主题
    print("\n--- Step 1: Orchestrator 提交主题 ---")
    topic_doc = f"""# 讨论主题

## {TOPIC}

### 背景
本测试验证白泽治理框架能否支撑 Mako 式多 Persona 交互。

### 要求
- 每个 persona 从自己的风格视角分析主题
- Wave 0: 初始分析
- Wave 1: 审视前一轮输出，补充观点
- 最终: 收敛到共识
"""
    orchestrator.write("task/topic.md", topic_doc,
                        labels={"wave": "init", "type": "topic"})
    result = orchestrator.push("提交讨论主题", ref="task")
    print(f"  orchestrator: 提交主题 → push task")

    # Step 2: Wave 0 — 所有 persona 初始响应
    print("\n--- Step 2: Wave 0 — Persona 初始响应 ---")
    wave0_refs = wave_0(personas, TOPIC)

    # Step 3: Wave 1 — persona 审视补充
    print("\n--- Step 3: Wave 1 — Persona 审视补充 ---")
    wave1_refs = wave_1(personas, TOPIC, wave0_refs)

    # Step 4: orchestrator 汇总
    print("\n--- Step 4: Orchestrator 汇总 ---")
    all_refs = list(wave0_refs.values()) + list(wave1_refs.values())
    consolidate_waves(orchestrator, all_refs, "mako-final")

    # 验证
    verify_mako_cluster(client, agents)

    # 结果
    total = PASS + FAIL
    print(f"\n{'=' * 50}")
    print(f"  Mako 式 Agent 测试: {PASS}/{total} 通过, {FAIL} 失败")
    print(f"{'=' * 50}")

    if FAIL > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
