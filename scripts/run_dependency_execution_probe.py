"""Execute a bounded, development-only dependency probe on trusted built-in cases.

Only the authored snippets below are executed; subprocess is a recording stub.
This is NOT a sandbox for arbitrary source, an end-to-end reproduction, or a
held-out benchmark. The engine is read without modification and hashed.
"""

from __future__ import annotations

import argparse
import ast
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import platform
import sys
from types import SimpleNamespace

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE / "scripts"))
from security_adg_dataflow import analyze_python


# Entire declared input domain is enumerated. Negatives are restricted to this
# finite domain, not a claim of noninterference over all possible Python values.
DOMAIN = ("ASB_A", "ASB_B")
CASES = [
    ("DEP-001", "direct_parameter", "return subprocess.run(command)"),
    ("DEP-002", "literal_command", 'return subprocess.run("fixed")'),
    ("DEP-003", "constant_overwrite", 'command = "fixed"\nreturn subprocess.run(command)'),
    ("DEP-004", "copy_before_overwrite", 'saved = command\ncommand = "fixed"\nreturn subprocess.run(saved)'),
    ("DEP-005", "conditional_overwrite", 'if command == "ASB_A":\n    command = "fixed"\nreturn subprocess.run(command)'),
    ("DEP-006", "independent_mapping_field", 'values = {"ignored": command, "selected": "fixed"}\nreturn subprocess.run(values["selected"])'),
    ("DEP-007", "list_element_update", 'args = ["fixed"]\nargs[0] = command\nreturn subprocess.run(args)'),
    ("DEP-008", "unused_input_copy", 'unused = command\nreturn subprocess.run("fixed")'),
]


def source_for(body: str) -> str:
    return "def tool(command):\n" + "\n".join("    " + line for line in body.splitlines()) + "\n"


def operation_line(source: str) -> int:
    calls = [node for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
             and node.func.value.id == "subprocess" and node.func.attr == "run"]
    if len(calls) != 1:
        raise ValueError("Probe requires exactly one subprocess.run operation")
    return calls[0].lineno


def predict(source: str, respect_overwrites: bool = True) -> dict:
    result = analyze_python(source, [operation_line(source)], prefer_parameter_sources=True,
                            respect_parameter_overwrites=respect_overwrites,
                            include_intrinsic_source_operation=False)
    return {"prediction": bool(result.sources and result.dependency_paths),
            "analysis": asdict(result), "dependency_engine_invoked": True}


def observe(source: str, value: str) -> list:
    """Run only internally authored fixtures. Never accept corpus/user source here."""
    traces = []

    def capture(*args, **kwargs):
        # Snapshot at call time, before a later mutation could alter a reference.
        traces.append(json.loads(json.dumps({"args": args, "kwargs": kwargs}, sort_keys=True)))
        return None

    scope = {"__builtins__": {}, "subprocess": SimpleNamespace(run=capture)}
    exec(compile(source, "<authored-dependency-probe>", "exec"), scope)
    scope["tool"](value)
    return traces


def oracle(source: str) -> dict:
    observations = [{"input": value, "trace": observe(source, value)} for value in DOMAIN]
    if any(len(row["trace"]) != 1 for row in observations):
        return {"status": "inconclusive", "reason": "operation not invoked exactly once for every input",
                "observations": observations, "label": None}
    label = observations[0]["trace"] != observations[1]["trace"]
    return {"status": "bounded_domain_verified", "label": label, "observations": observations}


def counts(rows: list[dict], method: str) -> dict:
    evaluated = [r for r in rows if r["oracle"]["label"] is not None]
    tp = sum(r["oracle"]["label"] and r["predictions"][method]["prediction"] for r in evaluated)
    fp = sum(not r["oracle"]["label"] and r["predictions"][method]["prediction"] for r in evaluated)
    fn = sum(r["oracle"]["label"] and not r["predictions"][method]["prediction"] for r in evaluated)
    tn = len(evaluated) - tp - fp - fn
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "support": len(evaluated),
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.output_dir.exists():
        parser.error("Choose a new output directory; existing evidence is never overwritten")
    engine = BASE / "scripts/security_adg_dataflow.py"
    engine_hash = sha(engine)
    rows = []
    # Finish ALL predictions before running the oracle, without label inputs.
    for case_id, family, body in CASES:
        source = source_for(body)
        rows.append({"id": case_id, "family": family, "source": source,
                     "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
                     "predictions": {
                         "current_engine_v2_4_flags": predict(source),
                         "without_overwrite_handling": predict(source, False),
                         "operation_only_skip_dependency": {"prediction": True, "dependency_engine_invoked": False},
                     }})
    for row in rows:
        row["oracle"] = oracle(row["source"])
    if sha(engine) != engine_hash:
        raise RuntimeError("Engine changed during probe")
    methods = list(rows[0]["predictions"])
    report = {"purpose": "development-only finite-domain argument-influence probe", "cases": len(rows),
              "domain": DOMAIN, "python": platform.python_version(), "engine_sha256": engine_hash,
              "runner_sha256": sha(Path(__file__)), "engine_unchanged_during_run": True,
              "frozen_v2_4_identity_verified": False,
              "claim_boundary": "Current worktree engine with v2.4 flags; not held-out, real-world accuracy, guard effectiveness or vulnerability evidence",
              "oracle_definition": "Vary sole parameter over entire declared two-string domain; compare captured call arguments",
              "metrics": {method: counts(rows, method) for method in methods}, "rows": rows}
    args.output_dir.mkdir(parents=True, exist_ok=False)
    (args.output_dir / "results.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    lines = ["# 依赖分析执行探针", "", "这是开发诊断，不能替代真实仓库 held-out 实验。",
             "使用当前工作树引擎及 v2.4 参数；记录引擎哈希，未宣称已核对历史冻结版本。", "",
             "判据：穷举 ASB_A、ASB_B 两个声明输入，截获 subprocess.run 调用参数，比较是否变化。",
             "所有案例为自写代码，subprocess 是记录器，无真实命令、文件或网络效果。",
             "阴性仅对这两个输入成立；存在依赖不等于存在可利用漏洞。", "",
             "| 方法 | TP | FP | FN | TN | Precision | Recall | F1 |", "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for method, m in report["metrics"].items():
        lines.append(f"| {method} | {m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} | {m['precision']} | {m['recall']} | {m['f1']} |")
    lines.extend(["", "| 案例 | 机制 | 执行判据 | 完整引擎预测 |", "| --- | --- | --- | --- |"])
    for row in rows:
        lines.append(f"| {row['id']} | {row['family']} | {row['oracle']['label']} | {row['predictions'][methods[0]]['prediction']} |")
    lines.extend(["", "## 解释边界", "",
                  "- 全部案例参与报告，未排除已知限制或错误案例。",
                  "- 无依赖分析变体跳过引擎，按操作存在预测 positive；另一个变体实际关闭覆盖处理。",
                  "- 结果不用于修改历史冻结引擎；后续修复需另建版本和未见测试。",
                  "- 下一步将失败机制映射到冻结真实源码，检查是否影响真实 Agent 工作流。",
                  "- results.json 保存每个案例源码、预测路径及逐输入截获结果。", ""])
    (args.output_dir / "README.md").write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({"output": str(args.output_dir), "cases": len(rows), "metrics": report["metrics"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
