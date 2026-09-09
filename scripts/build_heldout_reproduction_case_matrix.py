#!/usr/bin/env python3
"""Build a paper-facing matrix from held-out local reproduction evidence.

This script turns per-case evidence JSON files into a compact case-study
matrix. The matrix is deliberately not a metric report: it supports qualitative
RQ3/RQ4 discussion about behavior reachability, guard context, and claim
boundaries while independent held-out labels are still pending.
"""

from __future__ import annotations

import argparse
import csv
import html
import json
from collections import Counter
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = BASE_DIR / "analysis" / "reproduction" / "heldout"
DEFAULT_OUTPUT_DIR = BASE_DIR / "analysis" / "reproduction" / "case_matrix"


ECOSYSTEM_BY_REPO = {
    "dddabtc/winremote-mcp": "MCP / desktop automation",
    "nexu-io/html-anything": "Coding agent / skill marketplace",
}


BEHAVIOR_FAMILY_BY_STATUS = {
    "confirmed_mcp_tool_parameter_to_powershell_command_argument": "shell command execution",
    "confirmed_mcp_app_launch_parameter_to_powershell_start_process": "application launch",
    "confirmed_mcp_notification_parameter_to_guarded_powershell_toast_script": "desktop notification script",
    "confirmed_mcp_ping_parameter_to_argv_list_network_process": "network diagnostic process",
    "confirmed_mcp_service_start_parameter_to_guarded_powershell_service_control": "service control",
    "confirmed_openclaw_agent_probe_spawn_path_platform_conditional_shell": "agent CLI discovery process",
    "confirmed_guarded_github_tarball_to_fixed_argv_tar_extraction": "external tarball extraction",
    "confirmed_guarded_tarball_download_to_internal_scratch_file_write": "external content file write",
    "confirmed_guarded_skill_markdown_to_staged_install_file_write": "validated skill file write",
}


SINK_FAMILY_BY_STATUS = {
    "confirmed_mcp_tool_parameter_to_powershell_command_argument": "PowerShell -Command",
    "confirmed_mcp_app_launch_parameter_to_powershell_start_process": "PowerShell Start-Process",
    "confirmed_mcp_notification_parameter_to_guarded_powershell_toast_script": "PowerShell toast script",
    "confirmed_mcp_ping_parameter_to_argv_list_network_process": "subprocess argv list",
    "confirmed_mcp_service_start_parameter_to_guarded_powershell_service_control": "PowerShell Start-Service",
    "confirmed_openclaw_agent_probe_spawn_path_platform_conditional_shell": "child_process.spawn",
    "confirmed_guarded_github_tarball_to_fixed_argv_tar_extraction": "child_process.spawn tar",
    "confirmed_guarded_tarball_download_to_internal_scratch_file_write": "fs.writeFile",
    "confirmed_guarded_skill_markdown_to_staged_install_file_write": "fs.writeFile",
}


TRUST_BOUNDARY_BY_STATUS = {
    "confirmed_mcp_tool_parameter_to_powershell_command_argument": "MCP client parameter to local shell",
    "confirmed_mcp_app_launch_parameter_to_powershell_start_process": "MCP client parameter to desktop process launch",
    "confirmed_mcp_notification_parameter_to_guarded_powershell_toast_script": "MCP client text to local notification script",
    "confirmed_mcp_ping_parameter_to_argv_list_network_process": "MCP client host parameter to local network process",
    "confirmed_mcp_service_start_parameter_to_guarded_powershell_service_control": "MCP client service name to local service control",
    "confirmed_openclaw_agent_probe_spawn_path_platform_conditional_shell": "configured agent binary path to local agent CLI probe",
    "confirmed_guarded_github_tarball_to_fixed_argv_tar_extraction": "public GitHub tarball to local extraction toolchain",
    "confirmed_guarded_tarball_download_to_internal_scratch_file_write": "public GitHub response body to local scratch archive",
    "confirmed_guarded_skill_markdown_to_staged_install_file_write": "external skill package content to staged local install",
}


def read_records(input_dir: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not input_dir.exists():
        return records
    for path in sorted(input_dir.glob("*.latest.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        record["_source_file"] = path.resolve().relative_to(BASE_DIR).as_posix()
        records.append(record)
    return records


def display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return resolved.relative_to(BASE_DIR).as_posix()
    except ValueError:
        return resolved.as_posix()


def case_id(record: dict[str, Any]) -> str:
    return str(record.get("scouting_id") or record.get("reproduction_id") or record.get("task_id") or "")


def status_group(status: str) -> str:
    if status.startswith("confirmed_"):
        return "confirmed_behavior"
    if status.startswith("source_level_signal_incomplete"):
        return "incomplete_source_signal"
    return "other"


def any_true_in_dict(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    return any(v is True for v in value.values())


def guard_posture(record: dict[str, Any]) -> str:
    status = str(record.get("status", ""))
    classification = str(record.get("claim_boundary", {}).get("classification", "")).lower()
    if "guarded" in status or "guarded" in classification:
        return "guarded"
    guard_keys = [
        "preflight_guard_signals",
        "shared_guard_signals",
        "validation_observations",
        "remote_boundary_signals",
    ]
    if any(any_true_in_dict(record.get(key)) for key in guard_keys):
        return "guard_context_present"
    if record.get("security_adg_guard_prediction") is True:
        return "guard_context_present"
    return "no_guard_confirmed"


def evidence_mode(record: dict[str, Any]) -> str:
    safety = str(record.get("payload_safety", "")).lower()
    if "monkeypatch" in safety:
        return "local monkeypatch proof"
    if "source-level" in safety or "source level" in safety:
        return "source-level construction proof"
    if record.get("marker_seen") is True:
        return "benign runtime marker"
    return "local evidence record"


def destructive_effects(record: dict[str, Any]) -> str:
    flags = {
        "shell_executed": record.get("shell_executed"),
        "network_used": record.get("network_used"),
        "file_write_performed": record.get("file_write_performed"),
        "dependency_install_performed": record.get("dependency_install_performed"),
        "real_tar_executed": record.get("real_tar_executed"),
        "real_spawn_executed": record.get("real_spawn_executed"),
    }
    positives = [name for name, value in flags.items() if value is True]
    if positives:
        return ", ".join(positives)
    return "none recorded"


def source_to_sink_path(record: dict[str, Any]) -> str:
    proof = record.get("unexecuted_construction_proof", {})
    path = proof.get("source_to_sink_path")
    if isinstance(path, list) and path:
        return " -> ".join(str(item) for item in path)
    operation = record.get("operation")
    return str(operation or "")


def short_claim_boundary(record: dict[str, Any]) -> str:
    boundary = record.get("claim_boundary", {})
    if isinstance(boundary, dict):
        classification = boundary.get("classification")
        if classification:
            return str(classification)
    return "not specified"


def not_claimed(record: dict[str, Any]) -> str:
    boundary = record.get("claim_boundary", {})
    reasons = boundary.get("why_not_cve_ready") if isinstance(boundary, dict) else None
    if isinstance(reasons, list) and reasons:
        return "; ".join(str(reason) for reason in reasons[:2])
    if isinstance(boundary, dict) and boundary.get("not_a_vulnerability_claim"):
        return "not a vulnerability claim"
    return "final vulnerability claim not established"


def to_matrix_row(record: dict[str, Any]) -> dict[str, Any]:
    status = str(record.get("status", ""))
    repo = str(record.get("repository", ""))
    return {
        "id": case_id(record),
        "task_id": record.get("task_id", ""),
        "repository": repo,
        "ecosystem": ECOSYSTEM_BY_REPO.get(repo, "unknown"),
        "frozen_commit": record.get("frozen_commit", ""),
        "file": record.get("candidate_file", ""),
        "line": record.get("candidate_line", ""),
        "status": status,
        "status_group": status_group(status),
        "behavior_family": BEHAVIOR_FAMILY_BY_STATUS.get(status, "security-sensitive behavior"),
        "sink_family": SINK_FAMILY_BY_STATUS.get(status, "unknown sink"),
        "trust_boundary": TRUST_BOUNDARY_BY_STATUS.get(status, "not classified"),
        "dependency_path": source_to_sink_path(record),
        "guard_posture": guard_posture(record),
        "evidence_mode": evidence_mode(record),
        "destructive_effects_during_verification": destructive_effects(record),
        "claim_boundary": short_claim_boundary(record),
        "not_claimed": not_claimed(record),
        "paper_use": record.get("claim_boundary", {}).get("paper_use", ""),
        "evidence_file": record.get("_source_file", ""),
    }


def build_matrix(records: list[dict[str, Any]]) -> dict[str, Any]:
    rows = [to_matrix_row(record) for record in records]
    rows.sort(key=lambda row: row["id"])
    by_repo = Counter(row["repository"] for row in rows)
    by_ecosystem = Counter(row["ecosystem"] for row in rows)
    by_behavior = Counter(row["behavior_family"] for row in rows)
    by_guard = Counter(row["guard_posture"] for row in rows)
    by_mode = Counter(row["evidence_mode"] for row in rows)
    return {
        "schema_version": "1.0",
        "purpose": "paper-facing held-out reproduction case matrix; not a gold set and not a final metric report",
        "case_count": len(rows),
        "status_groups": dict(sorted(Counter(row["status_group"] for row in rows).items())),
        "repositories": dict(sorted(by_repo.items())),
        "ecosystems": dict(sorted(by_ecosystem.items())),
        "behavior_families": dict(sorted(by_behavior.items())),
        "guard_postures": dict(sorted(by_guard.items())),
        "evidence_modes": dict(sorted(by_mode.items())),
        "human_labels_used": any(record.get("human_labels_used") for record in records),
        "model_labels_used": any(record.get("model_labels_used") for record in records),
        "claim_boundary": "qualitative local/source evidence only; join to independent held-out gold before reporting precision, recall, or F1",
        "rows": rows,
    }


def md_escape(value: Any) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", "<br>")


def write_json(matrix: dict[str, Any], path: Path) -> None:
    path.write_text(json.dumps(matrix, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")


def write_csv(rows: list[dict[str, Any]], path: Path) -> None:
    fieldnames = [
        "id",
        "repository",
        "ecosystem",
        "behavior_family",
        "sink_family",
        "trust_boundary",
        "guard_posture",
        "evidence_mode",
        "status",
        "file",
        "line",
        "claim_boundary",
        "not_claimed",
        "evidence_file",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({name: row.get(name, "") for name in fieldnames})


def write_markdown(matrix: dict[str, Any], path: Path) -> None:
    lines = [
        "# Held-out Local Reproduction Case Matrix",
        "",
        "This matrix summarizes local/source reproduction evidence for held-out cases. It is not a held-out gold set and it does not report precision, recall, or F1.",
        "",
        "## Summary",
        "",
        f"- Cases: {matrix['case_count']}",
        f"- Confirmed behavior cases: {matrix['status_groups'].get('confirmed_behavior', 0)}",
        f"- Repositories: {', '.join(f'{k}={v}' for k, v in matrix['repositories'].items())}",
        f"- Ecosystems: {', '.join(f'{k}={v}' for k, v in matrix['ecosystems'].items())}",
        f"- Guard postures: {', '.join(f'{k}={v}' for k, v in matrix['guard_postures'].items())}",
        f"- Evidence modes: {', '.join(f'{k}={v}' for k, v in matrix['evidence_modes'].items())}",
        f"- Human labels used: {str(matrix['human_labels_used']).lower()}",
        f"- Model labels used: {str(matrix['model_labels_used']).lower()}",
        "",
        "## Paper-facing Matrix",
        "",
        "| ID | Repo | Ecosystem | Behavior | Sink | Guard | Evidence | Claim boundary | Evidence file |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in matrix["rows"]:
        lines.append(
            "| "
            + " | ".join(
                [
                    md_escape(row["id"]),
                    md_escape(row["repository"]),
                    md_escape(row["ecosystem"]),
                    md_escape(row["behavior_family"]),
                    md_escape(row["sink_family"]),
                    md_escape(row["guard_posture"]),
                    md_escape(row["evidence_mode"]),
                    md_escape(row["claim_boundary"]),
                    f"`{md_escape(row['evidence_file'])}`",
                ]
            )
            + " |"
        )
    lines.extend(
        [
            "",
            "## How to cite this matrix in the paper",
            "",
            "- Use it for qualitative case-study evidence: behavior reachability, trust-boundary structure, sink type, and guard context.",
            "- Do not use it as population-level accuracy evidence until `reviewer_b_labels.jsonl` is completed and adjudicated.",
            "- Cases marked `guarded` are especially useful for arguing that Security-ADG preserves defensive context instead of merely matching dangerous APIs.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def write_html(matrix: dict[str, Any], path: Path) -> None:
    rows_json = json.dumps(matrix["rows"], ensure_ascii=False).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    summary_cards = [
        ("Cases", matrix["case_count"]),
        ("Confirmed", matrix["status_groups"].get("confirmed_behavior", 0)),
        ("Guarded", matrix["guard_postures"].get("guarded", 0)),
        ("Repositories", len(matrix["repositories"])),
    ]
    cards_html = "\n".join(
        f'<section class="stat"><span>{html.escape(label)}</span><strong>{html.escape(str(value))}</strong></section>'
        for label, value in summary_cards
    )
    page = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Held-out Reproduction Case Study</title>
  <style>
    :root {{
      color-scheme: light dark;
      --bg: light-dark(#f7f8fb, #111318);
      --panel: light-dark(#ffffff, #191d24);
      --soft: light-dark(#eef2f7, #252b35);
      --text: light-dark(#18202f, #eef2f8);
      --muted: light-dark(#5e6a7d, #a9b3c2);
      --line: light-dark(#d9e0ea, #333b48);
      --accent: light-dark(#315eff, #88a2ff);
      --green: light-dark(#127a45, #6ee7a6);
      --orange: light-dark(#9a5a00, #ffc466);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: radial-gradient(circle at top left, color-mix(in srgb, var(--accent) 16%, transparent), transparent 34rem), var(--bg);
      color: var(--text);
      line-height: 1.5;
    }}
    main {{ width: min(1180px, calc(100% - 32px)); margin: 0 auto; padding: 34px 0 48px; }}
    header {{ display: grid; gap: 12px; margin-bottom: 22px; }}
    h1 {{ margin: 0; font-size: clamp(28px, 4vw, 48px); letter-spacing: -0.04em; line-height: 1.05; }}
    .lede {{ max-width: 850px; color: var(--muted); font-size: 16px; }}
    .claim {{
      display: inline-flex;
      width: fit-content;
      gap: 8px;
      align-items: center;
      padding: 7px 10px;
      border: 1px solid var(--line);
      border-radius: 999px;
      background: color-mix(in srgb, var(--panel) 84%, transparent);
      color: var(--muted);
      font-size: 13px;
    }}
    .stats {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin: 22px 0; }}
    .stat {{ background: var(--panel); border: 1px solid var(--line); border-radius: 18px; padding: 16px; }}
    .stat span {{ display: block; color: var(--muted); font-size: 13px; }}
    .stat strong {{ display: block; margin-top: 4px; font-size: 30px; letter-spacing: -0.03em; }}
    .controls {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: center;
      margin: 20px 0;
      padding: 12px;
      border: 1px solid var(--line);
      border-radius: 18px;
      background: color-mix(in srgb, var(--panel) 86%, transparent);
    }}
    label {{ color: var(--muted); font-size: 13px; }}
    select, input {{
      min-height: 38px;
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 8px 10px;
      background: var(--panel);
      color: var(--text);
      font: inherit;
    }}
    input {{ min-width: min(320px, 100%); flex: 1; }}
    .layout {{ display: grid; grid-template-columns: 290px 1fr; gap: 16px; align-items: start; }}
    .rail, .detail {{ background: var(--panel); border: 1px solid var(--line); border-radius: 22px; }}
    .rail {{ padding: 10px; display: grid; gap: 8px; }}
    .case-button {{
      width: 100%;
      text-align: left;
      border: 1px solid transparent;
      border-radius: 16px;
      padding: 11px 12px;
      background: transparent;
      color: var(--text);
      cursor: pointer;
      font: inherit;
    }}
    .case-button:hover, .case-button[aria-selected="true"] {{ background: var(--soft); border-color: var(--line); }}
    .case-button b {{ display: block; font-size: 14px; }}
    .case-button span {{ display: block; color: var(--muted); font-size: 12px; margin-top: 2px; }}
    .detail {{ padding: 22px; min-height: 520px; }}
    .detail-top {{ display: flex; justify-content: space-between; gap: 14px; align-items: start; margin-bottom: 18px; }}
    h2 {{ margin: 0; font-size: 26px; letter-spacing: -0.03em; }}
    .repo {{ color: var(--muted); margin-top: 4px; }}
    .badges {{ display: flex; flex-wrap: wrap; gap: 8px; justify-content: flex-end; }}
    .badge {{
      border-radius: 999px;
      padding: 5px 9px;
      background: var(--soft);
      color: var(--muted);
      font-size: 12px;
      white-space: nowrap;
    }}
    .badge.guard {{ color: var(--green); }}
    .badge.open {{ color: var(--orange); }}
    .path {{
      display: grid;
      gap: 8px;
      margin: 18px 0;
      padding: 14px;
      border-radius: 18px;
      background: var(--soft);
    }}
    .path-item {{ display: flex; gap: 10px; align-items: flex-start; }}
    .dot {{ width: 10px; height: 10px; border-radius: 50%; background: var(--accent); margin-top: 7px; flex: 0 0 auto; }}
    code {{
      overflow-wrap: anywhere;
      font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace;
      font-size: 13px;
    }}
    dl {{ display: grid; grid-template-columns: 170px 1fr; gap: 10px 14px; margin: 18px 0 0; }}
    dt {{ color: var(--muted); }}
    dd {{ margin: 0; overflow-wrap: anywhere; }}
    .empty {{ color: var(--muted); padding: 16px; }}
    footer {{ margin-top: 18px; color: var(--muted); font-size: 13px; }}
    @media (max-width: 820px) {{
      main {{ width: min(100% - 20px, 720px); padding-top: 22px; }}
      .stats {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      .layout {{ grid-template-columns: 1fr; }}
      .rail {{ max-height: none; }}
      .detail-top {{ display: grid; }}
      .badges {{ justify-content: flex-start; }}
      dl {{ grid-template-columns: 1fr; gap: 4px; }}
    }}
  </style>
</head>
<body>
  <main>
    <header>
      <div class="claim">Local/source evidence only · not final precision/recall/F1</div>
      <h1>Held-out reproduction case study</h1>
      <p class="lede">A compact view of confirmed security-sensitive behaviors, their trust boundaries, sink families, and guard posture. The page is generated from archived local evidence JSON records.</p>
    </header>
    <section class="stats" aria-label="Summary statistics">
      {cards_html}
    </section>
    <section class="controls" aria-label="Filters">
      <label>Repository <select id="repoFilter"><option value="">All</option></select></label>
      <label>Guard <select id="guardFilter"><option value="">All</option></select></label>
      <label>Evidence <select id="modeFilter"><option value="">All</option></select></label>
      <input id="searchBox" type="search" placeholder="Search behavior, sink, file, claim…" aria-label="Search cases">
    </section>
    <section class="layout">
      <nav id="caseList" class="rail" aria-label="Cases"></nav>
      <article id="caseDetail" class="detail" aria-live="polite"></article>
    </section>
    <footer>{html.escape(matrix["claim_boundary"])}</footer>
  </main>
  <script>
    const cases = {rows_json};
    const state = {{ selected: cases[0]?.id || "", repo: "", guard: "", mode: "", q: "" }};
    const repoFilter = document.getElementById("repoFilter");
    const guardFilter = document.getElementById("guardFilter");
    const modeFilter = document.getElementById("modeFilter");
    const searchBox = document.getElementById("searchBox");
    const caseList = document.getElementById("caseList");
    const caseDetail = document.getElementById("caseDetail");

    function unique(field) {{
      return [...new Set(cases.map(c => c[field]).filter(Boolean))].sort();
    }}
    function fillSelect(select, values) {{
      values.forEach(value => {{
        const option = document.createElement("option");
        option.value = value;
        option.textContent = value;
        select.appendChild(option);
      }});
    }}
    fillSelect(repoFilter, unique("repository"));
    fillSelect(guardFilter, unique("guard_posture"));
    fillSelect(modeFilter, unique("evidence_mode"));

    function matches(c) {{
      const haystack = [
        c.id, c.repository, c.ecosystem, c.behavior_family, c.sink_family,
        c.trust_boundary, c.guard_posture, c.evidence_mode, c.file,
        c.claim_boundary, c.not_claimed
      ].join(" ").toLowerCase();
      return (!state.repo || c.repository === state.repo)
        && (!state.guard || c.guard_posture === state.guard)
        && (!state.mode || c.evidence_mode === state.mode)
        && (!state.q || haystack.includes(state.q.toLowerCase()));
    }}
    function pathItems(c) {{
      const parts = (c.dependency_path || c.operation || "").split(" -> ").filter(Boolean);
      return parts.map(part => `<div class="path-item"><span class="dot"></span><code>${{escapeHtml(part)}}</code></div>`).join("");
    }}
    function escapeHtml(value) {{
      return String(value ?? "").replace(/[&<>"']/g, ch => ({{"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}}[ch]));
    }}
    function renderList() {{
      const visible = cases.filter(matches);
      if (!visible.some(c => c.id === state.selected)) state.selected = visible[0]?.id || "";
      caseList.innerHTML = visible.length ? "" : '<p class="empty">No cases match the current filters.</p>';
      visible.forEach(c => {{
        const button = document.createElement("button");
        button.type = "button";
        button.className = "case-button";
        button.setAttribute("aria-selected", c.id === state.selected ? "true" : "false");
        button.innerHTML = `<b>${{escapeHtml(c.id)}} · ${{escapeHtml(c.behavior_family)}}</b><span>${{escapeHtml(c.repository)}} · ${{escapeHtml(c.guard_posture)}}</span>`;
        button.addEventListener("click", () => {{ state.selected = c.id; render(); }});
        caseList.appendChild(button);
      }});
    }}
    function renderDetail() {{
      const c = cases.find(item => item.id === state.selected);
      if (!c) {{
        caseDetail.innerHTML = '<p class="empty">Select a case to inspect its evidence boundary.</p>';
        return;
      }}
      const guardClass = c.guard_posture === "guarded" ? "guard" : "open";
      caseDetail.innerHTML = `
        <div class="detail-top">
          <div>
            <h2>${{escapeHtml(c.id)}} · ${{escapeHtml(c.behavior_family)}}</h2>
            <div class="repo">${{escapeHtml(c.repository)}} · ${{escapeHtml(c.ecosystem)}}</div>
          </div>
          <div class="badges">
            <span class="badge ${{guardClass}}">${{escapeHtml(c.guard_posture)}}</span>
            <span class="badge">${{escapeHtml(c.evidence_mode)}}</span>
            <span class="badge">${{escapeHtml(c.status_group)}}</span>
          </div>
        </div>
        <div class="path" aria-label="Dependency path">${{pathItems(c)}}</div>
        <dl>
          <dt>Sink</dt><dd>${{escapeHtml(c.sink_family)}}</dd>
          <dt>Trust boundary</dt><dd>${{escapeHtml(c.trust_boundary)}}</dd>
          <dt>File</dt><dd><code>${{escapeHtml(c.file)}}:${{escapeHtml(c.line)}}</code></dd>
          <dt>Status</dt><dd><code>${{escapeHtml(c.status)}}</code></dd>
          <dt>Claim boundary</dt><dd>${{escapeHtml(c.claim_boundary)}}</dd>
          <dt>Not claimed</dt><dd>${{escapeHtml(c.not_claimed)}}</dd>
          <dt>Verification side effects</dt><dd>${{escapeHtml(c.destructive_effects_during_verification)}}</dd>
          <dt>Evidence JSON</dt><dd><code>${{escapeHtml(c.evidence_file)}}</code></dd>
        </dl>
      `;
    }}
    function render() {{
      renderList();
      renderDetail();
    }}
    repoFilter.addEventListener("change", e => {{ state.repo = e.target.value; render(); }});
    guardFilter.addEventListener("change", e => {{ state.guard = e.target.value; render(); }});
    modeFilter.addEventListener("change", e => {{ state.mode = e.target.value; render(); }});
    searchBox.addEventListener("input", e => {{ state.q = e.target.value; render(); }});
    render();
  </script>
</body>
</html>
"""
    path.write_text(page, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args()

    records = read_records(args.input_dir)
    matrix = build_matrix(records)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    json_path = args.output_dir / "heldout_reproduction_case_matrix.json"
    csv_path = args.output_dir / "heldout_reproduction_case_matrix.csv"
    md_path = args.output_dir / "heldout_reproduction_case_matrix.md"
    html_path = args.output_dir / "heldout_reproduction_case_study.html"
    write_json(matrix, json_path)
    write_csv(matrix["rows"], csv_path)
    write_markdown(matrix, md_path)
    write_html(matrix, html_path)

    print(
        json.dumps(
            {
                "status": "complete",
                "cases": matrix["case_count"],
                "confirmed_behavior": matrix["status_groups"].get("confirmed_behavior", 0),
                "repositories": matrix["repositories"],
                "ecosystems": matrix["ecosystems"],
                "guard_postures": matrix["guard_postures"],
                "outputs": {
                    "json": display_path(json_path),
                    "csv": display_path(csv_path),
                    "md": display_path(md_path),
                    "html": display_path(html_path),
                },
            },
            indent=2,
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
