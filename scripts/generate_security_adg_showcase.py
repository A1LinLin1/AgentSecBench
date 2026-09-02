"""Build a standalone, interactive Security-ADG evidence showcase from JSONL.

The page deliberately presents static-analysis candidates and their local
def-use evidence.  It does not label a candidate as a vulnerability.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
IMPACT_WEIGHT = {
    "command_execution": 7,
    "dynamic_code_execution": 7,
    "permission_or_auth_change": 7,
    "credential_access": 6,
    "filesystem_delete": 6,
    "external_tool_invocation": 5,
    "network_access": 4,
    "filesystem_write": 4,
    "message_or_email_send": 4,
    "database_access": 4,
    "browser_control": 3,
    "filesystem_read": 3,
}


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def operation(graph: dict) -> dict:
    return next(node for node in graph["nodes"] if node["type"] == "security_sensitive_operation")


def select_graphs(graphs: list[dict], candidate_ids: list[str], max_graphs: int) -> list[dict]:
    by_id = {graph["candidate_id"]: graph for graph in graphs}
    if candidate_ids:
        missing = [candidate_id for candidate_id in candidate_ids if candidate_id not in by_id]
        if missing:
            raise ValueError(f"candidate IDs not present in graph file: {', '.join(missing)}")
        return [by_id[candidate_id] for candidate_id in candidate_ids]

    def score(graph: dict) -> tuple[int, str]:
        view = graph.get("views", {}).get("security_adg", {})
        return (
            IMPACT_WEIGHT.get(operation(graph).get("category", ""), 1) * 100
            + view.get("source_candidates", 0) * 20
            + view.get("dependency_paths", 0) * 5
            + view.get("guard_candidates", 0),
            graph["candidate_id"],
        )

    return sorted(graphs, key=lambda graph: (-score(graph)[0], score(graph)[1]))[:max_graphs]


def compact_graph(graph: dict) -> dict:
    op = operation(graph)
    view = graph.get("views", {}).get("security_adg", {})
    nodes = []
    for node in graph["nodes"]:
        detail = node.get("name") or node.get("symbol") or node.get("source_type") or node.get("kind")
        if not detail and node["type"] == "external_effect":
            detail = node.get("target_class")
        if not detail and node["type"] == "trust_boundary":
            detail = node.get("boundary")
        nodes.append({"id": node["id"], "type": node["type"], "label": detail or node["type"]})
    return {
        "candidateId": graph["candidate_id"],
        "repo": graph["provenance"]["repo"],
        "sampleId": graph["provenance"]["sample_id"],
        "commit": graph["provenance"]["commit"],
        "file": graph["provenance"]["file"],
        "category": op.get("category", "unknown"),
        "operation": op.get("name", "security-sensitive operation"),
        "lines": op.get("evidence_lines", []),
        "engine": graph.get("analysis", {}).get("engine", "unknown"),
        "limitations": graph.get("analysis", {}).get("limitations", []),
        "counts": {
            "sources": view.get("source_candidates", 0),
            "guards": view.get("guard_candidates", 0),
            "paths": view.get("dependency_paths", 0),
        },
        "nodes": nodes,
        "edges": graph["edges"],
        "views": graph.get("views", {}),
    }


def page_html(cases: list[dict], source_name: str) -> str:
    encoded = json.dumps(cases, ensure_ascii=False).replace("</", "<\\/")
    source_name = html.escape(source_name)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>AgentSecBench Security-ADG Showcase</title>
<style>
:root{{--ink:#172033;--muted:#64748b;--line:#d8e0ea;--panel:#f8fafc;--purple:#6d4aff;--orange:#d97706;--green:#15803d;--blue:#2563eb;--red:#be123c}}
*{{box-sizing:border-box}} body{{margin:0;background:#f4f7fb;color:var(--ink);font:15px/1.45 system-ui,-apple-system,Segoe UI,sans-serif}}
main{{max-width:1240px;margin:auto;padding:32px 20px 48px}} h1{{font-size:28px;margin:0 0 6px}} h2{{font-size:18px;margin:0}} .lede,.muted{{color:var(--muted)}}
.toolbar{{display:flex;gap:12px;align-items:end;flex-wrap:wrap;margin:24px 0}} label{{font-weight:600;display:grid;gap:5px}} select,button{{font:inherit;border:1px solid var(--line);border-radius:8px;background:white;padding:8px 10px;color:var(--ink)}} button[aria-pressed="true"]{{background:var(--ink);color:white;border-color:var(--ink)}}
.overview{{display:grid;grid-template-columns:repeat(3,minmax(130px,1fr));gap:12px;margin:0 0 20px}} .metric{{background:white;border:1px solid var(--line);border-radius:10px;padding:12px}} .metric b{{display:block;font-size:24px}}
.layout{{display:grid;grid-template-columns:minmax(0,1fr) 300px;gap:18px}} .graph,.detail{{background:white;border:1px solid var(--line);border-radius:12px}} .graph{{padding:16px;min-height:470px}} .detail{{padding:18px}} .detail dl{{margin:14px 0;display:grid;grid-template-columns:84px 1fr;gap:7px 10px;word-break:break-word}} dt{{color:var(--muted)}} dd{{margin:0}} .notice{{border-left:4px solid var(--orange);padding-left:10px;color:#78350f}}
svg{{width:100%;height:auto;min-height:420px}} .edge{{stroke:#94a3b8;stroke-width:2;fill:none;marker-end:url(#arrow)}} .edge.may_data_depend_on{{stroke:var(--purple)}} .edge.may_guard{{stroke:var(--green)}} .edge.may_cross{{stroke:var(--orange)}} .node rect{{fill:white;stroke:var(--line);stroke-width:1.5;rx:8}} .node.security_sensitive_operation rect{{stroke:var(--red);stroke-width:2.5}} .node.input_source rect{{fill:#f5f3ff;stroke:var(--purple)}} .node.guard_candidate rect{{fill:#f0fdf4;stroke:var(--green)}} .node.trust_boundary rect{{fill:#fff7ed;stroke:var(--orange)}} .node text{{fill:var(--ink);font-size:13px}} .node .kind{{fill:var(--muted);font-size:11px}} .legend{{display:flex;gap:14px;flex-wrap:wrap;color:var(--muted);font-size:13px;margin-top:8px}} .swatch{{display:inline-block;width:12px;height:3px;vertical-align:middle;margin-right:4px;background:#94a3b8}} .purple{{background:var(--purple)}} .orange{{background:var(--orange)}} .green{{background:var(--green)}}
@media(max-width:760px){{main{{padding:20px 12px}}.layout{{grid-template-columns:1fr}}.overview{{grid-template-columns:1fr 1fr}}.graph{{padding:8px;overflow:auto}}svg{{min-width:650px}}}}
</style></head><body><main>
<h1>Security-ADG evidence showcase</h1><p class="lede">Interactive view generated from static-analysis graphs. Each item is a review candidate, not a confirmed vulnerability.</p>
<div class="toolbar"><label>Candidate <select id="case"></select></label><div><span class="muted">View</span><br><button type="button" data-view="sink_only" aria-pressed="false">Sink only</button> <button type="button" data-view="plain_adg" aria-pressed="false">Plain ADG</button> <button type="button" data-view="security_adg" aria-pressed="true">Security-ADG</button></div></div>
<section class="overview" aria-label="Evidence counts"><div class="metric"><span class="muted">Input sources</span><b id="sources">0</b></div><div class="metric"><span class="muted">Guard candidates</span><b id="guards">0</b></div><div class="metric"><span class="muted">Dependency paths</span><b id="paths">0</b></div></section>
<section class="layout"><div class="graph"><svg id="svg" viewBox="0 0 920 440" role="img" aria-label="Security-ADG graph"><defs><marker id="arrow" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto"><path d="M0,0 L10,3.5 L0,7 z" fill="#94a3b8"/></marker></defs><g id="edges"></g><g id="nodes"></g></svg><div class="legend"><span><i class="swatch purple"></i>data dependency</span><span><i class="swatch orange"></i>trust boundary</span><span><i class="swatch green"></i>candidate guard</span></div></div><aside class="detail"><h2 id="title"></h2><p class="notice">Static candidate — manual review required before making a security claim.</p><dl><dt>Repository</dt><dd id="repo"></dd><dt>File</dt><dd id="file"></dd><dt>Evidence</dt><dd id="lines"></dd><dt>Operation</dt><dd id="operation"></dd><dt>Engine</dt><dd id="engine"></dd><dt>Limitations</dt><dd id="limitations"></dd></dl></aside></section>
<p class="muted">Generated from <code>{source_name}</code>. Commit hashes and candidate identifiers are retained in the exported manifest.</p>
</main><script>
const cases={encoded}; let current=0, view='security_adg';
const el=id=>document.getElementById(id), svgNs='http://www.w3.org/2000/svg';
const label=t=>t.replaceAll('_',' '); const esc=s=>String(s||'').slice(0,34);
function pos(node,index,total){{const by={{input_source:[100,80+index*92],agent_or_program_symbol:[310,220],trust_boundary:[490,95],security_sensitive_operation:[600,220],external_effect:[820,220],guard_candidate:[490,345]}};return by[node.type]||[300+(index%3)*170,80+Math.floor(index/3)*110]}}
function render(){{const c=cases[current], allowed=new Set((c.views[view]||{{}}).nodes||[]);const nodes=c.nodes.filter(n=>allowed.has(n.id));const positions=new Map(nodes.map((n,i)=>[n.id,pos(n,i,nodes.length)]));
['sources','guards','paths'].forEach(k=>el(k).textContent=c.counts[{{sources:'sources',guards:'guards',paths:'paths'}}[k]]); el('title').textContent=c.candidateId+' · '+label(c.category); el('repo').textContent=c.repo+' @ '+c.commit.slice(0,12);el('file').textContent=c.file;el('lines').textContent=c.lines.join(', ')||'not recorded';el('operation').textContent=c.operation;el('engine').textContent=c.engine;el('limitations').textContent=c.limitations.join('; ')||'none recorded';
const eg=el('edges'),ng=el('nodes');eg.replaceChildren();ng.replaceChildren(); c.edges.filter(e=>allowed.has(e.from)&&allowed.has(e.to)&&(c.views[view].edges||[]).includes(e.type)).forEach(e=>{{const a=positions.get(e.from),b=positions.get(e.to),line=document.createElementNS(svgNs,'line');line.setAttribute('x1',a[0]+70);line.setAttribute('y1',a[1]+25);line.setAttribute('x2',b[0]-70);line.setAttribute('y2',b[1]+25);line.setAttribute('class','edge '+e.type);eg.append(line)}});nodes.forEach((n,i)=>{{const [x,y]=positions.get(n.id),g=document.createElementNS(svgNs,'g');g.setAttribute('class','node '+n.type);g.setAttribute('transform',`translate(${{x-70}},${{y}})`);const r=document.createElementNS(svgNs,'rect');r.setAttribute('width','140');r.setAttribute('height','50');g.append(r);const t=document.createElementNS(svgNs,'text');t.setAttribute('x','10');t.setAttribute('y','21');t.textContent=esc(n.label);g.append(t);const k=document.createElementNS(svgNs,'text');k.setAttribute('class','kind');k.setAttribute('x','10');k.setAttribute('y','39');k.textContent=label(n.type);g.append(k);ng.append(g)}})}}
cases.forEach((c,i)=>{{const o=document.createElement('option');o.value=i;o.textContent=c.candidateId+' — '+c.repo+' — '+label(c.category);el('case').append(o)}});el('case').addEventListener('change',e=>{{current=Number(e.target.value);render()}});document.querySelectorAll('[data-view]').forEach(b=>b.addEventListener('click',()=>{{view=b.dataset.view;document.querySelectorAll('[data-view]').forEach(x=>x.setAttribute('aria-pressed',String(x===b)));render()}}));render();
</script></body></html>"""


def build_showcase(graphs_path: Path, output_dir: Path, candidate_ids: list[str], max_graphs: int) -> dict:
    graphs = read_jsonl(graphs_path)
    selected = select_graphs(graphs, candidate_ids, max_graphs)
    if not selected:
        raise ValueError("no graph records were selected")
    cases = [compact_graph(graph) for graph in selected]
    output_dir.mkdir(parents=True, exist_ok=True)
    page = output_dir / "index.html"
    page.write_text(page_html(cases, graphs_path.name), encoding="utf-8")
    source_digest = hashlib.sha256(graphs_path.read_bytes()).hexdigest()
    manifest = {
        "schema_version": "1.0",
        "purpose": "interactive static-analysis evidence view; not a vulnerability report",
        "source_graphs": str(graphs_path),
        "source_sha256": source_digest,
        "candidate_count": len(cases),
        "candidates": [
            {"candidate_id": case["candidateId"], "repo": case["repo"], "commit": case["commit"], "file": case["file"]}
            for case in cases
        ],
        "files": {"page": "index.html"},
    }
    (output_dir / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graphs", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--candidate-id", action="append", default=[])
    parser.add_argument("--max-graphs", type=int, default=12)
    args = parser.parse_args()
    if args.max_graphs < 1:
        raise SystemExit("--max-graphs must be at least 1")
    manifest = build_showcase(args.graphs, args.output_dir, args.candidate_id, args.max_graphs)
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
