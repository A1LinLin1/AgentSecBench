"""Deterministic, dependency-free SVG figures for the evidence viewer.

Layout only: retain every selected node/edge, including disconnected nodes.
Core data dependencies run down the centre; context and policy occupy side rails.
"""
from __future__ import annotations

from collections import defaultdict
from html import escape
import textwrap
import heapq

VIEWS = {"sink_only": "Sink only", "plain_adg": "Simplified ADG", "security_adg": "Security-ADG"}
TYPES = {
    "input_source": ("INPUT", "#edf3ff", "#486aaf"),
    "agent_or_program_symbol": ("AGENT / ENTRY", "#eaf4f3", "#367d76"),
    "program_symbol": ("PROGRAM SYMBOL", "#f4f1fa", "#7c6a9d"),
    "security_sensitive_operation": ("SENSITIVE OPERATION", "#fff0ed", "#b75a48"),
    "external_effect": ("POTENTIAL EFFECT", "#f1f3f5", "#667683"),
    "trust_boundary": ("BOUNDARY CANDIDATE", "#fff6e7", "#ac7a29"),
    "guard_candidate": ("GUARD CANDIDATE", "#edf5ea", "#638254"),
}
EDGES = {
    "may_data_depend_on": ("#486aaf", "", "possible data dependency"),
    "contains": ("#70838a", "", "component relation"),
    "may_cause": ("#667683", "5 4", "potential effect"),
    "may_cross": ("#ac7a29", "6 4", "possible boundary crossing"),
    "may_guard": ("#638254", "3 4", "candidate guard relation"),
}


def wrap_label(value: str, width: int = 31) -> list[str]:
    return textwrap.wrap(str(value), width=width, break_long_words=True,
                         break_on_hyphens=False, replace_whitespace=False) or [""]


def layout(case: dict, view: str) -> dict:
    spec = case.get("views", {}).get(view, {})
    allowed = set(spec.get("nodes", []))
    nodes = [n for n in case["nodes"] if n["id"] in allowed]
    edges = [e for e in case["edges"] if e["from"] in allowed and e["to"] in allowed
             and e["type"] in spec.get("edges", [])]
    side_types = {"agent_or_program_symbol", "trust_boundary", "guard_candidate"}
    core = [n for n in nodes if n["type"] not in side_types]
    ids = {n["id"] for n in core}
    # Kahn ranks for the main data/effect chain. Cycles retain all nodes in a
    # deterministic fallback row, and are explicitly reported in layout.json.
    indegree = dict.fromkeys(ids, 0)
    children = defaultdict(list)
    for e in edges:
        if e["from"] in ids and e["to"] in ids:
            children[e["from"]].append(e["to"])
            indegree[e["to"]] += 1
    ranks = dict.fromkeys(ids, 0)
    ready = sorted(k for k, v in indegree.items() if not v)
    visited = set()
    while ready:
        nid = ready.pop(0)
        visited.add(nid)
        for target in children[nid]:
            ranks[target] = max(ranks[target], ranks[nid] + 1)
            indegree[target] -= 1
            if not indegree[target]:
                ready.append(target)
                ready.sort()
    cyclic = sorted(ids - visited)
    for offset, nid in enumerate(cyclic):
        ranks[nid] = max(ranks.values(), default=0) + 1
    rows = defaultdict(list)
    for n in core:
        rows[ranks[n["id"]]].append(n)
    max_columns = max((len(row) for row in rows.values()), default=1)
    node_w, gap = 284, 64
    centre_width = max_columns * (node_w + gap) - gap
    centre_x = 388
    right_x = centre_x + centre_width + 112
    width = right_x + node_w + 44
    boxes = {}
    y = 156

    def box(n, x, top):
        lines = wrap_label(n["label"])
        boxes[n["id"]] = {"x": x, "y": top, "width": node_w,
                              "height": 46 + 19 * len(lines), "lines": lines}

    for rank in sorted(rows):
        row = rows[rank]
        row_width = len(row) * (node_w + gap) - gap
        start = centre_x + (centre_width - row_width) / 2
        for index, n in enumerate(row):
            box(n, start + index * (node_w + gap), y)
        y += max(boxes[n["id"]]["height"] for n in row) + 60
    left_y = right_y = 156
    for n in nodes:
        if n["type"] not in side_types:
            continue
        is_left = n["type"] == "agent_or_program_symbol"
        box(n, 44 if is_left else right_x, left_y if is_left else right_y)
        step = boxes[n["id"]]["height"] + 68
        if is_left:
            left_y += step
        else:
            right_y += step
    height = max(y, left_y, right_y, 330) + 92 + len(edges) * 6
    return {"width": width, "height": height, "boxes": boxes,
            "nodes": nodes, "edges": edges, "cyclic_nodes": cyclic,
            "centre_x": centre_x, "centre_width": centre_width, "right_x": right_x}


def figure_svg(case: dict, view: str) -> tuple[str, dict]:
    plan = layout(case, view)
    w, h, boxes = plan["width"], plan["height"], plan["boxes"]
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" role="img" aria-label="{escape(case["candidateId"])} {VIEWS[view]}" style="background:white;font-family:Arial, sans-serif">',
           f'<title>{escape(case["candidateId"])} · {escape(case["repo"])} · {VIEWS[view]}</title>',
           '<desc>Evidence graph. Dashed relations denote possible effects, boundaries, or guards; they do not establish exploitability.</desc>',
           '<rect width="100%" height="100%" fill="white"/>',
           f'<text x="44" y="40" fill="#263b43" font-size="23" font-weight="700">{escape(case["candidateId"])} / {VIEWS[view]}</text>',
           f'<text x="44" y="66" fill="#6c7980" font-size="14">{escape(case["repo"])} · {escape(case["commit"][:12])}</text>',
           f'<line x1="44" y1="86" x2="{w-44}" y2="86" stroke="#dce3e4"/>']
    if view == "security_adg":
        for x, text in [(44, "01  CONTEXT"), (plan["centre_x"], "02  DEPENDENCY CHAIN"), (plan["right_x"], "03  BOUNDARIES & GUARDS")]:
            out.append(f'<text x="{x}" y="120" font-size="11" letter-spacing="1.5" fill="#73828a">{text.replace("&", "&amp;")}</text>')
    out.append('<defs>')
    for i, e in enumerate(plan["edges"]):
        color = EDGES.get(e["type"], ("#70838a", "", ""))[0]
        out.append(f'<marker id="arrow{i}" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,1 L7,4 L0,7" fill="none" stroke="{color}" stroke-width="1.2"/></marker>')
    out.append('</defs><g class="edges">')
    plan["routes"] = []
    for i, e in enumerate(plan["edges"]):
        a, b = boxes[e["from"]], boxes[e["to"]]
        ax, ay, bx, by = a["x"] + a["width"]/2, a["y"] + a["height"]/2, b["x"] + b["width"]/2, b["y"] + b["height"]/2
        color, dash, relation = EDGES.get(e["type"], ("#70838a", "4 4", e["type"]))
        points = route_edge(a, b, list(boxes.values()))
        plan["routes"].append({"from": e["from"], "to": e["to"], "points": points})
        d = "M " + " L ".join(f"{x} {y}" for x, y in points)
        out.append(f'<path class="edge" data-from="{escape(e["from"])}" data-to="{escape(e["to"])}" data-type="{escape(e["type"])}" d="{d}" fill="none" stroke="{color}" stroke-width="1.6" stroke-linejoin="round" stroke-dasharray="{dash}" marker-end="url(#arrow{i})"><title>{escape(e["type"])}: {escape(e["from"])} → {escape(e["to"])}</title></path>')
    out.append('</g><g class="nodes">')
    for n in plan["nodes"]:
        b = boxes[n["id"]]
        kind, fill, stroke = TYPES.get(n["type"], (n["type"].upper(), "#f4f1fa", "#7c6a9d"))
        dash = ' stroke-dasharray="5 3"' if n["type"] in ("guard_candidate", "trust_boundary") else ""
        out.append(f'<g class="node" data-id="{escape(n["id"])}" tabindex="0" role="button" aria-label="{escape(n["label"])}" transform="translate({b["x"]},{b["y"]})"><title>{escape(n["label"])}</title><rect width="{b["width"]}" height="{b["height"]}" rx="7" fill="{fill}" stroke="{stroke}" stroke-width="1.4"{dash}/><text x="16" y="22" font-size="10" letter-spacing="1" fill="{stroke}">{kind}</text>')
        for index, line in enumerate(b["lines"]):
            out.append(f'<text x="16" y="{44+19*index}" font-family="Consolas, monospace" font-size="13" fill="#283b44" xml:space="preserve">{escape(line)}</text>')
        out.append('</g>')
    out.append('</g>')
    legend_y = h-54
    for index, (typ, (color, dash, text)) in enumerate(EDGES.items()):
        x = 44 + (index % 3)*350
        yy = legend_y + (index//3)*24
        out.append(f'<path d="M{x},{yy} h26" fill="none" stroke="{color}" stroke-width="1.6" stroke-dasharray="{dash}"/><text x="{x+34}" y="{yy+4}" fill="#63737b" font-size="11">{text}</text>')
    out.append('</svg>')
    return "".join(out), plan


def route_edge(a: dict, b: dict, boxes: list[dict]) -> list[tuple[float, float]]:
    """Manhattan shortest path around node rectangles, with a bend penalty."""
    def ports(box):
        x, y, w, h = (box[k] for k in ("x", "y", "width", "height"))
        return [((x+w/2, y-16), (x+w/2, y)), ((x+w/2, y+h+16), (x+w/2, y+h)),
                ((x-16, y+h/2), (x, y+h/2)), ((x+w+16, y+h/2), (x+w, y+h/2))]
    starts, ends = ports(a), ports(b)
    xs, ys = set(), set()
    for box in boxes:
        for p, _ in ports(box):
            xs.add(p[0]); ys.add(p[1])
    xs, ys = sorted(xs), sorted(ys)
    rects = [(p["x"]-6, p["y"]-6, p["x"]+p["width"]+6, p["y"]+p["height"]+6) for p in boxes]
    def blocked(p, q):
        x1,x2 = sorted((p[0],q[0])); y1,y2 = sorted((p[1],q[1]))
        return any((l < x1 < r and y1 < bottom and y2 > top) if x1==x2
                   else (top < y1 < bottom and x1 < r and x2 > l) for l,top,r,bottom in rects)
    goals = {(xs.index(p[0]), ys.index(p[1])): (p, boundary) for p,boundary in ends}
    queue, costs, previous = [], {}, {}
    def estimate(x,y):
        return min(abs(xs[x]-p[0])+abs(ys[y]-p[1]) for p,_ in ends)
    for p, boundary in starts:
        x,y = xs.index(p[0]),ys.index(p[1]); state=(x,y,0)
        costs[state]=0;previous[state]=(None,boundary)
        heapq.heappush(queue,(estimate(x,y),0,state))
    while queue:
        _,cost,state=heapq.heappop(queue)
        if cost!=costs[state]: continue
        x,y,direction=state
        if (x,y) in goals:
            chain=[goals[(x,y)][1]]
            cursor=state
            while cursor is not None:
                chain.append((xs[cursor[0]],ys[cursor[1]]))
                cursor,boundary=previous[cursor]
                if cursor is None: chain.append(boundary)
            chain.reverse()
            compact=[]
            for p in chain:
                if len(compact)>1 and ((compact[-2][0]==compact[-1][0]==p[0]) or (compact[-2][1]==compact[-1][1]==p[1])):
                    compact[-1]=p
                else: compact.append(p)
            return compact
        for dx,dy,d in [(1,0,1),(-1,0,1),(0,1,2),(0,-1,2)]:
            nx,ny=x+dx,y+dy
            if not (0<=nx<len(xs) and 0<=ny<len(ys)): continue
            if blocked((xs[x],ys[y]),(xs[nx],ys[ny])): continue
            new_cost=cost+abs(xs[nx]-xs[x])+abs(ys[ny]-ys[y])+(18 if direction and direction!=d else 0)
            nxt=(nx,ny,d)
            if new_cost<costs.get(nxt,float("inf")):
                costs[nxt]=new_cost;previous[nxt]=(state,None)
                heapq.heappush(queue,(new_cost+estimate(nx,ny),new_cost,nxt))
    raise ValueError("No obstacle-free route between nodes")
