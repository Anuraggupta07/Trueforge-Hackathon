"""Merge the AST inventory with the per-block descriptions into one page data file.
Resolves internal calls to block ids and builds the reverse 'called by' index."""
import json, pathlib

HERE = pathlib.Path(__file__).parent
inv = json.load(open(HERE / "inventory.json", encoding="utf-8"))
mer = json.load(open(HERE / "merged.json", encoding="utf-8"))
DESC, EXTRA = mer["desc"], mer["extra"]
DESC["modules"].setdefault("warden.__init__", {
    "summary": "Package marker. Its docstring names the project (approval-gated, reversible AWS cost cleanup) and how to start the server with `uv run warden-server`.",
    "role": "entry"})

mods = {m["module"]: m for m in inv["modules"]}
blocks, by_id = [], {}


def add(b):
    blocks.append(b); by_id[b["id"]] = b


for m in inv["modules"]:
    mod = m["module"]
    for it in m["items"]:
        bid = f"{mod}:{it['qual']}"
        add({"id": bid, "module": mod, "path": m["path"], "kind": it["kind"], "name": it["name"], "qual": it["qual"],
             "sig": it.get("sig", ""), "bases": it.get("bases", []), "fields": it.get("fields", []),
             "decorators": it["decorators"], "doc": it["doc"], "line": it["line"], "end": it["end"],
             "raw_calls": it.get("calls", []), "raises": it.get("raises", []), "parent": None})
        for mt in it.get("methods", []):
            add({"id": f"{mod}:{mt['qual']}", "module": mod, "path": m["path"], "kind": "method", "name": mt["name"],
                 "qual": mt["qual"], "sig": mt["sig"], "decorators": mt["decorators"], "doc": mt["doc"],
                 "line": mt["line"], "end": mt["end"], "raw_calls": mt["calls"], "raises": mt["raises"], "parent": bid})
    for n in m.get("nested", []):
        pid = f"{mod}:{n['parent']}"
        add({"id": f"{mod}:{n['parent']}.<locals>.{n['name']}", "module": mod, "path": m["path"], "kind": "nested",
             "name": n["name"], "qual": f"{n['parent']}.<locals>.{n['name']}", "sig": n["sig"], "decorators": n["decorators"],
             "doc": n["doc"], "line": n["line"], "end": n["end"], "raw_calls": n["calls"], "raises": [],
             "parent": pid if pid in by_id else None})

# name resolution per module
def modules_for(mod, frm):
    """Map an import source to a module id."""
    if frm.startswith("."):
        base = "warden" if mod.startswith("warden") else mod.rsplit(".", 1)[0]
        rest = frm.lstrip(".")
        return base + ("." + rest if rest else "")
    if frm.startswith("warden"):
        return frm
    if frm == "_common":
        return "scripts._common"
    return None

resolved_calls = {}
for m in inv["modules"]:
    mod = m["module"]
    names, aliases = {}, {}
    for b in blocks:
        if b["module"] == mod and b["kind"] in ("function", "async function", "class"):
            names[b["name"]] = b["id"]
    for im in m["imports"]:
        target = modules_for(mod, im["from"])
        if not target:
            continue
        if target in mods and not im["names"]:
            aliases[target.split(".")[-1]] = target
        for nm in im["names"]:
            sub = f"{target}.{nm}"
            if sub in mods:
                aliases[nm] = sub                      # from . import audit
            elif target in mods and f"{target}:{nm}" in by_id:
                names.setdefault(nm, f"{target}:{nm}")  # from .config import is_frozen
    for b in [x for x in blocks if x["module"] == mod]:
        out = set()
        cls = b["qual"].split(".")[0] if b["kind"] == "method" else None
        nested = {x["name"]: x["id"] for x in blocks if x["kind"] == "nested" and x["parent"] == b["id"]}
        for c in b["raw_calls"]:
            if c in nested:
                out.add(nested[c])
            elif c in names:
                out.add(names[c])
            elif "." in c and not c.startswith("."):
                head, attr = c.split(".", 1)
                if head == "self" and cls and f"{mod}:{cls}.{attr}" in by_id:
                    out.add(f"{mod}:{cls}.{attr}")
                elif head in aliases and f"{aliases[head]}:{attr}" in by_id:
                    out.add(f"{aliases[head]}:{attr}")
        out.discard(b["id"])
        resolved_calls[b["id"]] = sorted(out)

called_by = {}
for bid, cs in resolved_calls.items():
    for c in cs:
        called_by.setdefault(c, []).append(bid)

page_blocks = []
for b in blocks:
    d = DESC["blocks"][b["id"]]
    page_blocks.append({
        "id": b["id"], "m": b["module"], "k": b["kind"], "n": b["name"], "q": b["qual"], "s": b["sig"],
        "dec": b["decorators"], "doc": b["doc"], "l": b["line"], "e": b["end"], "p": b["parent"],
        "bases": b.get("bases", []), "fields": b.get("fields", []),
        "w": d["what"], "d": d.get("detail", ""), "t": d.get("tags", []),
        "c": resolved_calls.get(b["id"], []), "cb": sorted(called_by.get(b["id"], [])), "r": b["raises"]})

page_mods = []
for m in inv["modules"]:
    internal, external = set(), set()
    for im in m["imports"]:
        t = modules_for(m["module"], im["from"])
        if t and t in mods:
            if im["names"] and all(f"{t}.{n}" in mods for n in im["names"]):
                internal.update(f"{t}.{n}" for n in im["names"])
            else:
                internal.add(t)
        elif t and t.startswith("warden"):
            internal.update(f"{t}.{n}" for n in im["names"] if f"{t}.{n}" in mods)
        else:
            external.add(im["from"].split(".")[0])
    internal.discard(m["module"])
    md = DESC["modules"][m["module"]]
    page_mods.append({"id": m["module"], "path": m["path"], "lines": m["lines"], "doc": m["doc"],
                      "summary": md["summary"], "role": md["role"], "imports": sorted(internal),
                      "external": sorted(x for x in external if x and x != "__future__"),
                      "constants": m["constants"],
                      "count": sum(1 for b in page_blocks if b["m"] == m["module"])})

tools = EXTRA["mcp_tools"]
gated = set(EXTRA["agent"]["approval_tools"])
for t in tools:
    t["approval"] = t["name"] in gated
    b = next(x for x in page_blocks if x["id"] == t["id"])
    t["what"], t["detail"], t["line"] = b["w"], b["d"], b["l"]

data = {"commit": inv["commit"], "modules": page_mods, "blocks": page_blocks, "tools": tools,
        "config": EXTRA["config"], "planted": EXTRA["planted"], "iam": EXTRA["iam"], "agent": EXTRA["agent"],
        "tests": [{"path": t["path"], "tests": t["tests"], "lines": t["lines"], "doc": (t["doc"] or "").split("\n")[0]} for t in inv["tests"]]}
json.dump(data, open(HERE / "atlas_data.json", "w", encoding="utf-8"), ensure_ascii=False, separators=(",", ":"))

# render the page: the template carries a /*__DATA__*/ slot for the JSON
page = (HERE / "atlas_template.html").read_text(encoding="utf-8")
(HERE.parent / "index.html").write_text(
    page.replace("/*__DATA__*/", (HERE / "atlas_data.json").read_text(encoding="utf-8")), encoding="utf-8")

kinds = {}
for b in page_blocks:
    kinds[b["k"]] = kinds.get(b["k"], 0) + 1
print("blocks", len(page_blocks), kinds, "modules", len(page_mods), "tools", len(tools), "gated", sum(t["approval"] for t in tools))
print("resolved call edges", sum(len(v) for v in resolved_calls.values()), "blocks with callers", len(called_by))
print("size KB", round((HERE / "atlas_data.json").stat().st_size / 1024))
print("module imports:", {m["id"]: m["imports"] for m in page_mods if m["imports"]})
