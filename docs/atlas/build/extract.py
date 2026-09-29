"""Walk the Warden repo with the ast module and write an exact inventory of every
module, class, function and method: signature, decorators, docstring, line span,
internal calls (and the reverse index), constants, and test counts."""
import ast, json, pathlib, subprocess, re

REPO = pathlib.Path(__file__).resolve().parents[3]  # repo root (docs/atlas/build/extract.py)
OUT = pathlib.Path(__file__).with_name("inventory.json")

files = subprocess.run(["git", "ls-files"], cwd=REPO, capture_output=True, text=True).stdout.split()
py = [f for f in files if f.endswith(".py")]
src = [f for f in py if not f.startswith("tests/")]
tests = [f for f in py if f.startswith("tests/")]


def modname(path):
    p = path[:-3].replace("/", ".")
    return p[4:] if p.startswith("src.") else p


def sig(fn):
    a = fn.args
    parts = []
    pos = a.posonlyargs + a.args
    defaults = [None] * (len(pos) - len(a.defaults)) + a.defaults
    for arg, d in zip(pos, defaults):
        s = arg.arg + (": " + ast.unparse(arg.annotation) if arg.annotation else "")
        if d is not None:
            s += " = " + ast.unparse(d)
        parts.append(s)
    if a.vararg:
        parts.append("*" + a.vararg.arg)
    elif a.kwonlyargs:
        parts.append("*")
    for arg, d in zip(a.kwonlyargs, a.kw_defaults):
        s = arg.arg + (": " + ast.unparse(arg.annotation) if arg.annotation else "")
        if d is not None:
            s += " = " + ast.unparse(d)
        parts.append(s)
    if a.kwarg:
        parts.append("**" + a.kwarg.arg)
    ret = " -> " + ast.unparse(fn.returns) if fn.returns else ""
    return "(" + ", ".join(parts) + ")" + ret


def calls_in(node):
    out = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            f = n.func
            if isinstance(f, ast.Name):
                out.add(f.id)
            elif isinstance(f, ast.Attribute):
                base = f.value
                if isinstance(base, ast.Name):
                    out.add(base.id + "." + f.attr)
                else:
                    out.add("." + f.attr)
    return sorted(out)


def raises_in(node):
    out = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Raise) and n.exc is not None:
            e = n.exc.func if isinstance(n.exc, ast.Call) else n.exc
            try:
                out.add(ast.unparse(e))
            except Exception:
                pass
    return sorted(out)


modules = []
for f in src:
    text = (REPO / f).read_text(encoding="utf-8")
    tree = ast.parse(text)
    m = {"path": f, "module": modname(f), "lines": text.count("\n") + 1,
         "doc": ast.get_docstring(tree) or "", "imports": [], "constants": [], "items": []}
    for node in tree.body:
        if isinstance(node, ast.ImportFrom):
            mod = ("." * node.level) + (node.module or "")
            m["imports"].append({"from": mod, "names": [a.name for a in node.names]})
        elif isinstance(node, ast.Import):
            for a in node.names:
                m["imports"].append({"from": a.name, "names": []})
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                if isinstance(t, ast.Name):
                    val = ast.unparse(node.value) if node.value is not None else ""
                    m["constants"].append({"name": t.id, "line": node.lineno,
                                           "value": val if len(val) <= 160 else val[:157] + "…"})
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            m["items"].append({"kind": "async function" if isinstance(node, ast.AsyncFunctionDef) else "function",
                               "name": node.name, "qual": node.name, "sig": sig(node),
                               "decorators": [ast.unparse(d) for d in node.decorator_list],
                               "doc": ast.get_docstring(node) or "", "line": node.lineno, "end": node.end_lineno,
                               "calls": calls_in(node), "raises": raises_in(node)})
        elif isinstance(node, ast.ClassDef):
            cls = {"kind": "class", "name": node.name, "qual": node.name,
                   "bases": [ast.unparse(b) for b in node.bases],
                   "decorators": [ast.unparse(d) for d in node.decorator_list],
                   "doc": ast.get_docstring(node) or "", "line": node.lineno, "end": node.end_lineno,
                   "fields": [], "methods": []}
            for b in node.body:
                if isinstance(b, ast.AnnAssign) and isinstance(b.target, ast.Name):
                    cls["fields"].append(b.target.id + ": " + ast.unparse(b.annotation) +
                                         (" = " + ast.unparse(b.value) if b.value is not None else ""))
                elif isinstance(b, ast.Assign):
                    for t in b.targets:
                        if isinstance(t, ast.Name):
                            cls["fields"].append(t.id + " = " + ast.unparse(b.value)[:80])
                elif isinstance(b, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    cls["methods"].append({"kind": "method", "name": b.name, "qual": node.name + "." + b.name,
                                           "sig": sig(b), "decorators": [ast.unparse(d) for d in b.decorator_list],
                                           "doc": ast.get_docstring(b) or "", "line": b.lineno, "end": b.end_lineno,
                                           "calls": calls_in(b), "raises": raises_in(b)})
            m["items"].append(cls)
    # nested functions (closures) are blocks too: record them under their parent
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for inner in node.body:
                if isinstance(inner, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    m.setdefault("nested", []).append({"parent": node.name, "name": inner.name, "sig": sig(inner),
                                                       "line": inner.lineno, "end": inner.end_lineno,
                                                       "doc": ast.get_docstring(inner) or "",
                                                       "decorators": [ast.unparse(d) for d in inner.decorator_list],
                                                       "calls": calls_in(inner)})
    modules.append(m)

# reverse index: who calls each top-level function (by bare name or module-qualified name)
defs = {}
for m in modules:
    short = m["module"].split(".")[-1]
    for it in m["items"]:
        if it["kind"] != "class":
            defs.setdefault(it["name"], []).append(m["module"])
            defs.setdefault(short + "." + it["name"], []).append(m["module"])
        else:
            defs.setdefault(it["name"], []).append(m["module"])
            for mt in it["methods"]:
                defs.setdefault("." + mt["name"], []).append(m["module"])
callers = {}
for m in modules:
    for it in m["items"]:
        blocks = [it] + it.get("methods", [])
        for b in blocks:
            for c in b.get("calls", []):
                key = c if c in defs else (c.split(".", 1)[1] if "." in c and c.split(".", 1)[1] in defs and not c.startswith(".") else None)
                if key:
                    callers.setdefault(key, set()).add(m["module"] + ":" + b["qual"])

tst = []
for f in tests:
    text = (REPO / f).read_text(encoding="utf-8")
    tree = ast.parse(text)
    names = [n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name.startswith("test_")]
    tst.append({"path": f, "lines": text.count("\n") + 1, "tests": len(names), "doc": ast.get_docstring(tree) or "", "names": names})

json.dump({"repo": str(REPO), "commit": subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True).stdout.strip(),
           "modules": modules, "callers": {k: sorted(v) for k, v in callers.items()}, "tests": tst},
          open(OUT, "w", encoding="utf-8"), indent=1, ensure_ascii=False)

nf = sum(1 for m in modules for it in m["items"] if it["kind"] != "class")
nc = sum(1 for m in modules for it in m["items"] if it["kind"] == "class")
nm = sum(len(it["methods"]) for m in modules for it in m["items"] if it["kind"] == "class")
nn = sum(len(m.get("nested", [])) for m in modules)
nodoc = sum(1 for m in modules for it in m["items"] for b in [it] + it.get("methods", []) if not b["doc"])
print(f"modules {len(modules)}  functions {nf}  classes {nc}  methods {nm}  nested {nn}  missing-docstring {nodoc}  tests {sum(t['tests'] for t in tst)}")
for m in modules:
    print(f"  {m['path']:34} {m['lines']:5} lines  items {len(m['items']):3}  nested {len(m.get('nested', []))}")
