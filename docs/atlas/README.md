# Warden Architecture Atlas

`index.html` is a single interactive page that covers every part of Warden. It has no build step and no server: open it in a browser from a clone of this repo.

It covers:
- all 20 modules and all 432 functions, classes, methods and nested helpers, each with:
  - its signature
  - a plain-English description
  - its docstring
  - its file and lines
  - what it calls and what calls it
- the 19 MCP tools, 10 of which need approval
- 11 safety invariants, each mapped to the functions that enforce it
- 27 settings, the demo's planted items, the IAM deny rules, and the test suite
- four diagrams (in `diagrams/`):
  - system context
  - the data flow of one cleanup
  - the life of one item
  - one approved cleanup, call by call

## How it is built

| File | Role |
|---|---|
| `build/extract.py` | Walks every tracked `.py` file with Python's `ast` module. It writes `inventory.json`: modules, blocks, signatures, docstrings, calls, raises, constants and tests. |
| `build/merged.json` | The written descriptions (what each block does, detail, tags) for every block and module, plus the tool, settings, IAM and agent tables. |
| `build/build_data.py` | Joins the two, resolves calls to block ids, builds the reverse "called by" index, and renders `index.html` from `atlas_template.html`. |
| `build/arch/*.json` | [archify](https://github.com/tt-a1i/archify) sources for the four diagrams. |

To rebuild after a code change, run from `build/`:

```
../../../.venv/Scripts/python.exe extract.py
../../../.venv/Scripts/python.exe build_data.py
```

`build_data.py` fails with a `KeyError` if a block has no description in `merged.json`. So a new or renamed function must be described before the page can be rebuilt.

"Calls" and "called by" come from static analysis. Calls made through dynamic dispatch, callbacks or `getattr` are not shown.
