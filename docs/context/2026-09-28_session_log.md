# Session log: 28–29 Sep 2026 (Warden Architecture Atlas)

These notes are from the Claude Code session that built `docs/atlas/`. The raw transcript is not in the repo; the decisions and findings are below.

## Ask

> "Build the complete artifact for the warden. And when I say complete I mean that every function, every block needs to be there."

The reference was an existing architecture atlas layout: diagrams first, then a searchable inventory of the code.

## What was built

The atlas is `docs/atlas/index.html` (see `docs/atlas/README.md`). It describes branch `Trueforge_agent` at `bcbf7a2`. The Python code is unchanged up to `967e00a`, which the rebuilt page now shows.

| Covered | Count |
|---|---|
| Modules | 20 (8,234 lines of Python) |
| Blocks | 432 = 334 functions + 3 async functions + 10 classes + 45 methods + 40 nested helpers |
| Internal call edges resolved | 813 |
| MCP tools | 19, of which 10 are gated by `require_approval_for_tools` |
| Tests collected | 491, from 313 test functions (parametrised) |
| Blocks with a docstring | 221 of 432; all 432 have a written description |

How it was made:
1. An `ast` pass extracted every block.
2. Claude agents read each function and wrote its description; docstrings are shown verbatim.
3. Four archify diagrams were drawn, each validated at the showcase quality level and visually checked in light and dark themes.

The atlas was also published as a private Claude artifact.

## Findings: where the code and the docs disagree

- `quarantine_volumes` and `recycle_snapshots` are annotated `destructiveHint=True`, even though both can be undone.
- `watchdog_verify` is annotated `readOnlyHint=True`, but it writes a sign-off file and a ledger entry.
- The README lists a "receipts" tool. The code has four tools in its place: `get_plan`, `get_receipt`, `list_receipts` and `list_warden_backups`. The total of 19 still matches.

Approval gating is not affected by any of this, because TrueForge gates by tool name.

It was also verified that `src/warden` never calls `terminate_instances`, `delete_bucket` or any KMS API.

## Lessons for working in this repo

- **Don't use `uv run` for read-only checks when the repo is on OneDrive.** It re-syncs `.venv`, and OneDrive can lock a `dist-info` folder partway through, which breaks the editable install (`import warden` fails).
  - Use `.venv/Scripts/python.exe -m pytest --collect-only -q -p no:cacheprovider` instead.
  - If the install breaks: `UV_LINK_MODE=copy uv sync --frozen --inexact`.
  - OneDrive can mark folders ReadOnly + ReparsePoint. Clearing the ReadOnly attribute fixes "Access is denied" from `uv sync` and `git worktree remove`.
- On Windows, pytest.exe is blocked by App Control. Run it as `python -m pytest`.

## Repo decisions (29 Sep)

- The repo stays **public**.
- The one-page site is `site/index.html`, and the atlas is `docs/atlas/`.
- Local-only material stays in `local/`, which is excluded through `.git/info/exclude`. It is never pushed.
- Commits use the GitHub noreply address, with no AI co-author trailer.
