"""Deterministic OpenUI dashboards for TrueForge's chat (generative UI).

Warden builds the UI from its own data so the model only has to paste it: numbers, ids and
refusals cannot be mistyped or left out. Every string that reaches OpenUI goes through _q(),
which escapes quotes/backslashes and strips control characters, so untrusted tag text (for
example a prompt-injection Name tag) can never break out of a string literal.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

_CTRL = re.compile(r"[\x00-\x1f\x7f]+")

ACTION_LABELS = {
    "quarantine_volume": "Back up + delete",
    "recycle_snapshot": "Recycle Bin (7 days)",
    "delete_snapshot": "Delete permanently",
    "stop_instance": "Stop (not terminate)",
    "quarantine_address": "Quarantine IP",
    "release_address": "Release IP",
}
TYPE_LABELS = {"volume": "Disk", "snapshot": "Snapshot", "instance": "Server", "address": "Public IP"}


def _q(value: Any, limit: int = 160) -> str:
    """OpenUI string literal: escaped, single-line, bounded."""
    text = _CTRL.sub(" ", "" if value is None else str(value)).strip()
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _arr(items: Iterable[str]) -> str:
    return "[" + ", ".join(items) + "]"


def _money(value: Any) -> str:
    try:
        return f"${float(value):,.2f}"
    except (TypeError, ValueError):
        return "n/a"


def _num(value: Any) -> str:
    try:
        return f"{float(value):.2f}"
    except (TypeError, ValueError):
        return "0"


def _tag(text: str, variant: str) -> str:
    return f"Tag({_q(text)}, null, \"sm\", {_q(variant)})"


def _button(label: str, message: str, variant: str = "secondary") -> str:
    return f"Button({_q(label)}, Action([@ToAssistant({_q(message, 400)})]), {_q(variant)})"


def _kpi(name: str, label: str, value: str, note: str) -> str:
    return (f"{name} = Card([TextContent({_q(label)}, \"small\"), TextContent({_q(value)}, \"large-heavy\"), "
            f"TextContent({_q(note)}, \"small\")])")


def _mode_callout(mock: bool) -> str | None:
    if not mock:
        return None
    return ('mode = Callout("warning", "Simulated AWS (mock mode)", '
            '"This run uses a local AWS simulator because the AWS account is not activated yet. '
            'Every safety check, sign-off, receipt and undo path is the same code that runs on real AWS.")')


def _program(root_children: list[str], lines: list[str]) -> str:
    return "\n".join([f"root = Stack({_arr(root_children)}, \"column\", \"l\")", *lines])


def scan_ui(report: dict, mock: bool = False) -> str:
    """Scan report -> KPI cards + tabs (decide / refused / leaks / savings / how it works)."""
    findings = report.get("findings") or []
    summary = report.get("summary") or {}
    tiers = summary.get("tiers") or {}
    plan_id = report.get("plan_id", "")
    act = [f for f in findings if f.get("verdict") in ("act", "review")]
    act.sort(key=lambda f: (f.get("tier") != "needs_review", -(f.get("est_monthly_usd") or 0)))
    keep = [f for f in findings if f.get("verdict") == "keep"]
    leaks = report.get("leaks") or []

    lines = [
        f"hdr = CardHeader(\"Warden · cloud waste report\", "
        f"{_q(f'Account {report.get('account_id')} · {report.get('region')} · scope {report.get('scope')} · plan {plan_id}', 220)})",
        "kpis = Stack([k1, k2, k3, k4, k5], \"row\", \"m\", \"stretch\", \"start\", true)",
        _kpi("k1", "Monthly waste found", _money(summary.get("est_monthly_savings_usd")), "list-price estimate"),
        _kpi("k2", "Safe & reversible", str(tiers.get("safe_reversible", 0)), "one approval per batch"),
        _kpi("k3", "Needs your review", str(tiers.get("needs_review", 0)), "irreversible or unclear"),
        _kpi("k4", "Refused (protected)", str(tiers.get("protected", 0)), "Warden will not touch these"),
        _kpi("k5", "Leaks found", str(len(leaks)), "sources that keep creating waste"),
        "tabs = Tabs([t1, t2, t3, t4, t5])",
    ]

    # Tab 1: the decision list.
    if act:
        names = [_q(f.get("name") or f.get("resource_id"), 48) for f in act]
        ids = [_q(f.get("resource_id")) for f in act]
        kinds = [_q(TYPE_LABELS.get(f.get("resource_type"), f.get("resource_type"))) for f in act]
        actions = [_tag(ACTION_LABELS.get(f.get("action") or "", "Needs your call"),
                        "danger" if f.get("reversible") is False else "info") for f in act]
        undo = [_tag("Reversible", "success") if f.get("reversible") else
                _tag("IRREVERSIBLE", "danger") if f.get("reversible") is False else _tag("Decide first", "warning")
                for f in act]
        costs = [_num(f.get("est_monthly_usd")) for f in act]
        whys = [_q(f.get("why") or "; ".join(f.get("reasons") or []), 180) for f in act]
        btns = [_button("Request approval" if f.get("verdict") == "act" else "Discuss",
                        (f"Approve plan {plan_id}: {f.get('action')} {f.get('resource_id')}" if f.get("verdict") == "act"
                         else f"Explain what you need from me to decide on {f.get('resource_id')}"),
                        "primary" if f.get("reversible") else "secondary")
                for f in act]
        lines += [
            "t1 = TabItem(\"decide\", " + _q(f"Decide ({len(act)})") + ", [intro1, dtable, dbtns])",
            "intro1 = TextContent(\"Each click only REQUESTS an action: Warden's independent Watchdog re-checks it, "
            "then TrueForge shows you an Allow / Deny card. Nothing changes before you click Allow.\", \"small\")",
            "dtable = Table([Col(\"Resource\", " + _arr(names) + "), Col(\"ID\", " + _arr(ids) + "), Col(\"Type\", "
            + _arr(kinds) + "), Col(\"Action\", " + _arr(actions) + "), Col(\"Undo\", " + _arr(undo)
            + "), Col(\"$/month\", " + _arr(costs) + ", \"number\"), Col(\"Why\", " + _arr(whys)
            + "), Col(\"\", " + _arr(btns) + ", \"action\")])",
        ]
        safe_ids = [f.get("resource_id") for f in act if f.get("tier") == "safe_reversible"]
        batch = [_button("Request approval for all safe & reversible items",
                         f"Approve plan {plan_id}: every safe & reversible item ({', '.join(safe_ids)}), "
                         "batched by action, one Watchdog sign-off and one approval per batch", "primary")] if safe_ids else []
        batch.append(_button("Show the rollback window", "Show the rollback window"))
        lines.append("dbtns = Buttons(" + _arr(batch) + ")")
    else:
        lines += ["t1 = TabItem(\"decide\", \"Decide (0)\", [none1])",
                  "none1 = Callout(\"success\", \"Nothing to clean\", \"No waste found in scope.\")"]

    # Tab 2: refusals are a feature.
    if keep:
        lines += [
            "t2 = TabItem(\"refused\", " + _q(f"Refused ({len(keep)})") + ", [intro2, ptable])",
            "intro2 = TextContent(\"A normal cleanup script would delete these. Warden refuses, and says why.\", \"small\")",
            "ptable = Table([Col(\"Resource\", " + _arr(_q(f.get("name") or f.get("resource_id"), 60) for f in keep)
            + "), Col(\"ID\", " + _arr(_q(f.get("resource_id")) for f in keep) + "), Col(\"Refused because\", "
            + _arr(_tag(_refusal_kind(f), "danger" if "suspicious" in " ".join(f.get("reasons") or []) else "warning")
                   for f in keep)
            + "), Col(\"Details\", " + _arr(_q(f.get("why") or "; ".join(f.get("reasons") or []), 200) for f in keep) + ")])",
        ]
    else:
        lines += ["t2 = TabItem(\"refused\", \"Refused (0)\", [none2])",
                  "none2 = TextContent(\"Nothing protected in scope.\")"]

    # Tab 3: leaks (fix the source, not just the symptom).
    leak_items = []
    for i, leak in enumerate(leaks, 1):
        leak_items.append(f"lk{i}")
        lines.append(f"lk{i} = Callout(\"warning\", {_q('Leak: ' + str(leak.get('launch_template_name')))}, "
                     f"{_q(str(leak.get('problem')) + ' Fix: ' + str(leak.get('fix')), 400)})")
        if leak.get("fix_cli"):
            leak_items.append(f"lkc{i}")
            lines.append(f"lkc{i} = CodeBlock(\"bash\", {_q(leak.get('fix_cli'), 600)})")
    if not leak_items:
        leak_items = ["nolk"]
        lines.append("nolk = TextContent(\"No launch template is leaking disks.\")")
    lines.append("t3 = TabItem(\"leaks\", " + _q(f"Leaks ({len(leaks)})") + ", " + _arr(leak_items) + ")")

    # Tab 4: savings.
    priced = [f for f in act if f.get("est_monthly_usd")]
    lines += [
        "t4 = TabItem(\"savings\", \"Savings\", [sbar, spie])",
        "sbar = HorizontalBarChart(" + _arr(_q(f.get("name") or f.get("resource_id"), 40) for f in priced)
        + ", [Series(\"$ per month\", " + _arr(_num(f.get("est_monthly_usd")) for f in priced) + ")], \"grouped\", \"$ per month\")",
        "spie = PieChart([\"Safe & reversible\", \"Needs your review\", \"Refused\"], ["
        f"{tiers.get('safe_reversible', 0)}, {tiers.get('needs_review', 0)}, {tiers.get('protected', 0)}], \"donut\")",
    ]

    # Tab 5: how Warden decides.
    lines += [
        "t5 = TabItem(\"how\", \"How Warden decides\", [how])",
        "how = Steps([StepsItem(\"1. Scan (read-only)\", \"Finds unused disks, snapshots, idle servers and IPs, and records "
        "a verdict for each in a tamper-evident ledger.\"), StepsItem(\"2. Refuse what is risky\", \"Production, legal-hold, "
        "Terraform/autoscaling, anything an image, DNS record or load balancer still uses, and instruction-like tag text.\"), "
        "StepsItem(\"3. Watchdog sign-off\", \"An independent checker re-reads AWS and signs a single-use permission slip.\"), "
        "StepsItem(\"4. You approve\", \"TrueForge pauses on an Allow / Deny card. Irreversible steps need their own approval.\"), "
        "StepsItem(\"5. Act, with undo\", \"Backup first, Recycle Bin, stop instead of terminate, IP quarantine before release, "
        "and a live rollback countdown.\")])",
    ]

    children = ["hdr"]
    mode = _mode_callout(mock)
    if mode:
        children.append("mode")
        lines.append(mode)
    children += ["kpis", "tabs"]
    return _program(children, lines)


def _refusal_kind(finding: dict) -> str:
    text = " ".join(finding.get("reasons") or []).lower()
    for needle, label in (("suspicious", "Prompt-injection attempt"), ("production", "Production"),
                          ("legal", "Legal hold"), ("terraform", "Managed by code"), ("cloudformation", "Managed by code"),
                          ("autoscaling", "Autoscaling"), ("kubernetes", "Kubernetes"), ("ami", "Used by an image"),
                          ("dns", "DNS still points here"), ("load balancer", "Serving traffic"),
                          ("backup", "Warden backup"), ("quarantine", "In quarantine"), ("active", "In use")):
        if needle in text:
            return label
    return "Protected"


def watchdog_ui(result: dict) -> str:
    approved = result.get("approved_ids") or []
    blocked = result.get("blocked") or {}
    checks = (result.get("checks") or [])[:10]
    lines = [
        ("wd = Callout(\"success\", " + _q(f"Watchdog signed off {len(approved)} item(s)") + ", "
         + _q(f"Action {result.get('action')} · single-use sign-off {result.get('signoff_id')} · expires {result.get('expires_at')}", 300) + ")")
        if approved else
        ("wd = Callout(\"error\", \"Watchdog blocked this request\", " + _q("Nothing will be executed.") + ")"),
        "wdsteps = Steps(" + _arr(f"StepsItem({_q('Check ' + str(i))}, {_q(c, 240)})" for i, c in enumerate(checks, 1)) + ")"
        if checks else "wdsteps = TextContent(\"No checks recorded.\")",
    ]
    children = ["wd", "wdsteps"]
    if blocked:
        children.append("wdb")
        lines.append("wdb = Table([Col(\"Blocked\", " + _arr(_q(k) for k in blocked) + "), Col(\"Why\", "
                     + _arr(_q(v, 220) for v in blocked.values()) + ")])")
    return _program(children, lines)


def receipt_ui(receipt: dict) -> str:
    results = receipt.get("results") or []
    counts = receipt.get("counts") or {}
    ok = counts.get("done", 0) and not counts.get("failed", 0)
    status_tag = {"done": "success", "skipped": "warning", "failed": "danger"}
    lines = [
        ("rc = Callout(" + _q("success" if ok else "warning") + ", "
         + _q(f"{receipt.get('action')}: {counts.get('done', 0)} done · {counts.get('skipped', 0)} skipped · "
              f"{counts.get('failed', 0)} failed") + ", "
         + _q(f"Estimated saving {_money(receipt.get('est_monthly_savings_usd'))}/month · receipt {receipt.get('receipt_id')}", 240) + ")"),
    ]
    children = ["rc"]
    if results:
        children.append("rt")
        undo_btns = [(_button("Undo", f"Undo: call {r['undo']['tool']} with {r['undo'].get('args')}")
                      if r.get("undo") else _q("")) for r in results]
        lines.append("rt = Table([Col(\"Resource\", " + _arr(_q(r.get("resource_id")) for r in results)
                     + "), Col(\"Result\", " + _arr(_tag(str(r.get("status")), status_tag.get(r.get("status"), "neutral"))
                                                   for r in results)
                     + "), Col(\"Details\", " + _arr(_q(r.get("detail"), 220) for r in results)
                     + "), Col(\"\", " + _arr(undo_btns) + ", \"action\")])")
    return _program(children, lines)


def rollback_ui(window: dict) -> str:
    items = window.get("items") or []
    ledger = window.get("ledger") or {}
    lines = [
        ("rl = Callout(\"success\", \"Ledger intact\", " + _q(f"{ledger.get('entries', 0)} hash-chained entries verified.") + ")")
        if ledger.get("ok") else
        ("rl = Callout(\"error\", \"Ledger problem\", " + _q(ledger.get("reason") or "verification failed") + ")"),
    ]
    children = ["rl"]
    if items:
        children.append("rw")
        state_tag = {"backup": "info", "recycled": "info", "stopped": "neutral", "quarantined": "warning"}
        lines.append(
            "rw = Table([Col(\"Resource\", " + _arr(_q(i.get("resource_id")) for i in items)
            + "), Col(\"State\", " + _arr(_tag(str(i.get("state")), state_tag.get(i.get("state"), "neutral")) for i in items)
            + "), Col(\"Undo window\", " + _arr(_tag(str(i.get("countdown")), "danger" if i.get("countdown") == "expired"
                                                      else "success") for i in items)
            + "), Col(\"Flags\", " + _arr(_q("; ".join(i.get("flags") or []) or "none", 200) for i in items)
            + "), Col(\"\", " + _arr((_button("Undo", f"Undo: call {i['undo']['tool']} with {i['undo'].get('args')}")
                                      if i.get("undo") else _q("")) for i in items) + ", \"action\")])")
    else:
        children.append("rwn")
        lines.append("rwn = TextContent(\"Nothing is waiting in a rollback window.\")")
    return _program(children, lines)
