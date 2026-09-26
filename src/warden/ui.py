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


def _savings_by_type(items: list[dict]) -> tuple[list[str], list[str]]:
    """Monthly savings grouped by resource type, for a single stacked bar."""
    totals: dict[str, float] = {}
    for f in items:
        label = TYPE_LABELS.get(f.get("resource_type"), str(f.get("resource_type")))
        totals[label] = totals.get(label, 0.0) + float(f.get("est_monthly_usd") or 0)
    ordered = sorted(totals.items(), key=lambda kv: -kv[1])
    return [_q(k) for k, _ in ordered], [_num(v) for _, v in ordered]


def scan_ui(report: dict, mock: bool = False, console_url: str | None = None) -> str:
    """Scan report -> KPI cards + tabs (decide / refused / leaks / savings / how it works)."""
    findings = report.get("findings") or []
    summary = report.get("summary") or {}
    tiers = summary.get("tiers") or {}
    plan_id = report.get("plan_id", "")
    act = [f for f in findings if f.get("verdict") in ("act", "review")]
    act.sort(key=lambda f: (f.get("tier") != "needs_review", -(f.get("est_monthly_usd") or 0)))
    keep_all = [f for f in findings if f.get("verdict") == "keep"]
    # Warden's own unexpired backups are not refusals; they live in the rollback window instead.
    backups = [f for f in keep_all if any(str(r).startswith("Warden backup of") for r in f.get("reasons") or [])]
    keep = [f for f in keep_all if f not in backups]
    leaks = report.get("leaks") or []

    lines = [
        f"hdr = CardHeader(\"🛡️ Warden · cloud waste report\", "
        f"{_q(f'Account {report.get('account_id')} · {report.get('region')} · scope {report.get('scope')} · plan {plan_id}', 220)})",
        "kpis = Stack([k1, k2, k3, k4, k5], \"row\", \"m\", \"stretch\", \"start\", true)",
        _kpi("k1", "💰 Monthly waste", _money(summary.get("est_monthly_savings_usd")), "list-price estimate"),
        _kpi("k2", "✅ Safe & reversible", str(tiers.get("safe_reversible", 0)), "one approval per batch"),
        _kpi("k3", "🙋 Needs your review", str(tiers.get("needs_review", 0)), "irreversible or unclear"),
        _kpi("k4", "🛡️ Refused", str(len(keep)), "Warden will not touch these"),
        _kpi("k5", "🔧 Leaks", str(len(leaks)), "sources that keep creating waste"),
        "tabs = Tabs([t5, t4, t3, t6, t2])",
    ]

    # The decision list sits above the tabs so it is always visible; TrueForge opens the last tab (Refused).
    decide: list[str] = []
    if act:
        names = [_q(f.get("name") or f.get("resource_id"), 34) for f in act]
        actions = [_tag(ACTION_LABELS.get(f.get("action") or "", "Needs your call"),
                        "danger" if f.get("reversible") is False else "info") for f in act]
        undo = [_tag("Reversible", "success") if f.get("reversible") else
                _tag("IRREVERSIBLE", "danger") if f.get("reversible") is False else _tag("Decide first", "warning")
                for f in act]
        whys = [_q(f.get("why") or "; ".join(f.get("reasons") or []), 180) for f in act]
        # TrueForge renders OpenUI without an action handler, so buttons would be dead: show what to TYPE instead.
        says = [_tag(("approve " if f.get("verdict") == "act" else "explain ") + str(f.get("name") or f.get("resource_id")),
                     "info" if f.get("reversible") else "neutral") for f in act]
        decide += [
            "decide = Card([dhdr, intro1, dtable, dbtns])",
            "dhdr = CardHeader(" + _q(f"Decide: {len(act)} item(s)") + ", \"Most urgent first\")",
            "intro1 = Callout(\"success\", \"You stay in control\", \"Typing 'approve ...' only REQUESTS an action. "
            "Warden's independent Watchdog re-checks it, then TrueForge shows you an Allow / Deny card. Nothing "
            "changes until you click Allow, and every item here can be undone.\")",
            "dtable = Table([Col(\"Resource\", " + _arr(names) + "), Col(\"Action\", " + _arr(actions)
            + "), Col(\"Undo\", " + _arr(undo) + "), Col(\"To act, type\", " + _arr(says) + ")])",
            "t6 = TabItem(\"why\", \"Why it is safe\", [whysteps])",
            "whysteps = Steps(" + _arr(f"StepsItem({n}, {w})" for n, w in zip(names, whys)) + ")",
        ]
        hint = "**Next:** type `approve all safe items`, or `approve <resource>` from the table. `show rollback window` lists everything you can undo."
        if console_url:
            hint += f" **Full dashboard:** {console_url}"
        decide.append("dbtns = MarkDownRenderer(" + _q(hint, 400) + ", \"sunk\")")
    else:
        decide += ["decide = Card([none1])", "t6 = TabItem(\"why\", \"Why it is safe\", [none6])",
                   "none6 = TextContent(\"Nothing to act on.\")",
                  "none1 = Callout(\"success\", \"Nothing to clean\", \"No waste found in scope.\")"]

    # Tab 2: refusals are a feature.
    if keep:
        lines += [
            "t2 = TabItem(\"refused\", " + _q(f"Refused ({len(keep)})") + ", [intro2, ptable])",
            "intro2 = Callout(\"warning\", " + _q(f"A normal cleanup script would delete all {len(keep)}")
            + ", \"Warden refuses each one and says why. Refusals are a feature, not a failure.\")",
            "ptable = Table([Col(\"Resource\", " + _arr(_q(f.get("name") or f.get("resource_id"), 40) for f in keep)
            + "), Col(\"Refused because\", "
            + _arr(_tag(_refusal_kind(f), "danger" if "suspicious" in " ".join(f.get("reasons") or []) else "warning")
                   for f in keep)
            + "), Col(\"Details\", " + _arr(_q((f.get("reasons") or [f.get("why")])[0], 90) for f in keep) + ")])",
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
    type_labels, type_values = _savings_by_type(priced)
    lines += [
        "t4 = TabItem(\"savings\", \"Savings\", [stitle, stype, sbar, sc1, sc2, sc3])",
        "stitle = TextContent(" + _q(f"{_money(summary.get('est_monthly_savings_usd'))} per month, by resource type")
        + ", \"large-heavy\")",
        "stype = SingleStackedBarChart(" + _arr(type_labels) + ", " + _arr(type_values) + ")",
        "sbar = HorizontalBarChart(" + _arr(_q(f.get("name") or f.get("resource_id"), 40) for f in priced)
        + ", [Series(\"$ per month\", " + _arr(_num(f.get("est_monthly_usd")) for f in priced) + ")], \"grouped\", \"$ per month\")",
        # PieChart takes no colours (three near-identical blues), so the tier split uses coloured callouts.
        "sc1 = TextCallout(\"success\", " + _q(f"{tiers.get('safe_reversible', 0)} safe & reversible") + ", \"One approval per batch; undo in one click.\")",
        "sc2 = TextCallout(\"warning\", " + _q(f"{tiers.get('needs_review', 0)} need your review") + ", \"Irreversible or unclear; a human decides.\")",
        "sc3 = TextCallout(\"danger\", " + _q(f"{len(keep)} refused") + ", \"Warden will not touch these, and says why.\")",
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

    lines += decide
    children = ["hdr"]
    mode = _mode_callout(mock)
    if mode:
        children.append("mode")
        lines.append(mode)
    children += ["kpis", "decide", "tabs"]
    return _program(children, lines)


def _refusal_kind(finding: dict) -> str:
    text = " ".join(finding.get("reasons") or []).lower()
    for needle, label in (("human undid", "Undone by you"), ("suspicious", "Prompt-injection attempt"), ("production", "Production"),
                          ("legal", "Legal hold"), ("terraform", "Managed by code"), ("cloudformation", "Managed by code"),
                          ("used by ami", "Used by an image"), ("machine image", "Used by an image"), ("autoscaling", "Autoscaling"),
                          ("kubernetes", "Kubernetes"),
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
        ("wd = Callout(\"success\", " + _q(f"🛡️ Watchdog signed off {len(approved)} item(s)") + ", "
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


def receipt_ui(receipt: dict, console_url: str | None = None) -> str:
    results = receipt.get("results") or []
    counts = receipt.get("counts") or {}
    ok = counts.get("done", 0) and not counts.get("failed", 0)
    status_tag = {"done": "success", "skipped": "warning", "failed": "danger"}
    lines = [
        ("rc = Callout(" + _q("success" if ok else "warning") + ", "
         + _q(f"{'✅' if ok else '⚠️'} {receipt.get('action')}: {counts.get('done', 0)} done · {counts.get('skipped', 0)} skipped · "
              f"{counts.get('failed', 0)} failed") + ", "
         + _q(f"Estimated saving {_money(receipt.get('est_monthly_savings_usd'))}/month · receipt {receipt.get('receipt_id')}", 240) + ")"),
    ]
    children = ["rc"]
    if results:
        children.append("rt")
        undo_says = [(_tag("undo " + str(r.get("resource_id")), "info") if r.get("undo") else _q("")) for r in results]
        lines.append("rt = Table([Col(\"Resource\", " + _arr(_q(r.get("resource_id")) for r in results)
                     + "), Col(\"Result\", " + _arr(_tag(str(r.get("status")), status_tag.get(r.get("status"), "neutral"))
                                                   for r in results)
                     + "), Col(\"Details\", " + _arr(_q(r.get("detail"), 70) for r in results)
                     + "), Col(\"To undo, type\", " + _arr(undo_says) + ")])")
    hint = "**Next:** type `show rollback window` to see every undo countdown."
    if console_url:
        hint += f" **Full dashboard:** {console_url}"
    children.append("rcb")
    lines.append("rcb = MarkDownRenderer(" + _q(hint, 300) + ", \"sunk\")")
    return _program(children, lines)


def rollback_ui(window: dict, console_url: str | None = None) -> str:
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
            + "), Col(\"To undo, type\", " + _arr((_tag("undo " + str(i.get("resource_id")), "info")
                                                   if i.get("undo") else _q("")) for i in items) + ")])")
    else:
        children.append("rwn")
        lines.append("rwn = TextContent(\"Nothing is waiting in a rollback window.\")")
    if console_url:
        children.append("rwb")
        lines.append("rwb = MarkDownRenderer(" + _q(f"**Live ticking countdowns:** {console_url}", 300) + ", \"sunk\")")
    return _program(children, lines)
