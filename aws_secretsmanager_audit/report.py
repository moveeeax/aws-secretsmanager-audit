"""Rendering. Both formats are deterministic for a given payload and --as-of."""

from __future__ import annotations

import datetime as dt
import json
from collections import OrderedDict
from typing import Any, Dict, List, Sequence

from .rules import SEVERITIES, Finding


def _counts(findings: Sequence[Finding]) -> "OrderedDict[str, int]":
    out: "OrderedDict[str, int]" = OrderedDict((s, 0) for s in reversed(SEVERITIES))
    for f in findings:
        out[f.severity] += 1
    return out


def render_text(findings: Sequence[Finding], audited: int, as_of: dt.datetime) -> str:
    lines: List[str] = []
    if not findings:
        return "no findings across %d secret(s) as of %s\n" % (audited, as_of.date().isoformat())

    width = max(len(f.rule) for f in findings)
    current = None
    for f in findings:
        if f.secret != current:
            if current is not None:
                lines.append("")
            lines.append(f.secret)
            current = f.secret
        lines.append("  %-6s %-*s  %s" % (f.severity, width, f.rule, f.detail))

    counts = _counts(findings)
    secrets = len({f.secret for f in findings})
    lines.append("")
    lines.append(
        "%d finding(s) across %d of %d secret(s) — %s"
        % (
            len(findings),
            secrets,
            audited,
            " ".join("%s=%d" % (k, v) for k, v in counts.items() if v),
        )
    )
    return "\n".join(lines) + "\n"


def render_json(
    findings: Sequence[Finding],
    audited: int,
    as_of: dt.datetime,
    payload: Dict[str, Any],
) -> str:
    by_rule: "OrderedDict[str, int]" = OrderedDict()
    for f in findings:
        by_rule[f.rule] = by_rule.get(f.rule, 0) + 1
    document = OrderedDict()
    document["as_of"] = as_of.isoformat()
    document["account"] = payload.get("account")
    document["region"] = payload.get("region")
    document["audited"] = audited
    document["findings"] = [f.as_dict() for f in findings]
    document["summary"] = OrderedDict(
        [
            ("total", len(findings)),
            ("by_severity", _counts(findings)),
            ("by_rule", OrderedDict(sorted(by_rule.items()))),
        ]
    )
    return json.dumps(document, indent=2) + "\n"
