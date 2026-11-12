"""Rendering. Both formats are deterministic for a given payload and --as-of."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Sequence

from .rules import SEVERITIES, Finding
from .schedule import STATUSES, ScheduleRow

#: Heading for findings and schedule rows nobody owns under ``--group-by owner``.
UNOWNED = "(unowned)"

GROUP_BY = ("secret", "owner")


def _counts(findings: Sequence[Finding]) -> "OrderedDict[str, int]":
    out: "OrderedDict[str, int]" = OrderedDict((s, 0) for s in reversed(SEVERITIES))
    for f in findings:
        out[f.severity] += 1
    return out


def _owner_order(owner: Optional[str]) -> tuple:
    """Owners alphabetically, the unowned pile last so it reads as the leftover."""
    return (owner is None, owner or "")


def _secret_heading(f: Finding, group_by: str) -> str:
    if group_by == "secret" and f.owner:
        return "%s  (owner: %s)" % (f.secret, f.owner)
    return f.secret


def render_text(
    findings: Sequence[Finding],
    audited: int,
    as_of: dt.datetime,
    group_by: str = "secret",
) -> str:
    lines: List[str] = []
    if not findings:
        return "no findings across %d secret(s) as of %s\n" % (audited, as_of.date().isoformat())

    width = max(len(f.rule) for f in findings)
    indent = "  " if group_by == "owner" else ""
    if group_by == "owner":
        findings = sorted(findings, key=lambda f: _owner_order(f.owner))
    current_owner: Any = object()
    current = None
    for f in findings:
        if group_by == "owner" and f.owner != current_owner:
            if lines:
                lines.append("")
            lines.append(f.owner or UNOWNED)
            current_owner = f.owner
            current = None
        if f.secret != current:
            if current is not None:
                lines.append("")
            lines.append(indent + _secret_heading(f, group_by))
            current = f.secret
        lines.append("%s  %-6s %-*s  %s" % (indent, f.severity, width, f.rule, f.detail))

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


# --- the rotation schedule ---------------------------------------------------------


def _status_counts(rows: Sequence[ScheduleRow]) -> "OrderedDict[str, int]":
    out: "OrderedDict[str, int]" = OrderedDict((s, 0) for s in STATUSES)
    for r in rows:
        out[r.status] += 1
    return out


def _when(row: ScheduleRow) -> str:
    if row.days_left is None:
        return ""
    if row.days_left < 0:
        return "%dd late" % -row.days_left
    if row.days_left == 0:
        return "today"
    return "in %dd" % row.days_left


def _schedule_line(row: ScheduleRow, indent: str, group_by: str, widths: Dict[str, int]) -> str:
    if row.interval_days:
        interval = "every %dd (%s)" % (row.interval_days, row.interval_source)
    elif row.rotation_enabled:
        interval = "no interval: the rotation schedule is a cron expression and no --interval matches"
    else:
        interval = "no interval: rotation is off and no --interval matches"
    if row.basis_date:
        basis = "%s %s" % (row.basis, row.basis_date.date().isoformat())
    else:
        basis = "no creation or rotation date to count from"
    cells = [
        "%-10s" % (row.due.isoformat() if row.due else "-"),
        "%-*s" % (widths["when"], _when(row)),
        "%-11s" % row.status,
    ]
    if group_by != "owner":
        cells.append("%-*s" % (widths["owner"], row.owner or UNOWNED))
    cells.append(row.secret)
    detail = "; ".join(p for p in (interval, basis) if p)
    return "%s%s\n%s    %s" % (indent, "  ".join(cells), indent, detail)


def render_schedule_text(
    rows: Sequence[ScheduleRow],
    as_of: dt.datetime,
    remind_days: int,
    group_by: str = "secret",
) -> str:
    if not rows:
        return "no credential-shaped secrets to schedule as of %s\n" % as_of.date().isoformat()
    lines: List[str] = []
    widths = {
        "when": max(len(_when(r)) for r in rows),
        "owner": max(len(r.owner or UNOWNED) for r in rows),
    }
    if group_by == "owner":
        current: Any = object()
        for row in sorted(rows, key=lambda r: _owner_order(r.owner)):
            if row.owner != current:
                if lines:
                    lines.append("")
                lines.append(row.owner or UNOWNED)
                current = row.owner
            lines.append(_schedule_line(row, "  ", group_by, widths))
    else:
        lines.extend(_schedule_line(row, "", group_by, widths) for row in rows)
    counts = _status_counts(rows)
    lines.append("")
    lines.append(
        "%d secret(s) on the schedule as of %s, reminding %dd ahead — %s"
        % (
            len(rows),
            as_of.date().isoformat(),
            remind_days,
            " ".join("%s=%d" % (k, v) for k, v in counts.items() if v),
        )
    )
    return "\n".join(lines) + "\n"


def render_schedule_json(
    rows: Sequence[ScheduleRow],
    as_of: dt.datetime,
    payload: Dict[str, Any],
    remind_days: int,
    grace_days: int,
) -> str:
    document = OrderedDict()
    document["as_of"] = as_of.isoformat()
    document["account"] = payload.get("account")
    document["region"] = payload.get("region")
    document["remind_before_days"] = remind_days
    document["rotation_grace_days"] = grace_days
    document["schedule"] = [r.as_dict() for r in rows]
    document["summary"] = OrderedDict([("total", len(rows)), ("by_status", _status_counts(rows))])
    return json.dumps(document, indent=2) + "\n"


def _ics_escape(text: str) -> str:
    return (
        text.replace("\\", "\\\\").replace(";", "\\;").replace(",", "\\,").replace("\n", "\\n")
    )


def _ics_fold(line: str) -> List[str]:
    """RFC 5545 3.1: lines over 75 octets continue on the next line after one space."""
    out: List[str] = []
    current = ""
    size = 0
    for ch in line:
        width = len(ch.encode("utf-8"))
        if size + width > (75 if not out else 74):
            out.append(current)
            current, size = "", 0
        current += ch
        size += width
    out.append(current)
    return [out[0]] + [" " + part for part in out[1:]]


def render_ics(
    rows: Sequence[ScheduleRow],
    as_of: dt.datetime,
    payload: Dict[str, Any],
    remind_days: int,
) -> str:
    """An iCalendar feed: one all-day event per due date, with an alarm ``remind_days`` ahead.

    DTSTAMP is ``as_of`` and the UID hashes the ARN alone, so replaying a dump produces the
    same file, and after a rotation the secret's one event moves to the new due date instead
    of a second event appearing next to the old one.
    """
    stamp = as_of.astimezone(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    where = " ".join(p for p in (payload.get("account"), payload.get("region")) if p)
    lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//aws-secretsmanager-audit//rotation schedule//EN",
        "CALSCALE:GREGORIAN",
        "X-WR-CALNAME:%s" % _ics_escape("Secrets Manager rotation" + (" " + where if where else "")),
    ]
    for row in rows:
        if row.due is None:
            continue
        uid = hashlib.sha256((row.arn or row.secret).encode("utf-8")).hexdigest()
        summary = "Rotate %s" % row.secret
        if row.status in ("overdue", "due"):
            summary += " (%s)" % _when(row)
        description = [
            "owner: %s" % (row.owner or "unowned"),
            "interval: %dd from %s" % (row.interval_days, row.interval_source),
            "%s: %s" % (row.basis, row.basis_date.date().isoformat()),
            "status as of %s: %s" % (as_of.date().isoformat(), row.status),
        ]
        if row.arn:
            description.append("arn: %s" % row.arn)
        event = [
            "BEGIN:VEVENT",
            "UID:%s@aws-secretsmanager-audit" % uid[:32],
            "DTSTAMP:%s" % stamp,
            "DTSTART;VALUE=DATE:%s" % row.due.strftime("%Y%m%d"),
            "DTEND;VALUE=DATE:%s" % (row.due + dt.timedelta(days=1)).strftime("%Y%m%d"),
            "SUMMARY:%s" % _ics_escape(summary),
            "DESCRIPTION:%s" % _ics_escape("\n".join(description)),
            "TRANSP:TRANSPARENT",
        ]
        if row.owner and re.match(r"^[^@\s\"]+@[^@\s\"]+$", row.owner):
            # An owner that is an address gets the reminder in their own calendar.
            event.append('ATTENDEE;CN="%s":mailto:%s' % (row.owner, row.owner))
        event += [
            "BEGIN:VALARM",
            "ACTION:DISPLAY",
            "DESCRIPTION:%s" % _ics_escape(summary),
            "TRIGGER:-P%dD" % remind_days,
            "END:VALARM",
            "END:VEVENT",
        ]
        lines.extend(event)
    lines.append("END:VCALENDAR")
    folded: List[str] = []
    for line in lines:
        folded.extend(_ics_fold(line))
    return "\r\n".join(folded) + "\r\n"
