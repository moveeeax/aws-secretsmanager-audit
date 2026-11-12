"""The rotation schedule: when each credential is next due, and how late it already is.

The audit rules answer "what is wrong now". The schedule answers "what comes due next and
who has to do it", so a rotation is planned ahead of the date instead of noticed after it.
Like the rules, it reads the payload only and never calls AWS.
"""

from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .model import Payload, Secret, days_between, format_day
from .rules import Options, looks_like_credential, owner_of, secret_ignored

#: Ordered from "act now" to "nothing to do"; the text summary counts in this order.
STATUSES = ("overdue", "due", "due-soon", "ok", "unscheduled")

#: The ``--interval`` key that applies to every credential no other pattern matched.
DEFAULT_CLASS = "default"

IntervalRules = Sequence[Tuple[str, int]]


def parse_duration(text: str) -> int:
    """``90``, ``90d`` or ``13w`` as a number of days. Raises ``ValueError`` otherwise."""
    m = re.match(r"^\s*(\d+)\s*([dw]?)\s*$", text or "", re.IGNORECASE)
    if not m:
        raise ValueError("%r is not a duration like 90d or 13w" % text)
    days = int(m.group(1))
    return days * 7 if m.group(2).lower() == "w" else days


def parse_intervals(values: Sequence[str]) -> List[Tuple[str, int]]:
    """``PATTERN=DURATION`` items, comma-separated within a value, in the order given.

    PATTERN is a case-insensitive regex searched in the secret's name, description and tags,
    or the literal ``default``. Commas always separate items, so a pattern cannot contain one.
    """
    rules: List[Tuple[str, int]] = []
    for value in values:
        for item in value.split(","):
            item = item.strip()
            if not item:
                continue
            pattern, sep, duration = item.rpartition("=")
            if not sep or not pattern.strip():
                raise ValueError("%r is not PATTERN=DURATION" % item)
            days = parse_duration(duration)
            if days <= 0:
                raise ValueError("%r: an interval must be at least one day" % item)
            pattern = pattern.strip()
            if pattern != DEFAULT_CLASS:
                try:
                    re.compile(pattern)
                except re.error as exc:
                    raise ValueError("%r: bad pattern: %s" % (item, exc)) from exc
            rules.append((pattern, days))
    return rules


def policy_interval(secret: Secret, rules: IntervalRules) -> Optional[Tuple[int, str]]:
    """The first ``--interval`` pattern matching the secret, falling back to ``default``."""
    fallback: Optional[Tuple[int, str]] = None
    for pattern, days in rules:
        if pattern == DEFAULT_CLASS:
            if fallback is None:
                fallback = (days, "--interval default")
            continue
        if re.search(pattern, secret.searchable, re.IGNORECASE):
            return days, "--interval %s" % pattern
    return fallback


@dataclass(frozen=True)
class ScheduleRow:
    secret: str
    arn: str
    owner: Optional[str]
    rotation_enabled: bool
    interval_days: Optional[int]
    interval_source: Optional[str]
    basis: Optional[str]
    basis_date: Optional[dt.datetime]
    due: Optional[dt.date]
    days_left: Optional[int]
    status: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "secret": self.secret,
            "arn": self.arn,
            "owner": self.owner,
            "rotation_enabled": self.rotation_enabled,
            "interval_days": self.interval_days,
            "interval_source": self.interval_source,
            "basis": self.basis,
            "basis_date": format_day(self.basis_date) if self.basis_date else None,
            "due": self.due.isoformat() if self.due else None,
            "days_left": self.days_left,
            "status": self.status,
        }


def _interval(secret: Secret, rules: IntervalRules) -> Tuple[Optional[int], Optional[str]]:
    """The stricter of the configured rotation period and the ``--interval`` policy.

    A secret rotating every 365 days under a 90 day policy is due by the policy: the
    configuration is what is wrong, and the schedule should not inherit the mistake.
    """
    configured = secret.rotation_interval_days if secret.rotation_enabled else None
    policy = policy_interval(secret, rules)
    if configured is not None and (policy is None or configured <= policy[0]):
        return configured, "rotation rules"
    if policy is not None:
        return policy
    return None, None


def _basis(secret: Secret) -> Tuple[Optional[str], Optional[dt.datetime]]:
    """What the next rotation counts from.

    ``LastRotatedDate`` when rotation has run, otherwise ``CreatedDate``. ``LastChangedDate``
    is not used: it moves on any modification, including a tag or description edit, so it
    would push the due date out without the value having changed.
    """
    if secret.last_rotated:
        return "last rotated", secret.last_rotated
    if secret.created:
        return "created, never rotated", secret.created
    return None, None


def _status(days_left: int, remind_days: int, grace_days: int) -> str:
    if days_left < -grace_days:
        return "overdue"
    if days_left < 0:
        return "due"
    if days_left <= remind_days:
        return "due-soon"
    return "ok"


def build_schedule(
    payload: Payload,
    as_of: dt.datetime,
    opts: Options,
    intervals: IntervalRules = (),
    remind_days: int = 14,
) -> List[ScheduleRow]:
    """One row per live, credential-shaped secret, soonest due first, unscheduled last.

    Which secrets count follows the rotation rules exactly (``--all-secrets``,
    ``--credential-pattern``, ``--ignore-secret``), so the schedule and the audit agree on
    what a credential is. ``rotation-stale`` and ``overdue`` share ``--rotation-grace-days``.
    """
    rows: List[ScheduleRow] = []
    for secret in payload:
        if secret.deleted or secret_ignored(secret, opts.ignore_secrets):
            continue
        if not looks_like_credential(secret, opts):
            continue
        interval, source = _interval(secret, intervals)
        basis, basis_date = _basis(secret)
        due: Optional[dt.date] = None
        days_left: Optional[int] = None
        status = "unscheduled"
        if interval is not None and basis_date is not None:
            due_at = basis_date + dt.timedelta(days=interval)
            due = due_at.date()
            days_left = -days_between(as_of, due_at) if due_at <= as_of else days_between(due_at, as_of)
            status = _status(days_left, remind_days, opts.rotation_grace_days)
        rows.append(
            ScheduleRow(
                secret=secret.name,
                arn=secret.arn,
                owner=owner_of(secret, opts),
                rotation_enabled=secret.rotation_enabled,
                interval_days=interval,
                interval_source=source,
                basis=basis,
                basis_date=basis_date,
                due=due,
                days_left=days_left,
                status=status,
            )
        )
    rows.sort(key=lambda r: (r.due is None, r.due or dt.date.max, r.secret, r.arn))
    return rows
