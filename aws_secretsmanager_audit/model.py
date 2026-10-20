"""Payload shape and the date handling shared by the collector and the rules."""

from __future__ import annotations

import datetime as dt
import re
from typing import Any, Dict, Iterable, List, Optional

PAYLOAD_VERSION = 1


def parse_time(value: Any) -> Optional[dt.datetime]:
    """Accept whatever boto3 or a JSON dump hands us; return an aware UTC datetime.

    boto3 gives real ``datetime`` objects, ``json.dumps(default=str)`` turns those into
    ``2026-07-01 00:00:00+00:00``, and hand-written fixtures tend to use ``...T00:00:00Z``.
    All three are the same instant and all three land here.
    """
    if value is None or value == "":
        return None
    if isinstance(value, dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)
    if isinstance(value, (int, float)):
        return dt.datetime.fromtimestamp(value, dt.timezone.utc)
    if not isinstance(value, str):
        raise TypeError("cannot read a timestamp from %r" % (value,))
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = dt.datetime.fromisoformat(text)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)


def format_day(value: Optional[dt.datetime]) -> str:
    return value.date().isoformat() if value else "never"


def days_between(later: dt.datetime, earlier: dt.datetime) -> int:
    """Whole days from ``earlier`` to ``later``, floored, never negative-by-rounding."""
    return int((later - earlier).total_seconds() // 86400)


class Secret:
    """One secret, normalised out of ``describe_secret`` plus ``get_resource_policy``."""

    def __init__(self, raw: Dict[str, Any]):
        self.raw = raw
        self.arn: str = raw.get("ARN") or raw.get("Arn") or ""
        self.name: str = raw.get("Name") or self.arn or "<unnamed>"
        self.description: str = (raw.get("Description") or "").strip()
        self.kms_key_id: Optional[str] = raw.get("KmsKeyId") or None
        self.rotation_enabled: bool = bool(raw.get("RotationEnabled", False))
        self.rotation_lambda: Optional[str] = raw.get("RotationLambdaARN") or None
        self.rotation_rules: Dict[str, Any] = raw.get("RotationRules") or {}
        self.created = parse_time(raw.get("CreatedDate"))
        self.last_rotated = parse_time(raw.get("LastRotatedDate"))
        self.last_accessed = parse_time(raw.get("LastAccessedDate"))
        self.last_changed = parse_time(raw.get("LastChangedDate"))
        self.deleted = parse_time(raw.get("DeletedDate"))
        self.tags: Dict[str, str] = {
            t.get("Key", ""): t.get("Value", "") for t in (raw.get("Tags") or [])
        }
        self.resource_policy = raw.get("ResourcePolicy")

    @property
    def rotation_interval_days(self) -> Optional[int]:
        """The configured rotation period in days, or ``None`` when it cannot be read.

        ``AutomaticallyAfterDays`` is the common case. A ``ScheduleExpression`` of
        ``rate(N days)`` is the same thing written differently; a cron expression is not
        reducible to a number of days, so it stays ``None`` and the staleness rule stands down.
        """
        after = self.rotation_rules.get("AutomaticallyAfterDays")
        if isinstance(after, int) and after > 0:
            return after
        schedule = self.rotation_rules.get("ScheduleExpression") or ""
        m = re.match(r"^\s*rate\(\s*(\d+)\s+(day|days|hour|hours)\s*\)\s*$", schedule)
        if not m:
            return None
        amount = int(m.group(1))
        if m.group(2).startswith("hour"):
            return max(1, amount // 24)
        return amount

    @property
    def searchable(self) -> str:
        parts: List[str] = [self.name, self.description]
        parts.extend(self.tags.keys())
        parts.extend(self.tags.values())
        return " ".join(p for p in parts if p)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<Secret %s>" % self.name


class Payload:
    """A whole collection run: account context plus every secret."""

    def __init__(self, data: Dict[str, Any]):
        self.data = data
        self.account: Optional[str] = data.get("account") or None
        self.region: Optional[str] = data.get("region") or None
        self.collected_at = parse_time(data.get("collected_at"))
        self.secrets: List[Secret] = [Secret(s) for s in (data.get("secrets") or [])]
        self.secrets.sort(key=lambda s: (s.name, s.arn))

    def __iter__(self) -> Iterable[Secret]:
        return iter(self.secrets)

    def __len__(self) -> int:
        return len(self.secrets)
