"""The rules. Each one takes a normalised secret and returns findings, never calls AWS."""

from __future__ import annotations

import datetime as dt
import json
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence

from .model import Payload, Secret, days_between, format_day

SEVERITIES = ("low", "medium", "high")

#: Names and descriptions that mean "this holds something you can log in with".
CREDENTIAL_PATTERN = (
    r"(password|passwd|pwd|secret|token|credential|cred|api[-_]?key|private[-_]?key"
    r"|[-_/.]keys?([-_/.]|$)|auth|oauth|session|signing|cert|dsn"
    r"|conn(ection)?[-_]?string|rds|aurora|postgres|mysql|maria|mongo|redis"
    r"|[-_/.]db([-_/.]|$)|database|smtp|ftp|ssh|license)"
)

MANAGED_KEY_ALIAS = "alias/aws/secretsmanager"

RULE_SEVERITY: Dict[str, str] = {
    "rotation-disabled": "high",
    "rotation-stale": "high",
    "never-rotated": "high",
    "wildcard-resource-policy": "high",
    "unused-secret": "medium",
    "pending-deletion": "medium",
    "default-kms-key": "low",
    "no-description": "low",
    "untagged": "low",
}

ALL_RULES = tuple(sorted(RULE_SEVERITY))


@dataclass(frozen=True)
class Finding:
    secret: str
    arn: str
    rule: str
    severity: str
    detail: str

    def as_dict(self) -> Dict[str, str]:
        return {
            "secret": self.secret,
            "arn": self.arn,
            "rule": self.rule,
            "severity": self.severity,
            "detail": self.detail,
        }


@dataclass
class Options:
    unused_days: int = 90
    rotation_grace_days: int = 7
    require_tags: Sequence[str] = ()
    credential_pattern: str = CREDENTIAL_PATTERN
    all_secrets: bool = False
    ignore_rules: Sequence[str] = ()
    ignore_secrets: Sequence[str] = ()
    min_severity: str = "low"


def looks_like_credential(secret: Secret, opts: Options) -> bool:
    """Whether the rotation rules should apply to this secret at all.

    ``--all-secrets`` turns the heuristic off and audits everything. Otherwise a secret
    qualifies when its name, description or tags read like a credential, or when somebody
    already configured rotation on it — that configuration is its own admission.
    """
    if opts.all_secrets:
        return True
    if secret.rotation_enabled or secret.rotation_rules:
        return True
    return bool(re.search(opts.credential_pattern, secret.searchable, re.IGNORECASE))


def _principals(statement: Dict[str, Any]) -> List[str]:
    raw = statement.get("Principal")
    out: List[str] = []
    if raw is None:
        return out
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, dict):
        for value in raw.values():
            if isinstance(value, str):
                out.append(value)
            elif isinstance(value, list):
                out.extend(str(v) for v in value)
    return out


def _account_of(principal: str) -> Optional[str]:
    m = re.match(r"^arn:aws[^:]*:iam::(\d{12}):", principal)
    if m:
        return m.group(1)
    if re.match(r"^\d{12}$", principal):
        return principal
    return None


# --- individual rules -------------------------------------------------------------


def rule_rotation(secret: Secret, as_of: dt.datetime, opts: Options) -> List[Finding]:
    """rotation-disabled, never-rotated and rotation-stale. At most one of them fires."""
    if secret.deleted:
        return []
    if not looks_like_credential(secret, opts):
        return []

    if not secret.rotation_enabled:
        age = days_between(as_of, secret.last_changed) if secret.last_changed else None
        detail = "rotation is not enabled"
        if age is not None:
            detail += "; value last changed %s (%dd ago)" % (format_day(secret.last_changed), age)
        return [_finding(secret, "rotation-disabled", detail)]

    if secret.last_rotated is None:
        detail = "rotation is enabled but has never run"
        if secret.rotation_lambda:
            detail += "; rotation lambda %s" % secret.rotation_lambda.rsplit(":", 1)[-1]
        return [_finding(secret, "never-rotated", detail)]

    interval = secret.rotation_interval_days
    if interval is None:
        return []
    age = days_between(as_of, secret.last_rotated)
    limit = interval + opts.rotation_grace_days
    if age <= limit:
        return []
    detail = "rotates every %dd but last rotated %s (%dd ago, %dd past the %dd grace)" % (
        interval,
        format_day(secret.last_rotated),
        age,
        age - limit,
        opts.rotation_grace_days,
    )
    return [_finding(secret, "rotation-stale", detail)]


def rule_unused(secret: Secret, as_of: dt.datetime, opts: Options) -> List[Finding]:
    if secret.deleted:
        return []
    # A secret younger than the window has not had time to look unused.
    if secret.created and days_between(as_of, secret.created) < opts.unused_days:
        return []
    if secret.last_accessed is None:
        return [
            _finding(
                secret,
                "unused-secret",
                "no recorded access at all; created %s" % format_day(secret.created),
            )
        ]
    age = days_between(as_of, secret.last_accessed)
    if age < opts.unused_days:
        return []
    detail = "last read %s (%dd ago, threshold %dd)" % (
        format_day(secret.last_accessed),
        age,
        opts.unused_days,
    )
    return [_finding(secret, "unused-secret", detail)]


def rule_kms(secret: Secret, as_of: dt.datetime, opts: Options) -> List[Finding]:
    if secret.deleted:
        return []
    key = secret.kms_key_id
    if key and MANAGED_KEY_ALIAS not in key:
        return []
    where = "no KmsKeyId set" if not key else "KmsKeyId is %s" % key
    return [
        _finding(
            secret,
            "default-kms-key",
            "%s, so it uses the aws/secretsmanager managed key and grants cannot be audited per team"
            % where,
        )
    ]


def rule_resource_policy(secret: Secret, as_of: dt.datetime, opts: Options) -> List[Finding]:
    policy = secret.resource_policy
    if not policy:
        return []
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except ValueError:
            return [
                _finding(secret, "wildcard-resource-policy", "resource policy is not valid JSON")
            ]
    statements = policy.get("Statement") or []
    if isinstance(statements, dict):
        statements = [statements]

    findings: List[Finding] = []
    for index, statement in enumerate(statements):
        if not isinstance(statement, dict):
            continue
        if statement.get("Effect") != "Allow":
            continue
        if statement.get("Condition"):
            # A condition is the whole point: an org-id or source-arn check is a real boundary.
            continue
        for principal in _principals(statement):
            if principal == "*":
                findings.append(
                    _finding(
                        secret,
                        "wildcard-resource-policy",
                        'statement %s allows Principal "*" with no Condition'
                        % (statement.get("Sid") or "#%d" % index),
                    )
                )
                break
            account = _account_of(principal)
            if account and secret.arn:
                owner = _account_of_arn(secret.arn)
                if owner and account != owner:
                    findings.append(
                        _finding(
                            secret,
                            "wildcard-resource-policy",
                            "statement %s allows account %s (outside %s) with no Condition"
                            % (statement.get("Sid") or "#%d" % index, account, owner),
                        )
                    )
                    break
    return findings


def _account_of_arn(arn: str) -> Optional[str]:
    parts = arn.split(":")
    return parts[4] if len(parts) > 4 and re.match(r"^\d{12}$", parts[4]) else None


def rule_pending_deletion(secret: Secret, as_of: dt.datetime, opts: Options) -> List[Finding]:
    if not secret.deleted:
        return []
    left = days_between(secret.deleted, as_of)
    if left >= 0:
        detail = "scheduled for deletion on %s (%dd of recovery window left)" % (
            format_day(secret.deleted),
            left,
        )
    else:
        detail = "recovery window closed on %s; the value is gone" % format_day(secret.deleted)
    return [_finding(secret, "pending-deletion", detail)]


def rule_ownership(secret: Secret, as_of: dt.datetime, opts: Options) -> List[Finding]:
    findings: List[Finding] = []
    if secret.deleted:
        return findings
    if not secret.description:
        findings.append(_finding(secret, "no-description", "no description, so its purpose is guesswork"))
    if opts.require_tags:
        missing = [t for t in opts.require_tags if t not in secret.tags]
        if missing:
            findings.append(
                _finding(secret, "untagged", "missing required tag keys: %s" % ", ".join(missing))
            )
    elif not secret.tags:
        findings.append(_finding(secret, "untagged", "no tags at all, so ownership is unknowable"))
    return findings


RULE_FUNCTIONS = (
    rule_rotation,
    rule_unused,
    rule_kms,
    rule_resource_policy,
    rule_pending_deletion,
    rule_ownership,
)


def _finding(secret: Secret, rule: str, detail: str) -> Finding:
    return Finding(
        secret=secret.name,
        arn=secret.arn,
        rule=rule,
        severity=RULE_SEVERITY[rule],
        detail=detail,
    )


def _secret_ignored(secret: Secret, patterns: Iterable[str]) -> bool:
    for pattern in patterns:
        if secret.name == pattern or secret.arn == pattern:
            return True
        if pattern.endswith("*") and secret.name.startswith(pattern[:-1]):
            return True
    return False


def audit(payload: Payload, as_of: dt.datetime, opts: Options) -> List[Finding]:
    """Run every rule over every secret and return the surviving findings, sorted."""
    min_rank = SEVERITIES.index(opts.min_severity)
    ignored_rules = set(opts.ignore_rules)
    findings: List[Finding] = []
    for secret in payload:
        if _secret_ignored(secret, opts.ignore_secrets):
            continue
        for fn in RULE_FUNCTIONS:
            for finding in fn(secret, as_of, opts):
                if finding.rule in ignored_rules:
                    continue
                if SEVERITIES.index(finding.severity) < min_rank:
                    continue
                findings.append(finding)
    findings.sort(key=lambda f: (f.secret, -SEVERITIES.index(f.severity), f.rule))
    return findings
