"""The command line. Exit 0 clean, 1 a --fail-on rule fired, 2 the invocation was wrong."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from typing import Any, Dict, List, Optional, Sequence, TextIO

from . import __version__
from .model import Payload, parse_time
from .owners import DEFAULT_OWNER_TAG, OwnersError, load_owners
from .report import (
    GROUP_BY,
    render_ics,
    render_json,
    render_schedule_json,
    render_schedule_text,
    render_text,
)
from .rules import ALL_RULES, SEVERITIES, Options, audit
from .schedule import build_schedule, parse_duration, parse_intervals

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aws-secretsmanager-audit",
        description="Audit AWS Secrets Manager for rotation that never runs, secrets nobody "
        "reads, managed-key encryption and wildcard resource policies.",
        epilog="rules: " + ", ".join(ALL_RULES),
    )
    p.add_argument("--version", action="version", version=__version__)

    src = p.add_argument_group("input")
    src.add_argument("--profile", help="AWS profile to collect with")
    src.add_argument("--region", help="AWS region to collect from")
    src.add_argument("--from-json", metavar="FILE", help="replay a dumped payload, no AWS calls")
    src.add_argument("--dump-json", metavar="FILE", help="write the collected payload here")
    src.add_argument(
        "--as-of",
        metavar="TIMESTAMP",
        help="treat this instant as now when ageing secrets; defaults to the payload's "
        "collected_at under --from-json, otherwise the real clock",
    )

    tune = p.add_argument_group("thresholds")
    tune.add_argument("--unused-days", type=int, default=90, metavar="N",
                      help="flag a secret unread for N days (default 90)")
    tune.add_argument("--rotation-grace-days", type=int, default=7, metavar="N",
                      help="slack allowed past the rotation interval (default 7)")
    tune.add_argument("--require-tags", metavar="KEYS", default="",
                      help="comma-separated tag keys every secret must carry")
    tune.add_argument("--credential-pattern", metavar="REGEX",
                      help="override the regex deciding which secrets rotation rules apply to")
    tune.add_argument("--all-secrets", action="store_true",
                      help="apply rotation rules to every secret, not just credential-shaped ones")

    own = p.add_argument_group("ownership")
    own.add_argument("--owners", metavar="FILE",
                     help="YAML mapping of secret-name glob to owner; the first matching glob wins")
    own.add_argument("--owner-tag", metavar="KEY", default=DEFAULT_OWNER_TAG,
                     help="tag key read when no --owners glob matches, case-insensitive "
                     "(default %s); an empty value turns the tag lookup off" % DEFAULT_OWNER_TAG)

    sched = p.add_argument_group("rotation schedule")
    sched.add_argument("--schedule", action="store_true",
                       help="print the rotation schedule (next due date per credential) "
                       "instead of findings")
    sched.add_argument("--interval", action="append", default=[], metavar="PATTERN=DURATION",
                       help="rotation policy per class of secret, e.g. 'db|password=90d,signing=365d,"
                       "default=180d'; PATTERN is a regex over name, description and tags; repeatable")
    sched.add_argument("--remind-before", default="14d", metavar="DURATION",
                       help="mark a rotation due-soon this far ahead and set the calendar alarm "
                       "(default 14d)")
    sched.add_argument("--export-ics", metavar="FILE",
                       help="write the schedule as an iCalendar file; works with or without --schedule")

    out = p.add_argument_group("output")
    out.add_argument("--format", choices=("text", "json"), default="text")
    out.add_argument("--group-by", choices=GROUP_BY, default="secret",
                     help="group the text report by secret (default) or by owner")
    out.add_argument("--severity", choices=SEVERITIES, default="low",
                     help="drop findings below this severity (default low)")
    out.add_argument("--ignore-rule", action="append", default=[], metavar="RULE")
    out.add_argument("--ignore-secret", action="append", default=[], metavar="NAME",
                     help="secret name or ARN; a trailing * matches a prefix")
    out.add_argument("--fail-on", default="", metavar="RULES",
                     help="comma-separated rules that make the run exit 1")
    return p


def _split(value: str) -> List[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def _unknown(names: Sequence[str]) -> List[str]:
    return [n for n in names if n not in ALL_RULES]


def _load_payload(args: argparse.Namespace, err: TextIO) -> Optional[Dict[str, Any]]:
    if args.from_json:
        with open(args.from_json, "r", encoding="utf-8") as fh:
            return json.load(fh)
    from .collect import collect

    return collect(profile=args.profile, region=args.region)


def main(argv: Optional[Sequence[str]] = None,
         out: Optional[TextIO] = None,
         err: Optional[TextIO] = None) -> int:
    out = out if out is not None else sys.stdout
    err = err if err is not None else sys.stderr
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    fail_on = _split(args.fail_on)
    ignore_rules = _split(",".join(args.ignore_rule))
    bad = _unknown(fail_on + ignore_rules)
    if bad:
        err.write("unknown rule(s): %s\nknown rules: %s\n" % (", ".join(bad), ", ".join(ALL_RULES)))
        return EXIT_USAGE
    if args.from_json and (args.profile or args.region):
        err.write("--from-json replays a dump; --profile/--region do not apply\n")
        return EXIT_USAGE
    if args.schedule and fail_on:
        err.write("--fail-on gates findings; --schedule prints no findings to gate on\n")
        return EXIT_USAGE
    try:
        intervals = parse_intervals(args.interval)
        remind_days = parse_duration(args.remind_before)
    except ValueError as exc:
        err.write("cannot read the schedule options: %s\n" % exc)
        return EXIT_USAGE
    owners = []
    if args.owners:
        try:
            owners = load_owners(args.owners)
        except (OSError, OwnersError) as exc:
            err.write("cannot read --owners: %s\n" % exc)
            return EXIT_USAGE

    try:
        raw = _load_payload(args, err)
    except FileNotFoundError as exc:
        err.write("cannot read payload: %s\n" % exc)
        return EXIT_USAGE
    except ValueError as exc:
        err.write("payload is not valid JSON: %s\n" % exc)
        return EXIT_USAGE
    if raw is None:
        return EXIT_USAGE

    if args.dump_json:
        with open(args.dump_json, "w", encoding="utf-8") as fh:
            json.dump(raw, fh, indent=2, sort_keys=True)
            fh.write("\n")

    payload = Payload(raw)
    try:
        as_of = _resolve_as_of(args, payload)
    except ValueError as exc:
        err.write("cannot read --as-of: %s\n" % exc)
        return EXIT_USAGE

    opts = Options(
        unused_days=args.unused_days,
        rotation_grace_days=args.rotation_grace_days,
        require_tags=_split(args.require_tags),
        credential_pattern=args.credential_pattern or Options.credential_pattern,
        all_secrets=args.all_secrets,
        ignore_rules=ignore_rules,
        ignore_secrets=list(args.ignore_secret),
        min_severity=args.severity,
        owners=owners,
        owner_tag=args.owner_tag.strip(),
    )

    if args.schedule or args.export_ics:
        rows = build_schedule(payload, as_of, opts, intervals, remind_days)
        if args.export_ics:
            with open(args.export_ics, "w", encoding="utf-8", newline="") as fh:
                fh.write(render_ics(rows, as_of, raw, remind_days))
        if args.schedule:
            if args.format == "json":
                out.write(render_schedule_json(rows, as_of, raw, remind_days, args.rotation_grace_days))
            else:
                out.write(render_schedule_text(rows, as_of, remind_days, args.group_by))
            return EXIT_CLEAN

    findings = audit(payload, as_of, opts)

    if args.format == "json":
        out.write(render_json(findings, len(payload), as_of, raw))
    else:
        out.write(render_text(findings, len(payload), as_of, args.group_by))

    if fail_on and any(f.rule in set(fail_on) for f in findings):
        return EXIT_FINDINGS
    return EXIT_CLEAN


def _resolve_as_of(args: argparse.Namespace, payload: Payload) -> dt.datetime:
    """Why a replay is byte-for-byte: a dump carries the instant it was taken.

    Without this every ``--from-json`` run would age the secrets against the wall clock and
    the same file would produce different day counts tomorrow.
    """
    if args.as_of:
        value = parse_time(args.as_of)
        if value is None:
            raise ValueError(args.as_of)
        return value
    if args.from_json and payload.collected_at:
        return payload.collected_at
    return dt.datetime.now(dt.timezone.utc)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
